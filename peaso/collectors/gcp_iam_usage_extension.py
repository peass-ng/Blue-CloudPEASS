"""Bounded, one-pass Cloud Audit Log evidence for exact IAM action use."""
import copy
from datetime import datetime, timedelta, timezone
import re

from peaso.snapshot import make_snapshot

URL = "https://logging.googleapis.com/v2/entries:list"
SCOPE = re.compile(r"(?:projects/(?:[a-z][a-z0-9-]{4,61}[a-z0-9]|[1-9][0-9]*)|(?:folders|organizations)/[1-9][0-9]*)")
STATUSES = {"collected", "empty", "partial", "denied", "unknown", "malformed", "timeout", "not_collected"}
PROJECT_ID = re.compile(r"projects/[a-z][a-z0-9-]{4,28}[a-z0-9]")


def _status(value):
    return value if value in STATUSES else "unknown"


def _retry_disabled_insights(snapshot, connector):
    """Retry only quota-project failures against the already selected project."""
    from .gcp import Credentials, Transport, ReadError

    candidates = [c for c in snapshot["collections"] if c.get("type") == "insight"
                  and PROJECT_ID.fullmatch(str(c.get("scope", "")))
                  and c.get("status") not in {"collected", "empty"}
                  and (c.get("error") or {}).get("reason") == "SERVICE_DISABLED"
                  and (c.get("error") or {}).get("service") == "recommender.googleapis.com"]
    if not candidates:
        return snapshot
    collections = copy.deepcopy(snapshot["collections"])
    metadata = copy.deepcopy(snapshot.get("metadata") or {})
    for collection in collections:
        if collection not in candidates:
            continue
        scope = collection["scope"]
        project_id = scope.split("/", 1)[1]
        credentials = transport = None
        try:
            credentials = Credentials(connector.get("auth") or {})
            transport = Transport(credentials, {**(connector.get("options") or {}), "quota_project": project_id})
            project, _ = transport.request("GET", "https://cloudresourcemanager.googleapis.com/v3/" + scope,
                                            scope=scope)
            canonical = project.get("name") if isinstance(project, dict) else None
            if (not isinstance(project, dict) or project.get("projectId") != project_id
                    or not isinstance(canonical, str) or not re.fullmatch(r"projects/[1-9][0-9]*", canonical)):
                raise ValueError("project_alias_unverified")
            url = ("https://recommender.googleapis.com/v1/" + scope
                   + "/locations/global/insightTypes/google.iam.policy.Insight/insights")
            items, token = [], None
            for _ in range(5):
                response, _ = transport.request("GET", url, params={"pageToken": token} if token else {}, scope=scope)
                page = response.get("insights") if isinstance(response, dict) else None
                if page is None:
                    page = []
                if not isinstance(page, list):
                    raise ValueError("insight_page_malformed")
                for insight in page:
                    name = insight.get("name") if isinstance(insight, dict) else None
                    if (not isinstance(name, str) or not re.fullmatch(
                            r"(?:" + re.escape(scope) + "|" + re.escape(canonical)
                            + r")/locations/global/insightTypes/google\.iam\.policy\.Insight/insights/[^/?#]+", name)):
                        raise ValueError("foreign_insight")
                    items.append(insight)
                token = response.get("nextPageToken")
                if not token:
                    break
            collection.update(items=items, status="partial" if token else "collected" if items else "empty",
                quota_project_retry=project_id)
            collection.pop("error", None)
            receipts = []
            for receipt in transport.evidence:
                projected = copy.deepcopy(receipt)
                projected["id"] = f"iam-insight-{project_id}-" + receipt["id"]
                receipts.append(projected)
            metadata.setdefault("source_requests", []).extend(receipts)
            collection["source_requests"] = [receipt["id"] for receipt in receipts]
            if token:
                collection["error"] = {"code": "insight_page_limit"}
        except Exception:
            # Keep the original native error; retry failure proves no insight.
            pass
        finally:
            if transport:
                transport.close()
            elif credentials:
                credentials.close()
    return make_snapshot(snapshot["provider"], snapshot["scopes"], collections,
                         created_at=snapshot["created_at"], metadata=metadata)


def enrich_snapshot(snapshot, connector, *, page_limit=5):
    from .gcp import Credentials, Transport, ReadError

    snapshot = _retry_disabled_insights(snapshot, connector)

    scopes = sorted({scope for scope in snapshot.get("scopes", [])
                     if isinstance(scope, str) and SCOPE.fullmatch(scope)
                     and not any(c["type"] == "iam_usage_activity" and c["scope"] == scope
                                 for c in snapshot["collections"])})
    if not scopes:
        return snapshot
    options = connector.get("options") or {}
    days = options.get("activity_days", 90)
    if type(days) is not int or not 1 <= days <= 365:
        days = 90
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    collections = copy.deepcopy(snapshot["collections"])
    credentials = transport = None
    try:
        credentials = Credentials(connector.get("auth") or {})
        transport = Transport(credentials, options)
        for scope in scopes:
            body = {"resourceNames": [scope], "filter":
                    f'logName:"cloudaudit.googleapis.com" AND timestamp>="{since}" '
                    'AND protoPayload.authorizationInfo.permission:*',
                    "orderBy": "timestamp desc", "pageSize": 1000}
            rows, token, status, error = [], None, "collected", None
            try:
                for _ in range(page_limit):
                    query = {**body, **({"pageToken": token} if token else {})}
                    response, _ = transport.request("POST", URL, body=query, scope=scope)
                    entries = response.get("entries", [])
                    if not isinstance(entries, list):
                        raise ReadError("malformed", "malformed_list")
                    for event in entries:
                        if not isinstance(event, dict):
                            continue
                        payload = event.get("protoPayload") or {}
                        if not isinstance(payload, dict):
                            continue
                        principal = (payload.get("authenticationInfo") or {}).get("principalEmail")
                        auth = payload.get("authorizationInfo") or []
                        if not isinstance(principal, str) or not isinstance(auth, list):
                            continue
                        permissions = [{"permission": a["permission"], "granted": a.get("granted")}
                                       for a in auth if isinstance(a, dict) and isinstance(a.get("permission"), str)]
                        if permissions and isinstance(event.get("timestamp"), str):
                            rows.append({"name": event.get("insertId") or event["timestamp"],
                                         "principalEmail": principal, "timestamp": event["timestamp"],
                                         "authorizationInfo": permissions,
                                         "statusCode": (payload.get("status") or {}).get("code", 0)})
                    token = response.get("nextPageToken")
                    if not token:
                        break
                if token:
                    status, error = "partial", {"code": "iam_usage_audit_page_limit"}
            except ReadError as exc:
                status = "partial" if rows else _status(exc.status)
                error = {"code": exc.error.get("code", "audit_read_failed")}
            collection = {"type": "iam_usage_activity", "scope": scope, "service": "logging",
                "status": status if rows else ("empty" if status == "collected" else status),
                "items": rows, "queryWindow": {"since": since, "days": days, "absenceProvesUnused": False}}
            if error:
                collection["error"] = error
            collections.append(collection)
    except ReadError as exc:
        for scope in scopes:
            if not any(c["type"] == "iam_usage_activity" and c["scope"] == scope for c in collections):
                collections.append({"type": "iam_usage_activity", "scope": scope, "service": "logging",
                    "status": _status(exc.status), "items": [], "error": {"code": exc.error.get("code", "audit_read_failed")}})
    except Exception:
        for scope in scopes:
            if not any(c["type"] == "iam_usage_activity" and c["scope"] == scope for c in collections):
                collections.append({"type": "iam_usage_activity", "scope": scope, "service": "logging",
                    "status": "unknown", "items": [], "error": {"code": "audit_read_failed"}})
    finally:
        if transport:
            transport.close()
        if credentials:
            credentials.close()
    return make_snapshot(snapshot["provider"], snapshot["scopes"], collections,
                         created_at=snapshot["created_at"], metadata=snapshot.get("metadata"))
