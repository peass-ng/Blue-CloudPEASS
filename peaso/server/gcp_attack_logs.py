"""Bounded, read-only Cloud Audit Logs source for GCP and GKE attack review."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

import requests

from peaso.collectors.gcp import Credentials
from peaso.gcp_platform import PLATFORM_PROJECT, approved_project, load_service_account, project_id


MAX_PAGES = 20
PAGE_SIZE = 100
MAX_EVENTS = 2_000
MAX_RESPONSE_BYTES = 5_000_000
WINDOW = timedelta(hours=24)
_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
_CLUSTER = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")


class GcpLogAccessError(Exception):
    """A stable public code; never includes credentials or provider error text."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _value(source, name):
    return source.get(name) if isinstance(source, dict) else getattr(source, name, None)


def _source(auth, scopes, options, source):
    kind = _value(source, "kind")
    if kind not in {"gcp_audit", "gke_audit"}:
        raise GcpLogAccessError("unsupported_log_source")
    project = _value(source, "project_id")
    if not isinstance(project, str) or not _PROJECT.fullmatch(project):
        raise GcpLogAccessError("select_valid_customer_project")
    if project == PLATFORM_PROJECT:
        raise GcpLogAccessError("platform_project_forbidden")
    selected = set()
    for scope in scopes or []:
        if not isinstance(scope, str) or scope == "*":
            continue
        try:
            selected.add(project_id(scope))
        except ValueError:
            continue
    # Discovery of children below a folder or organization alone does not
    # prove this project's ancestry. All-projects is the only implicit scope.
    if project not in selected and not options.get("all_projects"):
        raise GcpLogAccessError("project_outside_connector_scope")
    cluster = _value(source, "cluster_id")
    if kind == "gke_audit" and (not isinstance(cluster, str) or not _CLUSTER.fullmatch(cluster)):
        raise GcpLogAccessError("select_valid_gke_cluster")
    return kind, project, cluster


def _auth(auth, settings):
    if auth.get("method") != "platform-service-account":
        return auth
    try:
        info = load_service_account(settings.gcp_platform_sa_secret_arn)
    except Exception:
        raise GcpLogAccessError("platform_identity_unavailable") from None
    return {"method": "service-account", "sa_json": info}


def _json_response(response, content):
    try:
        if response.status_code in (401, 403):
            raise GcpLogAccessError("log_read_denied")
        if response.status_code == 404:
            raise GcpLogAccessError("log_source_not_found")
        if response.status_code == 429:
            raise GcpLogAccessError("log_read_rate_limited")
        if response.status_code >= 300:
            raise GcpLogAccessError("log_read_unavailable")
        if len(content) > MAX_RESPONSE_BYTES:
            raise GcpLogAccessError("log_response_too_large")
        value = json.loads(content)
        if not isinstance(value, dict):
            raise ValueError("expected object")
        return value
    except (ValueError, TypeError):
        raise GcpLogAccessError("invalid_log_response") from None


def _request(method, url, headers, *, params=None, body=None, session=None):
    try:
        request = requests.request if session is None else session.request
        response = request(method, url, headers=headers, params=params, json=body,
                                    timeout=10, stream=True, allow_redirects=False)
    except requests.RequestException:
        raise GcpLogAccessError("log_read_unavailable") from None
    try:
        if response.status_code >= 300:
            return _json_response(response, b"")
        content = bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            content.extend(chunk)
            if len(content) > MAX_RESPONSE_BYTES:
                raise GcpLogAccessError("log_response_too_large")
        return _json_response(response, bytes(content))
    except requests.RequestException:
        raise GcpLogAccessError("log_read_unavailable") from None
    finally:
        response.close()


def _verify_project(auth, headers, project, *, session=None):
    # For hosted platform credentials, the connector-specific approval label is
    # mandatory even when a caller selected an explicit project scope.
    if auth.get("method") != "platform-service-account":
        return
    label = auth.get("project_proof_label")
    if not isinstance(label, str):
        raise GcpLogAccessError("customer_project_not_approved")
    try:
        value = _request("GET", f"https://cloudresourcemanager.googleapis.com/v3/projects/{project}", headers, session=session)
    except GcpLogAccessError:
        raise GcpLogAccessError("customer_project_not_approved") from None
    if value.get("projectId") != project or not approved_project(value, label):
        raise GcpLogAccessError("customer_project_not_approved")


def _filter(kind, cluster, after):
    common = f'timestamp >= "{after.isoformat().replace("+00:00", "Z")}"'
    audit = '(log_id("cloudaudit.googleapis.com/activity") OR log_id("cloudaudit.googleapis.com/data_access"))'
    if kind == "gcp_audit":
        return f"{common} AND {audit}"
    # A selected cluster may share its project with others. Keep the filter
    # exact; no user text is accepted without the cluster-name whitelist.
    return (f'{common} AND {audit} AND resource.type="k8s_cluster" '
            f'AND resource.labels.cluster_name="{cluster}" AND protoPayload.serviceName="k8s.io"')


def _entries(headers, kind, project, cluster, *, max_pages, session=None):
    after = datetime.now(timezone.utc) - WINDOW
    filter_text = _filter(kind, cluster, after)
    token = None
    events = []
    truncated = False
    for _ in range(max_pages):
        body = {"resourceNames": [f"projects/{project}"], "filter": filter_text,
                "orderBy": "timestamp desc", "pageSize": PAGE_SIZE}
        if token:
            body["pageToken"] = token
        page = _request("POST", "https://logging.googleapis.com/v2/entries:list", headers, body=body, session=session)
        rows = page.get("entries", [])
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise GcpLogAccessError("invalid_log_response")
        remaining = MAX_EVENTS - len(events)
        events.extend(rows[:remaining])
        token = page.get("nextPageToken")
        if token is not None and (not isinstance(token, str) or len(token) > 8192):
            raise GcpLogAccessError("invalid_log_response")
        if len(events) >= MAX_EVENTS:
            truncated = bool(token or len(rows) > remaining)
            break
        if not token:
            break
    else:
        truncated = bool(token)
    return events, truncated


def _run(auth, scopes, options, settings, source, *, analyze, rules=None):
    kind, project, cluster = _source(auth, scopes, options, source)
    credentials = None
    session = None
    try:
        credentials = Credentials(_auth(auth, settings), timeout=10)
        headers = credentials.headers()
        session = requests.Session()
        _verify_project(auth, headers, project, session=session)
        events, truncated = _entries(headers, kind, project, cluster,
                                     max_pages=MAX_PAGES if analyze else 1, session=session)
    except GcpLogAccessError:
        raise
    except Exception:
        raise GcpLogAccessError("log_read_unavailable") from None
    finally:
        try:
            if session is not None:
                session.close()
        finally:
            if credentials is not None:
                credentials.close()
    if not analyze:
        return {"project_id": project, "source_status": "accessible",
                "coverage": ("Cloud Logging accepted the read, but no matching audit entry was found in the last 24 hours. "
                             if not events else "Cloud Logging returned audit entries from the last 24 hours. ")
                            + "Data Access coverage is not proved by this check; it depends on logging configuration and private-log access."}
    from peaso.attack_detection import detect_gcp_events, detect_kubernetes_events
    detector = detect_gcp_events if kind == "gcp_audit" else detect_kubernetes_events
    detections = detector(events) if rules is None else detector(events, rules)
    return {"coverage": {"project_id": project, "cluster_id": cluster if kind == "gke_audit" else None,
                          "source": kind, "events_read": len(events), "truncated": truncated,
                          "window_hours": 24},
            "detections": [d.__dict__ for d in detections]}


def check_gcp_source(auth, scopes, options, settings, source):
    return _run(auth, scopes, options, settings, source, analyze=False)


def analyze_gcp_source(auth, scopes, options, settings, source, *, rules=None):
    return _run(auth, scopes, options, settings, source, analyze=True, rules=rules)
