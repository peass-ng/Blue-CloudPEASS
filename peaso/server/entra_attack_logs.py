"""Bounded Microsoft Entra directory audit reads for one connector tenant.

Graph directoryAudits: https://learn.microsoft.com/graph/api/directoryaudit-list
Least-privilege Graph permission: AuditLog.Read.All (application or delegated).
Delegated access also requires a supported Entra role, such as Reports Reader.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlencode, urlsplit

from peaso.collectors.azure import AzureTransport, GRAPH, _claims

from .attack_logs import LogAccessError


MAX_PAGES = 20
MAX_EVENTS = 2_000
MAX_RESPONSE_BYTES = 2_000_000
WINDOW = timedelta(hours=24)
_PATH = "/v1.0/auditLogs/directoryAudits"
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_SAFE_LABEL = re.compile(r"[A-Za-z0-9 _./:()&,+-]{1,120}\Z")


def _value(source, field):
    return source.get(field) if isinstance(source, dict) else getattr(source, field, None)


def _tenant(auth, source):
    tenant = auth.get("tenant_id") if isinstance(auth, dict) else None
    if not isinstance(tenant, str) or not _UUID.fullmatch(tenant):
        raise LogAccessError("entra_connector_tenant_required")
    source_tenant = _value(source, "tenant_id")
    if source_tenant is not None and (not isinstance(source_tenant, str) or
                                      not _UUID.fullmatch(source_tenant) or
                                      source_tenant.lower() != tenant.lower()):
        raise LogAccessError("entra_source_tenant_mismatch")
    return tenant.lower()


def _verified_graph_token(transport, tenant):
    try:
        claims = _claims(transport.token(GRAPH))
    except Exception:
        raise LogAccessError("entra_graph_token_unavailable") from None
    if str(claims.get("tid", "")).lower() != tenant:
        raise LogAccessError("entra_graph_tenant_mismatch")
    if claims.get("aud") not in (GRAPH, GRAPH + "/", "00000003-0000-0000-c000-000000000000"):
        raise LogAccessError("entra_graph_audience_mismatch")


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result.astimezone(timezone.utc) if result.tzinfo else None


def _initial_url(now):
    stamp = lambda value: value.isoformat(timespec="seconds").replace("+00:00", "Z")
    interval = f"activityDateTime ge {stamp(now - WINDOW)} and activityDateTime le {stamp(now)}"
    query = urlencode({"$filter": interval, "$top": "100", "$orderby": "activityDateTime desc"})
    return GRAPH + _PATH + "?" + query, interval


def _validate_next_link(url, interval):
    if not isinstance(url, str) or len(url) > 12_000:
        raise LogAccessError("invalid_entra_log_continuation")
    try:
        parsed = urlsplit(url)
        query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        raise LogAccessError("invalid_entra_log_continuation") from None
    if (parsed.scheme != "https" or parsed.netloc != "graph.microsoft.com" or
            parsed.path != _PATH or parsed.username or parsed.password or parsed.port or
            parsed.fragment or set(query) - {"$filter", "$top", "$orderby", "$skiptoken", "skiptoken"} or
            query.get("$filter") != [interval] or query.get("$top") != ["100"] or
            query.get("$orderby") != ["activityDateTime desc"]):
        raise LogAccessError("invalid_entra_log_continuation")
    tokens = query.get("$skiptoken", []) + query.get("skiptoken", [])
    if len(tokens) != 1 or not tokens[0] or len(tokens[0]) > 8192:
        raise LogAccessError("invalid_entra_log_continuation")


def _safe_label(value):
    return value if isinstance(value, str) and _SAFE_LABEL.fullmatch(value) else None


def _metadata(row, *, after, before):
    if not isinstance(row, dict):
        return None
    when = _timestamp(row.get("activityDateTime"))
    if when is None or not after <= when <= before:
        return None
    event_id = row.get("id")
    if not isinstance(event_id, str) or not 0 < len(event_id) <= 256:
        return None
    return {
        "event_id_sha256": hashlib.sha256(event_id.encode()).hexdigest(),
        "time": when.isoformat().replace("+00:00", "Z"),
        "activity": _safe_label(row.get("activityDisplayName")),
        "category": _safe_label(row.get("category")),
        "result": row.get("result") if row.get("result") in ("success", "failure", "timeout", "unknownFutureValue") else None,
        "operation_type": _safe_label(row.get("operationType")),
    }


def _read(transport, *, analyze, now, tenant):
    url, interval = _initial_url(now)
    after = now - WINDOW
    events = []
    candidates = []
    read = ignored = pages = 0
    truncated = False
    seen_urls = {url}
    for _ in range(MAX_PAGES if analyze else 1):
        try:
            page = transport.request(url, audience=GRAPH, max_response_bytes=MAX_RESPONSE_BYTES)
        except Exception:
            raise LogAccessError("entra_log_read_failed") from None
        pages += 1
        if not isinstance(page, dict) or not isinstance(page.get("value"), list):
            raise LogAccessError("invalid_entra_log_response")
        rows = page["value"]
        remaining = MAX_EVENTS - read
        for row in rows[:remaining]:
            read += 1
            if analyze:
                metadata = _metadata(row, after=after, before=now)
                if metadata is None:
                    ignored += 1
                else:
                    events.append(metadata)
                    from peaso.attack_detection.entra import normalize_entra_credential_add
                    candidate = normalize_entra_credential_add(
                        row, tenant=tenant,
                        event_id=metadata["event_id_sha256"], event_time=metadata["time"],
                    )
                    if candidate is not None:
                        candidates.append(candidate)
        next_url = page.get("@odata.nextLink")
        if next_url is not None:
            _validate_next_link(next_url, interval)
            if next_url in seen_urls:
                raise LogAccessError("invalid_entra_log_continuation")
            seen_urls.add(next_url)
        if not analyze:
            truncated = bool(next_url or len(rows) > remaining)
            break
        if read >= MAX_EVENTS:
            truncated = bool(next_url or len(rows) > remaining)
            break
        if not next_url:
            break
        url = next_url
    else:
        truncated = bool(next_url)
    return read, pages, events, candidates, ignored, truncated


def _run(auth, scopes, options, source, *, analyze):
    if _value(source, "kind") != "entra_directory_audit":
        raise LogAccessError("unsupported_log_source")
    tenant = _tenant(auth, source)
    try:
        transport = AzureTransport(auth)
    except Exception:
        raise LogAccessError("entra_graph_token_unavailable") from None
    try:
        _verified_graph_token(transport, tenant)
        read, pages, events, candidates, ignored, truncated = _read(
            transport, analyze=analyze, now=datetime.now(timezone.utc), tenant=tenant)
    finally:
        transport.close()
    coverage = {"source": "entra_directory_audit", "tenant_id": tenant, "window_hours": 24,
                "pages_read": pages, "events_read": read, "events_normalized": len(events),
                "events_ignored": ignored, "truncated": truncated,
                "credential_add_candidates": len(candidates),
                "detection_status": "credential_add_only"}
    if not analyze:
        return {"source_status": "accessible", "coverage": coverage,
                "note": "Graph directoryAudits read succeeded. Empty results do not prove that all activities were logged or retained."}
    from peaso.attack_detection import detect_azure_events
    return {"coverage": coverage, "events": events,
            "detections": [item.__dict__ for item in detect_azure_events(candidates)] if candidates else []}


def check_entra_source(auth, scopes, options, source):
    return _run(auth, scopes, options, source, analyze=False)


def analyze_entra_source(auth, scopes, options, source):
    return _run(auth, scopes, options, source, analyze=True)
