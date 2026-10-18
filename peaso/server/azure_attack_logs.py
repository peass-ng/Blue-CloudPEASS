"""Bounded Azure Activity Log reads for an explicitly selected subscription.

The Activity Log records a successful role-assignment write, but does not
reliably include the assigned role and principal. Those records are available
to a future evaluator; this module does not label them as privilege escalation.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlencode, urlsplit

from peaso.collectors.azure import AzureTransport

from .attack_logs import LogAccessError


MAX_PAGES = 20
MAX_EVENTS = 2_000
MAX_RESPONSE_BYTES = 5_000_000
WINDOW = timedelta(hours=24)
_SUBSCRIPTION = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_ROLE_WRITE = "microsoft.authorization/roleassignments/write"
_API_VERSION = "2015-04-01"


def _value(source, field):
    return source.get(field) if isinstance(source, dict) else getattr(source, field, None)


def _selected_subscription(scopes, source):
    subscription = _value(source, "subscription_id")
    if not isinstance(subscription, str) or not _SUBSCRIPTION.fullmatch(subscription):
        raise LogAccessError("select_valid_azure_subscription")
    subscription = subscription.lower()
    if scopes:
        configured = set()
        for scope in scopes:
            if not isinstance(scope, str):
                raise LogAccessError("invalid_connector_scope")
            candidate = scope.removeprefix("/subscriptions/")
            if not _SUBSCRIPTION.fullmatch(candidate):
                raise LogAccessError("invalid_connector_scope")
            configured.add(candidate.lower())
        if subscription not in configured:
            raise LogAccessError("subscription_outside_connector_scope")
    return subscription


def _event_value(value):
    if isinstance(value, dict):
        value = value.get("value")
    return value if isinstance(value, str) else None


def normalize_azure_activity_event(record, subscription):
    """Project trustworthy Activity Log fields without inferring assignment impact."""
    if not isinstance(record, dict):
        return None
    event_subscription = record.get("subscriptionId")
    resource = record.get("resourceId")
    if not isinstance(event_subscription, str) or event_subscription.lower() != subscription:
        return None
    if (not isinstance(resource, str) or
            not (resource.lower() == f"/subscriptions/{subscription}"
                 or resource.lower().startswith(f"/subscriptions/{subscription}/"))):
        return None
    operation = _event_value(record.get("operationName"))
    status = _event_value(record.get("status"))
    if not operation or not status:
        return None
    return {
        "cloud.provider": "azure",
        "event.name": operation,
        "event.outcome": "success" if status.lower() == "succeeded" else "unknown",
        "event.id": record.get("eventDataId") if isinstance(record.get("eventDataId"), str) else None,
        "event.time": record.get("eventTimestamp") if isinstance(record.get("eventTimestamp"), str) else None,
        "account.id": subscription,
        "actor.id": record.get("caller") if isinstance(record.get("caller"), str) else None,
        "target.id": resource,
        "request.role_assignment_write": (operation.lower() == _ROLE_WRITE and
                                          "/providers/microsoft.authorization/roleassignments/" in resource.lower()),
    }


def _is_foreign_scope(record, subscription):
    if not isinstance(record, dict):
        return False
    declared = record.get("subscriptionId")
    if isinstance(declared, str) and declared.lower() != subscription:
        return True
    resource = record.get("resourceId")
    if isinstance(resource, str):
        match = re.match(r"/subscriptions/([^/]+)(?:/|\Z)", resource, re.IGNORECASE)
        if match and match.group(1).lower() != subscription:
            return True
    return False


def _initial_url(subscription):
    now = datetime.now(timezone.utc)
    after = now - WINDOW
    stamp = lambda value: value.isoformat(timespec="seconds").replace("+00:00", "Z")
    interval = f"eventTimestamp ge '{stamp(after)}' and eventTimestamp le '{stamp(now)}'"
    path = f"/subscriptions/{subscription}/providers/Microsoft.Insights/eventtypes/management/values"
    return "https://management.azure.com" + path + "?" + urlencode({"api-version": _API_VERSION, "$filter": interval}), path


def _continuation(url, path, expected_filter):
    if not isinstance(url, str) or len(url) > 12_000:
        raise LogAccessError("invalid_azure_log_continuation")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "management.azure.com" or parsed.path.lower() != path.lower() or parsed.username or parsed.password or parsed.port or parsed.fragment:
        raise LogAccessError("invalid_azure_log_continuation")
    values = parse_qs(parsed.query, keep_blank_values=True)
    if (not values or set(values) - {"api-version", "$filter", "$skiptoken"}
            or values.get("api-version", [_API_VERSION]) != [_API_VERSION]
            or values.get("$filter", [expected_filter]) != [expected_filter]
            or "$skiptoken" not in values or len(values["$skiptoken"]) != 1
            or not values["$skiptoken"][0] or len(values["$skiptoken"][0]) > 8192):
        raise LogAccessError("invalid_azure_log_continuation")


def _read_pages(transport, subscription, *, analyze):
    url, path = _initial_url(subscription)
    expected_filter = parse_qs(urlsplit(url).query)["$filter"][0]
    events = []
    read_count = 0
    ignored = 0
    relevant = 0
    truncated = False
    max_pages = MAX_PAGES if analyze else 1
    for _ in range(max_pages):
        try:
            page = transport.request(url, max_response_bytes=MAX_RESPONSE_BYTES)
        except Exception:
            raise LogAccessError("azure_log_read_failed") from None
        if not isinstance(page, dict) or not isinstance(page.get("value"), list):
            raise LogAccessError("invalid_azure_log_response")
        rows = page["value"]
        remaining = MAX_EVENTS - read_count
        for row in rows[:remaining]:
            if _is_foreign_scope(row, subscription):
                raise LogAccessError("azure_log_foreign_subscription")
            read_count += 1
            if not analyze:
                continue
            normalized = normalize_azure_activity_event(row, subscription)
            if normalized is None:
                ignored += 1
                continue
            events.append(normalized)
            if normalized["request.role_assignment_write"] and normalized["event.outcome"] == "success":
                relevant += 1
        next_url = page.get("nextLink")
        if next_url is not None and not isinstance(next_url, str):
            raise LogAccessError("invalid_azure_log_response")
        if next_url:
            _continuation(next_url, path, expected_filter)
        if read_count >= MAX_EVENTS:
            truncated = bool(next_url or len(rows) > remaining)
            break
        if not next_url:
            break
        url = next_url
    else:
        truncated = bool(next_url)
    return read_count, events, ignored, relevant, truncated


def _run(auth, scopes, options, source, *, analyze):
    if _value(source, "kind") != "azure_activity_log":
        raise LogAccessError("unsupported_log_source")
    subscription = _selected_subscription(scopes, source)
    transport = AzureTransport(auth)
    try:
        read_count, events, ignored, relevant, truncated = _read_pages(transport, subscription, analyze=analyze)
    finally:
        transport.close()
    if not analyze:
        return {
            "subscription_id": subscription,
            "source_status": "accessible",
            "coverage": "Azure Activity Log read succeeded for the selected subscription and last 24 hours. An empty response does not prove that all operations were logged or retained.",
        }
    return {
        "coverage": {"subscription_id": subscription, "source": "azure_activity_log",
                     "window_hours": 24, "events_read": read_count,
                     "events_normalized": len(events), "events_ignored": ignored,
                     "successful_role_assignment_writes": relevant,
                     "truncated": truncated, "detection_status": "not_implemented"},
        "detections": [],
    }


def check_azure_source(auth, scopes, options, source):
    return _run(auth, scopes, options, source, analyze=False)


def analyze_azure_source(auth, scopes, options, source):
    return _run(auth, scopes, options, source, analyze=True)
