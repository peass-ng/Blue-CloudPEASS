"""Narrow Cloud Logging audit-stream suppression candidates.

These are observed successful API operations in a single project. They don't
prove that entries existed before deletion, or that other sinks or buckets
stopped retaining the same records.
"""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
_EMAIL = re.compile(r"[^\s@:/]+@[^\s@:/]+\.[^\s@:/]+\Z")
_EXCLUSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
_LOG = re.compile(r"projects/([^/]+)/logs/cloudaudit\.googleapis\.com%2Factivity\Z")
_AUDIT_TYPE = "type.googleapis.com/google.cloud.audit.AuditLog"
_DELETE_REQUEST_TYPE = "type.googleapis.com/google.logging.v2.DeleteLogRequest"
_EXCLUSION_REQUEST_TYPE = "type.googleapis.com/google.logging.v2.CreateExclusionRequest"
_EXCLUSION_TYPE = "type.googleapis.com/google.logging.v2.LogExclusion"


def _context(record: Mapping[str, Any]) -> tuple[str, Mapping[str, Any], str, str, str] | None:
    if not isinstance(record, Mapping):
        return None
    log_name = record.get("logName")
    match = _LOG.fullmatch(log_name) if isinstance(log_name, str) else None
    if match is None or _PROJECT.fullmatch(match.group(1)) is None:
        return None
    project = match.group(1)
    resource = record.get("resource")
    if not isinstance(resource, Mapping):
        return None
    labels = resource.get("labels")
    if labels is not None and (not isinstance(labels, Mapping) or labels.get("project_id", project) != project):
        return None
    payload = record.get("protoPayload")
    if not isinstance(payload, Mapping) or payload.get("@type") != _AUDIT_TYPE or payload.get("serviceName") != "logging.googleapis.com":
        return None
    status = payload.get("status")
    if status is not None and (
        not isinstance(status, Mapping)
        or (status and (type(status.get("code")) is not int or status["code"] != 0))
    ):
        return None
    operation = record.get("operation")
    if operation is not None and (not isinstance(operation, Mapping) or operation.get("last") is not True):
        return None
    auth = payload.get("authenticationInfo")
    actor = auth.get("principalEmail") if isinstance(auth, Mapping) else None
    event_id, event_time = record.get("insertId"), record.get("timestamp")
    if not isinstance(actor, str) or _EMAIL.fullmatch(actor) is None:
        return None
    if not isinstance(event_id, str) or not event_id or not isinstance(event_time, str) or not event_time:
        return None
    return project, payload, actor.lower(), event_id, event_time


def normalize_gcp_data_access_log_delete(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Observe a successful DeleteLog for the project's Data Access stream.

    DeleteLog affects the global `_Default` bucket only. It neither removes
    `_Required` records nor proves there were entries in the deleted stream.
    """
    context = _context(record)
    if context is None:
        return None
    project, payload, actor, event_id, event_time = context
    if payload.get("methodName") != "google.logging.v2.LoggingServiceV2.DeleteLog":
        return None
    target = f"projects/{project}/logs/cloudaudit.googleapis.com%2Fdata_access"
    if payload.get("resourceName") not in (None, target):
        return None
    request, response = payload.get("request"), payload.get("response")
    if not isinstance(request, Mapping) or request.get("@type") != _DELETE_REQUEST_TYPE or request.get("logName") != target:
        return None
    if not isinstance(response, Mapping) or response not in ({}, {"@type": "type.googleapis.com/google.protobuf.Empty"}):
        return None
    return {
        "cloud.provider": "gcp",
        "event.name": "data_access_audit_log_delete_succeeded",
        "event.source": "logging.googleapis.com",
        "event.outcome": "success",
        "event.id": event_id,
        "event.time": event_time,
        "account.id": project,
        "actor.id": actor,
        "target.id": target,
        "request.audit_stream": "DATA_ACCESS",
        "storage.scope": "_Default",
    }


def normalize_gcp_data_access_exclusion_created(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Observe an enabled `_Default` exclusion for one exact audit log name.

    This intentionally accepts only one simple exact-equality filter form;
    broader valid Logging filters are left for explicit human review.
    """
    context = _context(record)
    if context is None:
        return None
    project, payload, actor, event_id, event_time = context
    if payload.get("methodName") != "google.logging.v2.ConfigServiceV2.CreateExclusion":
        return None
    request, response = payload.get("request"), payload.get("response")
    if not isinstance(request, Mapping) or request.get("@type") != _EXCLUSION_REQUEST_TYPE or request.get("parent") != f"projects/{project}":
        return None
    exclusion = request.get("exclusion")
    if not isinstance(exclusion, Mapping) or not isinstance(response, Mapping) or response.get("@type") != _EXCLUSION_TYPE:
        return None
    name = exclusion.get("name")
    if not isinstance(name, str) or _EXCLUSION.fullmatch(name) is None or response.get("name") != name:
        return None
    target = f"projects/{project}/exclusions/{name}"
    if payload.get("resourceName") not in (None, target):
        return None
    audit_log = f"projects/{project}/logs/cloudaudit.googleapis.com%2Fdata_access"
    exact_filter = f'logName="{audit_log}"'
    if exclusion.get("filter") != exact_filter or response.get("filter") != exact_filter:
        return None
    if exclusion.get("disabled") is not False or response.get("disabled") is not False:
        return None
    return {
        "cloud.provider": "gcp",
        "event.name": "data_access_audit_log_exclusion_created",
        "event.source": "logging.googleapis.com",
        "event.outcome": "success",
        "event.id": event_id,
        "event.time": event_time,
        "account.id": project,
        "actor.id": actor,
        "target.id": target,
        "request.audit_stream": "DATA_ACCESS",
        "request.exclusion_enabled": True,
        "request.exact_log_name_filter": True,
        "storage.scope": "_Default",
    }
