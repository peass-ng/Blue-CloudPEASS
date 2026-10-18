"""Conservative Cloud Logging _Default sink disable observation.

The Logging API updates only fields named in UpdateSinkRequest.updateMask.
Requiring that mask, the requested disabled value, and the returned LogSink
state prevents a filter-only update to an already disabled sink from matching.
The event does not establish whether the sink was enabled beforehand.
"""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
_EMAIL = re.compile(r"[^\s@:/]+@[^\s@:/]+\.[^\s@:/]+\Z")
_LOG = re.compile(r"projects/([^/]+)/logs/cloudaudit\.googleapis\.com%2Factivity\Z")
_AUDIT_TYPE = "type.googleapis.com/google.cloud.audit.AuditLog"
_METHOD = "google.logging.v2.ConfigServiceV2.UpdateSink"
_REQUEST_TYPE = "type.googleapis.com/google.logging.v2.UpdateSinkRequest"
_SINK_TYPE = "type.googleapis.com/google.logging.v2.LogSink"


def normalize_gcp_default_sink_disabled(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return a completed project `_Default` sink disabled-setting event.

    The Admin Activity entry and response prove the requested setting was
    applied. They do not prove a state transition, any lost entries, or that
    other log routes were absent. `_Required` is unaffected by this setting.
    """
    if not isinstance(record, Mapping):
        return None
    log_name = record.get("logName")
    log_match = _LOG.fullmatch(log_name) if isinstance(log_name, str) else None
    if log_match is None:
        return None
    project = log_match.group(1)
    if _PROJECT.fullmatch(project) is None:
        return None
    resource = record.get("resource")
    if not isinstance(resource, Mapping):
        return None
    labels = resource.get("labels")
    if labels is not None and (not isinstance(labels, Mapping) or labels.get("project_id", project) != project):
        return None
    payload = record.get("protoPayload")
    if not isinstance(payload, Mapping) or payload.get("@type") != _AUDIT_TYPE:
        return None
    if payload.get("serviceName") != "logging.googleapis.com" or payload.get("methodName") != _METHOD:
        return None
    sink_name = f"projects/{project}/sinks/_Default"
    if payload.get("resourceName") not in (None, sink_name):
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
    request = payload.get("request")
    response = payload.get("response")
    if not all(isinstance(value, Mapping) for value in (auth, request, response)):
        return None
    actor = auth.get("principalEmail")
    if not isinstance(actor, str) or _EMAIL.fullmatch(actor) is None:
        return None
    if request.get("@type") != _REQUEST_TYPE or request.get("sinkName") != sink_name:
        return None
    request_sink = request.get("sink")
    if not isinstance(request_sink, Mapping) or request_sink.get("name") != "_Default" or request_sink.get("disabled") is not True:
        return None
    mask = request.get("updateMask")
    if not isinstance(mask, str) or "disabled" not in {field.strip() for field in mask.split(",")}:
        return None
    if response.get("@type") != _SINK_TYPE or response.get("name") != "_Default" or response.get("disabled") is not True:
        return None
    if response.get("resourceName") not in (None, sink_name):
        return None
    event_id = record.get("insertId")
    event_time = record.get("timestamp")
    if not isinstance(event_id, str) or not event_id or not isinstance(event_time, str) or not event_time:
        return None
    return {
        "cloud.provider": "gcp",
        "event.name": "default_log_sink_disable_update_succeeded",
        "event.source": "logging.googleapis.com",
        "event.outcome": "success",
        "event.id": event_id,
        "event.time": event_time,
        "account.id": project,
        "actor.id": actor.lower(),
        "target.id": sink_name,
        "request.disabled": True,
        "request.disabled_field_updated": True,
        "sink.disabled_after_update": True,
    }
