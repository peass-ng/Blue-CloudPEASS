"""Observe a completed Cloud Storage HMAC key creation from Admin Activity.

The returned metadata identifies the key and service account. It does not
establish that the credential was used or that creation was unauthorized.
The HMAC secret is never included in the normalized event.
"""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from peaso.attack_detection.gcp import _ACCOUNT_EMAIL, _PRINCIPAL_EMAIL, _PROJECT, _successful_status


_LOG = re.compile(r"projects/([^/]+)/logs/cloudaudit\.googleapis\.com%2Factivity\Z")
_RESOURCE_NAME = re.compile(r"projects/([^/]+)\Z")
_ACCESS_ID = re.compile(r"GOOG[A-Z0-9]+\Z")
_AUDIT_TYPE = "type.googleapis.com/google.cloud.audit.AuditLog"
_REQUEST_TYPE = "type.googleapis.com/google.storage.v1.CreateHmacKeyRequest"
_RESPONSE_TYPE = "type.googleapis.com/google.storage.v1.CreateHmacKeyResponse"


def normalize_gcp_hmac_key_created(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return only an exact, successful HMAC creation observation.

    Cloud Storage can use a numeric project in ``resourceName`` while the
    request, returned metadata, resource label, and log name use the project
    ID. A response with no returned key metadata is not enough evidence.
    """
    if not isinstance(record, Mapping):
        return None
    log_name = record.get("logName")
    log_match = _LOG.fullmatch(log_name) if isinstance(log_name, str) else None
    if log_match is None or _PROJECT.fullmatch(log_match.group(1)) is None:
        return None
    project = log_match.group(1)
    resource = record.get("resource")
    if not isinstance(resource, Mapping) or resource.get("type") != "audited_resource":
        return None
    labels = resource.get("labels")
    if not isinstance(labels, Mapping) or labels.get("project_id") != project:
        return None
    payload = record.get("protoPayload")
    if not isinstance(payload, Mapping) or payload.get("@type") != _AUDIT_TYPE:
        return None
    if payload.get("serviceName") != "storage.googleapis.com" or payload.get("methodName") != "storage.hmacKeys.create":
        return None
    resource_name = payload.get("resourceName")
    resource_match = _RESOURCE_NAME.fullmatch(resource_name) if isinstance(resource_name, str) else None
    if resource_match is None or (resource_match.group(1) != project and not resource_match.group(1).isdecimal()):
        return None
    status = payload.get("status")
    if not isinstance(status, Mapping) or not _successful_status(status):
        return None
    if status and (type(status.get("code")) is not int or status["code"] != 0 or status.get("message")):
        return None
    operation = record.get("operation")
    if operation is not None and (not isinstance(operation, Mapping) or operation.get("last") is not True):
        return None
    auth, request, response = (payload.get(key) for key in ("authenticationInfo", "request", "response"))
    if not all(isinstance(value, Mapping) for value in (auth, request, response)):
        return None
    actor = auth.get("principalEmail")
    if not isinstance(actor, str) or _PRINCIPAL_EMAIL.fullmatch(actor) is None:
        return None
    if request.get("@type") != _REQUEST_TYPE or response.get("@type") != _RESPONSE_TYPE:
        return None
    if request.get("projectId") != project:
        return None
    target = request.get("serviceAccountEmail")
    if not isinstance(target, str) or _ACCOUNT_EMAIL.fullmatch(target) is None:
        return None
    if not target.endswith(f"@{project}.iam.gserviceaccount.com"):
        return None
    metadata = response.get("metadata")
    if not isinstance(metadata, Mapping):
        return None
    access_id = metadata.get("accessId")
    if not isinstance(access_id, str) or _ACCESS_ID.fullmatch(access_id) is None:
        return None
    if (metadata.get("projectId") != project
            or metadata.get("serviceAccountEmail") != target
            or metadata.get("id") != f"{project}/{access_id}"
            or metadata.get("state") != "ACTIVE"):
        return None
    event_id, event_time = record.get("insertId"), record.get("timestamp")
    if not isinstance(event_id, str) or not event_id or not isinstance(event_time, str) or not event_time:
        return None
    return {
        "cloud.provider": "gcp",
        "event.source": "storage.googleapis.com",
        "event.name": "storage.hmacKeys.create",
        "event.outcome": "success",
        "event.id": event_id,
        "event.time": event_time,
        "account.id": project,
        "actor.id": actor.lower(),
        "target.id": f"projects/{project}/hmacKeys/{access_id}",
        "target.service_account": target,
        "credential.access_id": access_id,
        "credential.hmac_key_create_observed": True,
    }
