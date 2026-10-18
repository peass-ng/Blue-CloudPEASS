"""Conservative Secret Manager version operation observations from Admin Activity.

DestroySecretVersion omits ``protoPayload.response`` in real Cloud Logging
records. It is therefore an observed successful API operation, not proof of
the final version state. DisableSecretVersion includes a typed response whose
DISABLED state can be confirmed. Neither observation implies malicious intent.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

from peaso.attack_detection.gcp import _PRINCIPAL_EMAIL, _PROJECT


_LOG = re.compile(r"projects/([^/]+)/logs/cloudaudit\.googleapis\.com%2Factivity\Z")
_VERSION = re.compile(r"projects/([^/]+)/secrets/([A-Za-z0-9_-]{1,255})/versions/([1-9][0-9]*)\Z")
_SECRET = re.compile(r"projects/([^/]+)/secrets/([A-Za-z0-9_-]{1,255})\Z")
_AUDIT = "type.googleapis.com/google.cloud.audit.AuditLog"
_PREFIX = "google.cloud.secretmanager.v1.SecretManagerService."
_TYPE_PREFIX = "type.googleapis.com/google.cloud.secretmanager.v1."


def _normal(record: Mapping[str, Any], operation: str) -> dict[str, Any] | None:
    if not isinstance(record, Mapping):
        return None
    log_name = record.get("logName")
    log = _LOG.fullmatch(log_name) if isinstance(log_name, str) else None
    if log is None or _PROJECT.fullmatch(log.group(1)) is None:
        return None
    project = log.group(1)
    resource = record.get("resource")
    if not isinstance(resource, Mapping) or resource.get("type") != "audited_resource":
        return None
    labels = resource.get("labels")
    method = _PREFIX + operation + "SecretVersion"
    if (not isinstance(labels, Mapping) or labels.get("project_id") != project
            or labels.get("service") != "secretmanager.googleapis.com"
            or labels.get("method") != method):
        return None
    payload = record.get("protoPayload")
    if (not isinstance(payload, Mapping) or payload.get("@type") != _AUDIT
            or payload.get("serviceName") != "secretmanager.googleapis.com"
            or payload.get("methodName") != method):
        return None
    status = payload.get("status")
    if not isinstance(status, Mapping) or (status and status != {"code": 0}):
        return None
    if record.get("operation") is not None:
        op = record["operation"]
        if not isinstance(op, Mapping) or op.get("last") is not True:
            return None
    auth, request = payload.get("authenticationInfo"), payload.get("request")
    if not isinstance(auth, Mapping) or not isinstance(request, Mapping):
        return None
    actor = auth.get("principalEmail")
    if not isinstance(actor, str) or _PRINCIPAL_EMAIL.fullmatch(actor) is None:
        return None
    if request.get("@type") != _TYPE_PREFIX + operation + "SecretVersionRequest":
        return None
    request_name = request.get("name")
    requested = _VERSION.fullmatch(request_name) if isinstance(request_name, str) else None
    if requested is None or requested.group(1) != project:
        return None
    observed_name = payload.get("resourceName")
    observed = _VERSION.fullmatch(observed_name) if isinstance(observed_name, str) else None
    if (observed is None or observed.group(2, 3) != requested.group(2, 3)
            or (observed.group(1) != project and not observed.group(1).isdecimal())):
        return None
    response = payload.get("response")
    if operation == "Disable":
        if (not isinstance(response, Mapping)
                or response.get("@type") != _TYPE_PREFIX + "SecretVersion"
                or response.get("name") != observed_name
                or response.get("state") != "DISABLED"):
            return None
    elif response is not None:
        # A returned state may be used only when it agrees with the invocation.
        if (not isinstance(response, Mapping)
                or response.get("@type") != _TYPE_PREFIX + "SecretVersion"
                or response.get("name") != observed_name
                or response.get("state") != "DESTROYED"):
            return None
    event_id, event_time = record.get("insertId"), record.get("timestamp")
    if not isinstance(event_id, str) or not event_id or not isinstance(event_time, str):
        return None
    try:
        parsed = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    result = {
        "cloud.provider": "gcp", "event.source": "secretmanager.googleapis.com",
        "event.name": method, "event.outcome": "success", "event.id": event_id,
        "event.time": event_time, "account.id": project, "actor.id": actor.lower(),
        "target.id": request_name,
        "secret.version_operation": operation.lower(),
    }
    if operation == "Disable":
        result["secret.version_state"] = "DISABLED"
    else:
        result["secret.version_destroy_invoked"] = True
        result["secret.version_state_confirmed"] = response is not None
        if response is not None:
            result["secret.version_state"] = "DESTROYED"
    return result


def normalize_gcp_secret_version_destroy(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Observe a successful DestroySecretVersion call, with response if present."""
    return _normal(record, "Destroy")


def normalize_gcp_secret_version_disable(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Confirm a successful DisableSecretVersion response in DISABLED state."""
    return _normal(record, "Disable")


def normalize_gcp_secret_delete(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Observe a successful DeleteSecret call; no final-state or intent claim.

    Secret cleanup and rotation are legitimate uses. Consumers should present
    this as a review signal, not an attacker verdict.
    """
    if not isinstance(record, Mapping):
        return None
    log_name = record.get("logName")
    log = _LOG.fullmatch(log_name) if isinstance(log_name, str) else None
    if log is None or _PROJECT.fullmatch(log.group(1)) is None:
        return None
    project = log.group(1)
    method = _PREFIX + "DeleteSecret"
    resource = record.get("resource")
    if not isinstance(resource, Mapping) or resource.get("type") != "audited_resource":
        return None
    labels = resource.get("labels")
    if (not isinstance(labels, Mapping) or labels.get("project_id") != project
            or labels.get("service") != "secretmanager.googleapis.com"
            or labels.get("method") != method):
        return None
    payload = record.get("protoPayload")
    if (not isinstance(payload, Mapping) or payload.get("@type") != _AUDIT
            or payload.get("serviceName") != "secretmanager.googleapis.com"
            or payload.get("methodName") != method):
        return None
    status = payload.get("status")
    if not isinstance(status, Mapping) or (status and status != {"code": 0}):
        return None
    if record.get("operation") is not None:
        op = record["operation"]
        if not isinstance(op, Mapping) or op.get("last") is not True:
            return None
    auth, request = payload.get("authenticationInfo"), payload.get("request")
    if not isinstance(auth, Mapping) or not isinstance(request, Mapping):
        return None
    actor = auth.get("principalEmail")
    if not isinstance(actor, str) or _PRINCIPAL_EMAIL.fullmatch(actor) is None:
        return None
    if request.get("@type") != _TYPE_PREFIX + "DeleteSecretRequest":
        return None
    request_name = request.get("name")
    requested = _SECRET.fullmatch(request_name) if isinstance(request_name, str) else None
    observed_name = payload.get("resourceName")
    observed = _SECRET.fullmatch(observed_name) if isinstance(observed_name, str) else None
    if (requested is None or requested.group(1) != project or observed is None
            or observed.group(2) != requested.group(2)
            or (observed.group(1) != project and not observed.group(1).isdecimal())
            or payload.get("response") is not None):
        return None
    event_id, event_time = record.get("insertId"), record.get("timestamp")
    if not isinstance(event_id, str) or not event_id or not isinstance(event_time, str):
        return None
    try:
        parsed = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return {
        "cloud.provider": "gcp", "event.source": "secretmanager.googleapis.com",
        "event.name": method, "event.outcome": "success", "event.id": event_id,
        "event.time": event_time, "account.id": project, "actor.id": actor.lower(),
        "target.id": request_name, "secret.delete_invoked": True,
    }
