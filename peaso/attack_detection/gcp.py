"""Normalize proven service-account key creation from Google Cloud Audit Logs."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
_ACCOUNT_EMAIL = re.compile(r"[a-z][a-z0-9-]*@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com\Z")
_PRINCIPAL_EMAIL = re.compile(r"[^\s@:/]+@[^\s@:/]+\.[^\s@:/]+\Z")
_TOKEN_CREATOR = "roles/iam.serviceAccountTokenCreator"
_AUDIT_TYPE = "type.googleapis.com/google.cloud.audit.AuditLog"
_POLICY_TYPE = "type.googleapis.com/google.iam.v1.Policy"
_REQUEST_TYPE = "type.googleapis.com/google.iam.v1.SetIamPolicyRequest"


def _owned_service_account_path(value: Any, project: str) -> str | None:
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"projects/([^/]+)/serviceAccounts/([^/]+)", value)
    if match is None or match.group(1) not in ("-", project):
        return None
    email = match.group(2)
    if _ACCOUNT_EMAIL.fullmatch(email) is None or not email.endswith(f"@{project}.iam.gserviceaccount.com"):
        return None
    return email


def normalize_gcp_uploaded_service_account_key(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Observe a completed uploaded public key, without retaining key material.

    This proves that the IAM operation returned a key resource. It does not
    establish whether the corresponding private key was subsequently used.
    """
    if not isinstance(record, Mapping):
        return None
    log_name = record.get("logName")
    log_match = re.fullmatch(r"projects/([^/]+)/logs/cloudaudit\.googleapis\.com%2Factivity", log_name) if isinstance(log_name, str) else None
    if log_match is None or _PROJECT.fullmatch(log_match.group(1)) is None:
        return None
    project = log_match.group(1)
    resource = record.get("resource")
    if not isinstance(resource, Mapping) or resource.get("type") != "service_account":
        return None
    labels = resource.get("labels")
    if isinstance(labels, Mapping) and labels.get("project_id") not in (None, project):
        return None
    payload = record.get("protoPayload")
    if not isinstance(payload, Mapping) or payload.get("@type") != _AUDIT_TYPE:
        return None
    if payload.get("serviceName") != "iam.googleapis.com" or payload.get("methodName") != "google.iam.admin.v1.UploadServiceAccountKey":
        return None
    status = payload.get("status")
    if status is not None and (not isinstance(status, Mapping) or status.get("code") not in (None, 0) or isinstance(status.get("code"), bool)):
        return None
    auth = payload.get("authenticationInfo")
    request = payload.get("request")
    response = payload.get("response")
    if not isinstance(auth, Mapping) or not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    if request.get("@type") != "type.googleapis.com/google.iam.admin.v1.UploadServiceAccountKeyRequest":
        return None
    if response.get("@type") != "type.googleapis.com/google.iam.admin.v1.ServiceAccountKey":
        return None
    actor = auth.get("principalEmail")
    if not isinstance(actor, str) or _PRINCIPAL_EMAIL.fullmatch(actor) is None:
        return None
    target_email = _owned_service_account_path(request.get("name"), project)
    if target_email is None:
        return None
    key_name = response.get("name")
    if not isinstance(key_name, str):
        return None
    key_match = re.fullmatch(r"(projects/[^/]+/serviceAccounts/[^/]+)/keys/([A-Za-z0-9_-]+)", key_name)
    if key_match is None or _owned_service_account_path(key_match.group(1), project) != target_email:
        return None
    if response.get("keyOrigin") not in (None, "USER_PROVIDED"):
        return None
    named_resource = payload.get("resourceName")
    if named_resource is not None:
        named_match = re.fullmatch(r"projects/([^/]+)/serviceAccounts/([^/]+)", named_resource) if isinstance(named_resource, str) else None
        if named_match is None or named_match.group(1) not in ("-", project):
            return None
        if not (named_match.group(2).isdigit() or named_match.group(2) == target_email):
            return None
    event_id = record.get("insertId")
    event_time = record.get("timestamp")
    if not isinstance(event_id, str) or not event_id or not isinstance(event_time, str) or not event_time:
        return None
    return {
        "cloud.provider": "gcp",
        "event.name": "google.iam.admin.v1.UploadServiceAccountKey",
        "event.source": "iam.googleapis.com",
        "event.outcome": "success",
        "event.id": event_id,
        "event.time": event_time,
        "account.id": project,
        "actor.id": actor.lower(),
        "target.id": request["name"],
        "credential.key_name": key_name,
        "credential.key_origin": "USER_PROVIDED",
        "credential.upload_observed": True,
    }


def normalize_gcp_token_creator_binding_observation(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return a policy-binding observation for a separately reviewed rule.

    A SetIAMPolicy response contains the resulting complete policy, not a
    before/after delta. Therefore this event does not prove a new privilege.
    """
    if not isinstance(record, Mapping):
        return None
    log_name = record.get("logName")
    if not isinstance(log_name, str):
        return None
    log_match = re.fullmatch(r"projects/([^/]+)/logs/cloudaudit\.googleapis\.com%2Factivity", log_name)
    if log_match is None or _PROJECT.fullmatch(log_match.group(1)) is None:
        return None
    project = log_match.group(1)
    resource = record.get("resource")
    if not isinstance(resource, Mapping) or resource.get("type") != "service_account":
        return None
    labels = resource.get("labels")
    if isinstance(labels, Mapping) and labels.get("project_id") not in (None, project):
        return None
    payload = record.get("protoPayload")
    if not isinstance(payload, Mapping) or payload.get("@type") != _AUDIT_TYPE:
        return None
    if payload.get("serviceName") != "iam.googleapis.com" or payload.get("methodName") != "google.iam.admin.v1.SetIAMPolicy":
        return None
    status = payload.get("status")
    if status is not None and (not isinstance(status, Mapping) or status.get("code") not in (None, 0) or isinstance(status.get("code"), bool)):
        return None
    auth = payload.get("authenticationInfo")
    request = payload.get("request")
    response = payload.get("response")
    if not isinstance(auth, Mapping) or not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    if request.get("@type") != _REQUEST_TYPE or response.get("@type") != _POLICY_TYPE:
        return None
    actor = auth.get("principalEmail")
    if not isinstance(actor, str) or _PRINCIPAL_EMAIL.fullmatch(actor) is None:
        return None
    actor = actor.lower()
    requested_resource = request.get("resource")
    if not isinstance(requested_resource, str):
        return None
    target_match = re.fullmatch(r"projects/-/serviceAccounts/([^/]+)", requested_resource)
    if target_match is None:
        return None
    target_email = target_match.group(1)
    if _ACCOUNT_EMAIL.fullmatch(target_email) is None or not target_email.endswith(f"@{project}.iam.gserviceaccount.com"):
        return None
    named_resource = payload.get("resourceName")
    named_match = re.fullmatch(r"projects/-/serviceAccounts/([^/]+)", named_resource) if isinstance(named_resource, str) else None
    if named_match is None or not (named_match.group(1).isdigit() or named_match.group(1) == target_email):
        return None
    member = ("serviceAccount:" if actor.endswith(".gserviceaccount.com") else "user:") + actor
    bindings = response.get("bindings")
    if not isinstance(bindings, list):
        return None
    if not any(isinstance(binding, Mapping) and binding.get("role") == _TOKEN_CREATOR
               and "condition" not in binding and isinstance(binding.get("members"), list)
               and member in binding["members"] for binding in bindings):
        return None
    event_id = record.get("insertId")
    event_time = record.get("timestamp")
    if not isinstance(event_id, str) or not event_id or not isinstance(event_time, str) or not event_time:
        return None
    return {
        "cloud.provider": "gcp",
        "event.name": "service_account_token_creator_self_binding_observed",
        "event.source": "iam.googleapis.com",
        "event.outcome": "success",
        "event.id": event_id,
        "event.time": event_time,
        "account.id": project,
        "actor.id": actor,
        "target.id": requested_resource,
        "request.actor_is_member": True,
        "request.role": _TOKEN_CREATOR,
        "request.binding_observed": True,
        "target.service_account": target_email,
    }


def normalize_gcp_audit(record: Mapping[str, Any]) -> dict[str, Any] | None:
    uploaded_key = normalize_gcp_uploaded_service_account_key(record)
    if uploaded_key is not None:
        return uploaded_key
    payload = record.get("protoPayload") if isinstance(record, Mapping) else None
    if isinstance(payload, Mapping) and payload.get("methodName") == "google.iam.admin.v1.UploadServiceAccountKey":
        return None
    policy_binding = normalize_gcp_token_creator_binding_observation(record)
    if policy_binding is not None:
        return policy_binding
    if not isinstance(payload, Mapping) or payload.get("@type") != "type.googleapis.com/google.cloud.audit.AuditLog":
        return None
    if payload.get("serviceName") != "iam.googleapis.com":
        return None
    log_name = record.get("logName")
    if not isinstance(log_name, str) or not log_name.endswith("/logs/cloudaudit.googleapis.com%2Factivity"):
        return None
    auth = payload.get("authenticationInfo")
    auth = auth if isinstance(auth, Mapping) else {}
    request = payload.get("request")
    request = request if isinstance(request, Mapping) else {}
    response = payload.get("response")
    response = response if isinstance(response, Mapping) else {}
    status = payload.get("status")
    status = status if isinstance(status, Mapping) else {}
    code = status.get("code")
    target = request.get("name")
    key_name = response.get("name")
    key_returned = isinstance(key_name, str) and "/serviceAccounts/" in key_name and "/keys/" in key_name and bool(key_name.rsplit("/keys/", 1)[-1])
    explicit_success = code == 0 and not isinstance(code, bool)
    if code not in (None, 0) or not (explicit_success or key_returned):
        return None
    if not isinstance(target, str) or not target.startswith("projects/") or "/serviceAccounts/" not in target or not target.rsplit("/serviceAccounts/", 1)[-1]:
        return None
    return {
        "cloud.provider": "gcp",
        "event.name": payload.get("methodName"),
        "event.source": payload.get("serviceName"),
        "event.outcome": "success",
        "event.id": record.get("insertId"),
        "event.time": record.get("timestamp"),
        "account.id": log_name.split("/logs/", 1)[0],
        "actor.id": auth.get("principalEmail"),
        "target.id": target,
        "credential.key_name": key_name if key_returned else None,
        "credential.effect_confirmed": True,
    }
