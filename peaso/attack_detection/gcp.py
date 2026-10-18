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


def _successful_status(value: Any, *, require_code: bool = False) -> bool:
    if value is None:
        return not require_code
    if not isinstance(value, Mapping):
        return False
    code = value.get("code")
    return (type(code) is int and code == 0) if require_code else (code is None or type(code) is int and code == 0)


def normalize_gcp_generated_access_token(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Observe a successful cross-principal service-account token mint.

    A successful mint is not evidence that the token was used or that the
    impersonation was unauthorized. Token values are never returned.
    """
    if not isinstance(record, Mapping):
        return None
    log_name = record.get("logName")
    log_match = re.fullmatch(r"projects/([^/]+)/logs/cloudaudit\.googleapis\.com%2Fdata_access", log_name) if isinstance(log_name, str) else None
    if log_match is None or _PROJECT.fullmatch(log_match.group(1)) is None:
        return None
    project = log_match.group(1)
    resource = record.get("resource")
    if not isinstance(resource, Mapping) or resource.get("type") != "service_account":
        return None
    labels = resource.get("labels")
    if not isinstance(labels, Mapping) or labels.get("project_id") != project:
        return None
    target_email = labels.get("email_id")
    if not isinstance(target_email, str) or _ACCOUNT_EMAIL.fullmatch(target_email) is None:
        return None
    if not target_email.endswith(f"@{project}.iam.gserviceaccount.com"):
        return None
    payload = record.get("protoPayload")
    if not isinstance(payload, Mapping) or payload.get("@type") != _AUDIT_TYPE:
        return None
    if payload.get("serviceName") != "iamcredentials.googleapis.com" or payload.get("methodName") != "GenerateAccessToken":
        return None
    status = payload.get("status")
    if not _successful_status(status, require_code=True):
        return None
    auth = payload.get("authenticationInfo")
    request = payload.get("request")
    if not isinstance(auth, Mapping) or not isinstance(request, Mapping):
        return None
    if request.get("@type") != "type.googleapis.com/google.iam.credentials.v1.GenerateAccessTokenRequest":
        return None
    target = request.get("name")
    if target != f"projects/-/serviceAccounts/{target_email}":
        return None
    actor = auth.get("principalEmail")
    if not isinstance(actor, str) or _PRINCIPAL_EMAIL.fullmatch(actor) is None or actor.lower() == target_email:
        return None
    named_resource = payload.get("resourceName")
    if named_resource is not None:
        named_match = re.fullmatch(r"projects/([^/]+)/serviceAccounts/([^/]+)", named_resource) if isinstance(named_resource, str) else None
        if named_match is None or named_match.group(1) not in ("-", project):
            return None
        label_id = labels.get("unique_id")
        if named_match.group(2) != target_email and (not isinstance(label_id, str) or named_match.group(2) != label_id):
            return None
    operation = record.get("operation")
    if operation is not None and (not isinstance(operation, Mapping) or operation.get("first") is True and operation.get("last") is not True):
        return None
    event_id = record.get("insertId")
    event_time = record.get("timestamp")
    if not isinstance(event_id, str) or not event_id or not isinstance(event_time, str) or not event_time:
        return None
    return {
        "cloud.provider": "gcp",
        "event.name": "GenerateAccessToken",
        "event.source": "iamcredentials.googleapis.com",
        "event.outcome": "success",
        "event.id": event_id,
        "event.time": event_time,
        "account.id": project,
        "actor.id": actor.lower(),
        "target.id": target,
        "target.service_account": target_email,
        "request.cross_principal": True,
        "credential.token_mint_observed": True,
    }


def normalize_gcp_undeleted_service_account(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Observe a restored service-account identity, without inferring access.

    The returned unique ID proves which deleted identity was restored. Its
    permissions and usable credentials require separate evidence.
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
    if payload.get("serviceName") != "iam.googleapis.com" or payload.get("methodName") != "google.iam.admin.v1.UndeleteServiceAccount":
        return None
    status = payload.get("status")
    if not _successful_status(status):
        return None
    auth = payload.get("authenticationInfo")
    request = payload.get("request")
    response = payload.get("response")
    if not isinstance(auth, Mapping) or not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    if request.get("@type") != "type.googleapis.com/google.iam.admin.v1.UndeleteServiceAccountRequest":
        return None
    if response.get("@type") != "type.googleapis.com/google.iam.admin.v1.UndeleteServiceAccountResponse":
        return None
    actor = auth.get("principalEmail")
    if not isinstance(actor, str) or _PRINCIPAL_EMAIL.fullmatch(actor) is None:
        return None
    requested_name = request.get("name")
    requested_match = re.fullmatch(r"projects/([^/]+)/serviceAccounts/([0-9]{21})", requested_name) if isinstance(requested_name, str) else None
    if requested_match is None or requested_match.group(1) not in ("-", project):
        return None
    unique_id = requested_match.group(2)
    named_resource = payload.get("resourceName")
    named_match = re.fullmatch(r"projects/([^/]+)/serviceAccounts/([0-9]{21})", named_resource) if isinstance(named_resource, str) else None
    if named_match is None or named_match.group(1) not in ("-", project) or named_match.group(2) != unique_id:
        return None
    restored = response.get("restoredAccount")
    if not isinstance(restored, Mapping) or restored.get("projectId") != project or restored.get("uniqueId") != unique_id:
        return None
    email = restored.get("email")
    if not isinstance(email, str) or _owned_service_account_path(restored.get("name"), project) != email:
        return None
    event_id = record.get("insertId")
    event_time = record.get("timestamp")
    if not isinstance(event_id, str) or not event_id or not isinstance(event_time, str) or not event_time:
        return None
    return {
        "cloud.provider": "gcp",
        "event.name": "google.iam.admin.v1.UndeleteServiceAccount",
        "event.source": "iam.googleapis.com",
        "event.outcome": "success",
        "event.id": event_id,
        "event.time": event_time,
        "account.id": project,
        "actor.id": actor.lower(),
        "target.id": restored["name"],
        "target.service_account": email,
        "identity.unique_id": unique_id,
        "identity.restore_observed": True,
    }


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
    if not _successful_status(status):
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
    """Return a self-grant only when the audit delta and resulting policy agree."""
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
    if not _successful_status(status):
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
    target_match = re.fullmatch(r"projects/([^/]+)/serviceAccounts/([^/]+)", requested_resource)
    if target_match is None or target_match.group(1) not in ("-", project):
        return None
    target_email = target_match.group(2)
    if _ACCOUNT_EMAIL.fullmatch(target_email) is None or not target_email.endswith(f"@{project}.iam.gserviceaccount.com"):
        return None
    named_resource = payload.get("resourceName")
    named_match = re.fullmatch(r"projects/([^/]+)/serviceAccounts/([^/]+)", named_resource) if isinstance(named_resource, str) else None
    if (named_match is None or named_match.group(1) not in ("-", project)
            or not (named_match.group(2).isdigit() or named_match.group(2) == target_email)):
        return None
    member = ("serviceAccount:" if actor.endswith(".gserviceaccount.com") else "user:") + actor
    service_data = payload.get("serviceData")
    policy_delta = service_data.get("policyDelta") if isinstance(service_data, Mapping) else None
    deltas = policy_delta.get("bindingDeltas") if isinstance(policy_delta, Mapping) else None
    if not isinstance(deltas, list) or not any(
        isinstance(delta, Mapping) and delta.get("action") == "ADD"
        and delta.get("role") == _TOKEN_CREATOR and delta.get("member") == member
        and "condition" not in delta for delta in deltas
    ):
        return None
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
        "request.binding_added": True,
        "target.service_account": target_email,
    }


def normalize_gcp_audit(record: Mapping[str, Any]) -> dict[str, Any] | None:
    minted_token = normalize_gcp_generated_access_token(record)
    if minted_token is not None:
        return minted_token
    restored_account = normalize_gcp_undeleted_service_account(record)
    if restored_account is not None:
        return restored_account
    uploaded_key = normalize_gcp_uploaded_service_account_key(record)
    if uploaded_key is not None:
        return uploaded_key
    payload = record.get("protoPayload") if isinstance(record, Mapping) else None
    if (isinstance(payload, Mapping) and isinstance(payload.get("methodName"), str)
            and payload.get("methodName") in {
        "google.iam.admin.v1.UploadServiceAccountKey", "google.iam.admin.v1.UndeleteServiceAccount",
    }):
        return None
    policy_binding = normalize_gcp_token_creator_binding_observation(record)
    if policy_binding is not None:
        return policy_binding
    if not isinstance(payload, Mapping) or payload.get("@type") != "type.googleapis.com/google.cloud.audit.AuditLog":
        return None
    if (payload.get("serviceName") != "iam.googleapis.com"
            or payload.get("methodName") != "google.iam.admin.v1.CreateServiceAccountKey"):
        return None
    log_name = record.get("logName")
    log_match = re.fullmatch(r"projects/([^/]+)/logs/cloudaudit\.googleapis\.com%2Factivity", log_name) if isinstance(log_name, str) else None
    if log_match is None or _PROJECT.fullmatch(log_match.group(1)) is None:
        return None
    project = log_match.group(1)
    resource = record.get("resource")
    labels = None
    if resource is not None:
        if not isinstance(resource, Mapping) or resource.get("type") != "service_account":
            return None
        labels = resource.get("labels")
        if not isinstance(labels, Mapping) or labels.get("project_id") not in (None, project):
            return None
    label_email = labels.get("email_id") if isinstance(labels, Mapping) else None
    label_unique_id = labels.get("unique_id") if isinstance(labels, Mapping) else None
    if isinstance(labels, Mapping):
        if ("email_id" in labels and (not isinstance(label_email, str)
                                      or _ACCOUNT_EMAIL.fullmatch(label_email) is None
                                      or not label_email.endswith(f"@{project}.iam.gserviceaccount.com"))):
            return None
        if ("unique_id" in labels and (not isinstance(label_unique_id, str)
                                        or re.fullmatch(r"[0-9]{21}", label_unique_id) is None)):
            return None

    def account_email(value: Any) -> str | None:
        match = re.fullmatch(r"projects/([^/]+)/serviceAccounts/([^/]+)", value) if isinstance(value, str) else None
        if match is None or match.group(1) not in ("-", project):
            return None
        identifier = match.group(2)
        if _ACCOUNT_EMAIL.fullmatch(identifier) and identifier.endswith(f"@{project}.iam.gserviceaccount.com"):
            return identifier
        if (re.fullmatch(r"[0-9]{21}", identifier) and isinstance(labels, Mapping)
                and labels.get("project_id") == project and label_email is not None
                and identifier == label_unique_id):
            return label_email
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
    target_email = account_email(target)
    if target_email is None or (label_email is not None and label_email != target_email):
        return None
    key_name = response.get("name")
    key_match = re.fullmatch(r"(projects/[^/]+/serviceAccounts/[^/]+)/keys/([A-Za-z0-9_-]+)", key_name) if isinstance(key_name, str) else None
    if key_name is not None and (key_match is None or account_email(key_match.group(1)) != target_email):
        return None
    if "resourceName" in payload and account_email(payload["resourceName"]) != target_email:
        return None
    key_returned = key_match is not None
    explicit_success = type(code) is int and code == 0
    if (code is not None and not explicit_success) or not (explicit_success or key_returned):
        return None
    actor = auth.get("principalEmail")
    if not isinstance(actor, str) or _PRINCIPAL_EMAIL.fullmatch(actor) is None:
        return None
    return {
        "cloud.provider": "gcp",
        "event.name": payload.get("methodName"),
        "event.source": payload.get("serviceName"),
        "event.outcome": "success",
        "event.id": record.get("insertId"),
        "event.time": record.get("timestamp"),
        "account.id": project,
        "actor.id": actor.lower(),
        "target.id": target,
        "credential.key_name": key_name if key_returned else None,
        "credential.effect_confirmed": True,
    }
