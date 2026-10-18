"""Confirmed project IAM self-binding additions from GCP Admin Activity.

Google documents SetIamPolicy policyDelta.bindingDeltas as the changes to a
policy. An ADD delta corroborated by the returned Policy proves a new direct
binding. Whether it newly confers effective access or was authorized still
requires separate evidence. A reviewed rule chooses the role of interest.
"""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
_EMAIL = re.compile(r"[^\s@:/]+@[^\s@:/]+\.[^\s@:/]+\Z")
_ROLE = re.compile(r"roles/[A-Za-z][A-Za-z0-9_.]*\Z")
_AUDIT_TYPE = "type.googleapis.com/google.cloud.audit.AuditLog"
_REQUEST_TYPE = "type.googleapis.com/google.iam.v1.SetIamPolicyRequest"
_POLICY_TYPE = "type.googleapis.com/google.iam.v1.Policy"
_LOG = re.compile(r"projects/([^/]+)/logs/cloudaudit\.googleapis\.com%2Factivity\Z")


def normalize_gcp_project_self_iam_bindings(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return unconditional project IAM bindings added for the actor.

    Only an exact, completed project Admin Activity event with both an ADD
    policy delta and a matching returned binding is used. This does not prove
    newly effective access or malicious intent.
    """
    if not isinstance(record, Mapping):
        return []
    log_name = record.get("logName")
    log_match = _LOG.fullmatch(log_name) if isinstance(log_name, str) else None
    if log_match is None:
        return []
    project = log_match.group(1)
    if _PROJECT.fullmatch(project) is None:
        return []
    resource = record.get("resource")
    if not isinstance(resource, Mapping) or resource.get("type") != "project":
        return []
    labels = resource.get("labels")
    if labels is not None and (not isinstance(labels, Mapping) or labels.get("project_id", project) != project):
        return []
    payload = record.get("protoPayload")
    if not isinstance(payload, Mapping) or payload.get("@type") != _AUDIT_TYPE:
        return []
    if payload.get("serviceName") != "cloudresourcemanager.googleapis.com" or payload.get("methodName") != "SetIamPolicy":
        return []
    if payload.get("resourceName") != f"projects/{project}":
        return []
    status = payload.get("status")
    if status is not None and (not isinstance(status, Mapping) or type(status.get("code")) is not int or status["code"] != 0):
        return []
    operation = record.get("operation")
    if operation is not None and (not isinstance(operation, Mapping) or operation.get("last") is not True):
        return []
    auth = payload.get("authenticationInfo")
    request = payload.get("request")
    response = payload.get("response")
    if not all(isinstance(value, Mapping) for value in (auth, request, response)):
        return []
    actor = auth.get("principalEmail")
    if not isinstance(actor, str) or _EMAIL.fullmatch(actor) is None:
        return []
    if request.get("@type") != _REQUEST_TYPE or request.get("resource") not in (project, f"projects/{project}"):
        return []
    if response.get("@type") != _POLICY_TYPE:
        return []
    bindings = response.get("bindings")
    if not isinstance(bindings, list):
        return []
    service_data = payload.get("serviceData")
    policy_delta = service_data.get("policyDelta") if isinstance(service_data, Mapping) else None
    deltas = policy_delta.get("bindingDeltas") if isinstance(policy_delta, Mapping) else None
    if not isinstance(deltas, list):
        return []
    event_id = record.get("insertId")
    event_time = record.get("timestamp")
    if not isinstance(event_id, str) or not event_id or not isinstance(event_time, str) or not event_time:
        return []

    actor = actor.lower()
    member = f"serviceAccount:{actor}" if actor.endswith(".iam.gserviceaccount.com") else f"user:{actor}"
    returned_roles: set[str] = set()
    for binding in bindings:
        if not isinstance(binding, Mapping) or "condition" in binding:
            continue
        role = binding.get("role")
        members = binding.get("members")
        if isinstance(role, str) and _ROLE.fullmatch(role) and isinstance(members, list) and member in members:
            returned_roles.add(role)
    added_roles = {
        delta["role"] for delta in deltas
        if isinstance(delta, Mapping)
        and delta.get("action") == "ADD"
        and delta.get("member") == member
        and "condition" not in delta
        and isinstance(delta.get("role"), str)
        and _ROLE.fullmatch(delta["role"])
    }

    return [
        {
            "cloud.provider": "gcp",
            "event.name": "project_iam_self_binding_added",
            "event.source": "cloudresourcemanager.googleapis.com",
            "event.outcome": "success",
            "event.id": event_id,
            "event.time": event_time,
            "account.id": project,
            "actor.id": actor,
            "target.id": f"projects/{project}",
            "request.actor_is_member": True,
            "request.binding_added": True,
            "request.role": role,
        }
        for role in sorted(returned_roles & added_roles)
    ]
