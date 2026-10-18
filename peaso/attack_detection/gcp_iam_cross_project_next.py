"""Confirmed cross-project service-account grants in project IAM policies.

An ADD policy delta plus the returned unconditional binding proves a new
direct grant. A different service-account home project is not, by itself,
evidence of an external organization, attacker control, or misuse.
"""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
_EMAIL = re.compile(r"[^\s@:/]+@[^\s@:/]+\.[^\s@:/]+\Z")
_SA_MEMBER = re.compile(r"serviceAccount:([a-z][a-z0-9-]*@([a-z][a-z0-9-]{4,28}[a-z0-9])\.iam\.gserviceaccount\.com)\Z")
_ROLE = re.compile(r"roles/[A-Za-z][A-Za-z0-9_.]*\Z")
_LOG = re.compile(r"projects/([^/]+)/logs/cloudaudit\.googleapis\.com%2Factivity\Z")
_AUDIT_TYPE = "type.googleapis.com/google.cloud.audit.AuditLog"
_REQUEST_TYPE = "type.googleapis.com/google.iam.v1.SetIamPolicyRequest"
_POLICY_TYPE = "type.googleapis.com/google.iam.v1.Policy"


def normalize_gcp_cross_project_sa_grants(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return exact unconditional ADD grants to service accounts in other projects.

    A reviewed rule selects the role. The audit record does not establish
    whether the grantee had equivalent inherited access before this grant.
    """
    if not isinstance(record, Mapping):
        return []
    log_name = record.get("logName")
    match = _LOG.fullmatch(log_name) if isinstance(log_name, str) else None
    if match is None or _PROJECT.fullmatch(match.group(1)) is None:
        return []
    project = match.group(1)
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
    if status is not None and (
        not isinstance(status, Mapping)
        or (status and (type(status.get("code")) is not int or status["code"] != 0))
    ):
        return []
    operation = record.get("operation")
    if operation is not None and (not isinstance(operation, Mapping) or operation.get("last") is not True):
        return []
    auth, request, response = (payload.get(field) for field in ("authenticationInfo", "request", "response"))
    if not all(isinstance(item, Mapping) for item in (auth, request, response)):
        return []
    actor = auth.get("principalEmail")
    if not isinstance(actor, str) or _EMAIL.fullmatch(actor) is None:
        return []
    if request.get("@type") != _REQUEST_TYPE or request.get("resource") not in (project, f"projects/{project}"):
        return []
    if response.get("@type") != _POLICY_TYPE or not isinstance(response.get("bindings"), list):
        return []
    service_data = payload.get("serviceData")
    policy_delta = service_data.get("policyDelta") if isinstance(service_data, Mapping) else None
    deltas = policy_delta.get("bindingDeltas") if isinstance(policy_delta, Mapping) else None
    if not isinstance(deltas, list):
        return []
    event_id, event_time = record.get("insertId"), record.get("timestamp")
    if not isinstance(event_id, str) or not event_id or not isinstance(event_time, str) or not event_time:
        return []

    returned: set[tuple[str, str]] = set()
    for binding in response["bindings"]:
        if not isinstance(binding, Mapping) or "condition" in binding:
            continue
        role, members = binding.get("role"), binding.get("members")
        if not isinstance(role, str) or _ROLE.fullmatch(role) is None or not isinstance(members, list):
            continue
        for member in members:
            if isinstance(member, str) and _SA_MEMBER.fullmatch(member):
                returned.add((role, member))
    added: set[tuple[str, str]] = set()
    for delta in deltas:
        if not isinstance(delta, Mapping) or delta.get("action") != "ADD" or "condition" in delta:
            continue
        role, member = delta.get("role"), delta.get("member")
        if isinstance(role, str) and _ROLE.fullmatch(role) and isinstance(member, str) and _SA_MEMBER.fullmatch(member):
            added.add((role, member))

    rows: list[dict[str, Any]] = []
    for role, member in sorted(returned & added):
        member_match = _SA_MEMBER.fullmatch(member)
        if member_match is None or member_match.group(2) == project:
            continue
        rows.append({
            "cloud.provider": "gcp",
            "event.name": "cross_project_service_account_binding_added",
            "event.source": "cloudresourcemanager.googleapis.com",
            "event.outcome": "success",
            "event.id": event_id,
            "event.time": event_time,
            "account.id": project,
            "actor.id": actor.lower(),
            "target.id": f"projects/{project}",
            "target.principal": member,
            "target.principal_project": member_match.group(2),
            "request.role": role,
            "request.binding_added": True,
            "request.cross_project_service_account": True,
        })
    return rows
