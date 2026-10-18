"""Correlate Azure ARM RBAC activity without claiming an attack or new effective access.

Azure Activity Log puts the role assignment request on a Started row and the
outcome on a separate Succeeded row. This is a bounded Python correlation,
not a Sigma rule or a claim that a successful request was malicious.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping


OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
USER_ACCESS_ADMINISTRATOR = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
PRIVILEGED_ROLES = {OWNER: "Owner", USER_ACCESS_ADMINISTRATOR: "User Access Administrator"}
MAX_PAIR_AGE = timedelta(minutes=10)
_GUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_ASSIGNMENT = re.compile(
    rf"(?P<scope>/subscriptions/(?P<subscription>{_GUID}))"
    rf"/providers/Microsoft\.Authorization/roleAssignments/(?P<assignment>{_GUID})\Z", re.IGNORECASE)
_ROLE = re.compile(rf"(?:/[^?#]+)?/providers/Microsoft\.Authorization/roleDefinitions/(?P<role>{_GUID})\Z", re.IGNORECASE)
_ACTION = "microsoft.authorization/roleassignments/write"
_OID_CLAIM = "http://schemas.microsoft.com/identity/claims/objectidentifier"
_CREATED = {"created", "created (http status code: 201)", "201"}


def _value(value: Any) -> str | None:
    if isinstance(value, Mapping):
        value = value.get("value")
    return value if isinstance(value, str) else None


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def _actor_oid(record: Mapping[str, Any]) -> str | None:
    claims = record.get("claims")
    if not isinstance(claims, Mapping):
        return None
    oid = claims.get(_OID_CLAIM) or claims.get("oid")
    return oid.lower() if isinstance(oid, str) and re.fullmatch(_GUID, oid, re.IGNORECASE) else None


def _field(value: Mapping[str, Any], name: str) -> Any:
    return next((item for key, item in value.items() if isinstance(key, str) and key.lower() == name.lower()), None)


def _request(record: Mapping[str, Any], assignment: str) -> tuple[str, str] | None:
    properties = record.get("properties")
    if not isinstance(properties, Mapping):
        return None
    raw = _field(properties, "requestbody")
    if not isinstance(raw, str) or not raw or len(raw) > 20_000:
        return None
    try:
        body = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(body, Mapping):
        return None
    identifier = _field(body, "id")
    if identifier is not None and (not isinstance(identifier, str) or identifier.rsplit("/", 1)[-1].lower() != assignment):
        return None
    details = _field(body, "properties")
    if not isinstance(details, Mapping):
        return None
    principal = _field(details, "principalId")
    role_ref = _field(details, "roleDefinitionId")
    if not isinstance(principal, str) or not re.fullmatch(_GUID, principal, re.IGNORECASE) or not isinstance(role_ref, str):
        return None
    role_match = _ROLE.fullmatch(role_ref)
    if not role_match:
        return None
    role = role_match.group("role").lower()
    return principal.lower(), role


def _candidate(record: Any, subscription: str | None):
    if not isinstance(record, Mapping):
        return None
    if (_value(record.get("operationName")) or "").lower() != _ACTION:
        return None
    if (_value(record.get("category")) or "").lower() != "administrative":
        return None
    status = (_value(record.get("status")) or "").lower()
    if status not in {"started", "succeeded"}:
        return None
    if status == "succeeded" and (_value(record.get("subStatus")) or "").lower() not in _CREATED:
        return None
    resource = record.get("resourceId")
    match = _ASSIGNMENT.fullmatch(resource) if isinstance(resource, str) else None
    if not match:
        return None
    declared = record.get("subscriptionId")
    if not isinstance(declared, str) or (subscription and declared.lower() != subscription.lower()):
        return None
    if match.group("subscription") and declared.lower() != match.group("subscription").lower():
        return None
    operation = record.get("operationId")
    when = _timestamp(record.get("eventTimestamp"))
    actor = _actor_oid(record)
    event_id = record.get("eventDataId")
    if (not isinstance(operation, str) or not re.fullmatch(_GUID, operation, re.IGNORECASE)
            or when is None or actor is None or not isinstance(event_id, str)
            or not 0 < len(event_id) <= 256 or not isinstance(record.get("caller"), str)
            or not record["caller"]):
        return None
    return status, (operation.lower(), resource.lower()), match, when, actor


def _unique_rows(rows):
    """Collapse identical pagination repeats; reject conflicting rows for one event ID."""
    unique = {}
    for row in rows:
        event_id = row[0]["eventDataId"]
        prior = unique.get(event_id)
        if prior is not None and prior[0] != row[0]:
            return None
        unique[event_id] = row
    return tuple(unique.values())


def correlate_azure_self_grants(records: Iterable[Mapping[str, Any]], *, subscription: str | None = None) -> list[dict[str, Any]]:
    """Produce narrow canonical events for separately reviewed detection rules."""
    starts: dict[tuple[str, str], list[tuple[Mapping[str, Any], Any, datetime, str]]] = {}
    successes: dict[tuple[str, str], list[tuple[Mapping[str, Any], Any, datetime, str]]] = {}
    for index, record in enumerate(records):
        if index >= 2_000:
            break
        candidate = _candidate(record, subscription)
        if candidate is None:
            continue
        status, key, match, when, actor = candidate
        (starts if status == "started" else successes).setdefault(key, []).append((record, match, when, actor))
    candidates = []
    seen = set()
    for key, begun in starts.items():
        begun = _unique_rows(begun)
        completed = _unique_rows(successes.get(key, []))
        if begun is None or completed is None or len(begun) != 1 or len(completed) != 1:
            continue
        for start, match, start_time, actor in begun:
            details = _request(start, match.group("assignment").lower())
            if details is None:
                continue
            principal, role = details
            if principal != actor:
                continue
            for success, _, success_time, success_actor in completed:
                if (success_actor != actor or success.get("caller") != start.get("caller")
                        or success.get("eventDataId") == start.get("eventDataId")
                        or not timedelta(0) <= success_time - start_time <= MAX_PAIR_AGE):
                    continue
                success_id = success.get("eventDataId")
                if not isinstance(success_id, str) or not success_id or (key, success_id) in seen:
                    continue
                seen.add((key, success_id))
                scope = match.group("scope")
                candidates.append({
                    "cloud.provider": "azure",
                    "event.source": "azure.activity",
                    "event.name": "role_self_assignment",
                    "event.outcome": "success",
                    "event.id": success_id,
                    "event.time": success.get("eventTimestamp"),
                    "account.id": match.group("subscription"),
                    "actor.id": actor,
                    "target.id": principal,
                    "request.self_grant": True,
                    "request.role_definition_id": role,
                    "request.role_name": PRIVILEGED_ROLES.get(role),
                    "scope.id": scope,
                    "scope.type": "subscription",
                    "correlation_evidence": {
                        "started_event_id": start.get("eventDataId"),
                        "succeeded_event_id": success_id,
                        "operation_id": key[0],
                        "assignment_id": match.group("assignment").lower(),
                        "scope": scope,
                    },
                })
                break
    return candidates
