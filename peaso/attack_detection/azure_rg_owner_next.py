"""Correlate an Azure resource-group Owner self-assignment from Activity Log.

The Started request supplies the principal and role; a matching Succeeded,
Created operation proves an assignment was written. This does not establish
that effective access increased or that the action was malicious.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any


_GUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_RESOURCE = re.compile(
    rf"/subscriptions/(?P<sub>{_GUID})/resourceGroups/(?P<group>[A-Za-z0-9_.()-]{{1,90}})"
    rf"/providers/Microsoft\.Authorization/roleAssignments/(?P<assignment>{_GUID})\Z", re.I)
_ROLE = re.compile(rf"/subscriptions/{_GUID}/providers/Microsoft\.Authorization/roleDefinitions/(?P<role>{_GUID})\Z", re.I)
_ACTOR_CLAIM = "http://schemas.microsoft.com/identity/claims/objectidentifier"
OWNER_ROLE = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
_CREATED = {"created", "created (http status code: 201)", "201"}


def _value(value):
    return value.get("value") if isinstance(value, Mapping) else value


def _timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def _actor(row):
    claims = row.get("claims")
    if not isinstance(claims, Mapping):
        return None
    oid = claims.get(_ACTOR_CLAIM) or claims.get("oid")
    return oid.lower() if isinstance(oid, str) and re.fullmatch(_GUID, oid, re.I) else None


def _candidate(row: Mapping[str, Any], subscription: str):
    if not isinstance(row, Mapping):
        return None
    if str(_value(row.get("operationName")) or "").lower() != "microsoft.authorization/roleassignments/write":
        return None
    if str(_value(row.get("category")) or "").lower() != "administrative":
        return None
    status = str(_value(row.get("status")) or "").lower()
    if status not in {"started", "succeeded"}:
        return None
    if status == "succeeded" and str(_value(row.get("subStatus")) or "").lower() not in _CREATED:
        return None
    resource = row.get("resourceId")
    match = _RESOURCE.fullmatch(resource) if isinstance(resource, str) else None
    if not match or match.group("sub").lower() != subscription.lower():
        return None
    if not isinstance(row.get("subscriptionId"), str) or row["subscriptionId"].lower() != subscription.lower():
        return None
    operation = row.get("operationId")
    when = _timestamp(row.get("eventTimestamp"))
    actor = _actor(row)
    event_id = row.get("eventDataId")
    if (not isinstance(operation, str) or not re.fullmatch(_GUID, operation, re.I)
            or when is None or actor is None
            or not isinstance(event_id, str) or not 0 < len(event_id) <= 256
            or not isinstance(row.get("caller"), str) or not row["caller"]):
        return None
    return status, match, operation.lower(), when, actor


def _grant(row, match):
    properties = row.get("properties")
    if not isinstance(properties, Mapping):
        return None
    raw = next((value for key, value in properties.items() if isinstance(key, str) and key.lower() == "requestbody"), None)
    if not isinstance(raw, str) or not raw or len(raw) > 20_000:
        return None
    try:
        body = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(body, Mapping):
        return None
    returned_id = body.get("id")
    if returned_id is not None and (not isinstance(returned_id, str) or returned_id.lower() != row["resourceId"].lower()):
        return None
    details = body.get("properties")
    if not isinstance(details, Mapping):
        return None
    principal = details.get("principalId")
    role_ref = details.get("roleDefinitionId")
    if not isinstance(principal, str) or not re.fullmatch(_GUID, principal, re.I) or not isinstance(role_ref, str):
        return None
    role = _ROLE.fullmatch(role_ref)
    if not role or role_ref.lower().split("/providers/", 1)[0] != f"/subscriptions/{match.group('sub').lower()}":
        return None
    role_id = role.group("role").lower()
    return (principal.lower(), role_id) if role_id == OWNER_ROLE else None


def correlate_azure_rg_owner_self_grants(records: Iterable[Mapping[str, Any]], *, subscription: str) -> list[dict[str, Any]]:
    """Return completed Owner self-grants at exact RG scope, with no intent claim."""
    if not re.fullmatch(_GUID, subscription, re.I):
        return []
    starts = {}
    successes = {}
    for index, row in enumerate(records):
        if index >= 2000:
            break
        item = _candidate(row, subscription)
        if item is None:
            continue
        status, match, operation, when, actor = item
        key = (operation, row["resourceId"].lower())
        (starts if status == "started" else successes).setdefault(key, []).append((row, match, when, actor))
    result = []
    seen = set()
    for key, begun in starts.items():
        if len(begun) != 1 or len(successes.get(key, [])) != 1:
            continue
        for first, match, start_time, actor in begun:
            grant = _grant(first, match)
            if grant is None or grant[0] != actor:
                continue
            principal, role = grant
            for second, _, end_time, end_actor in successes.get(key, []):
                if (end_actor != actor or second.get("caller") != first.get("caller")
                        or not timedelta(0) <= end_time - start_time <= timedelta(minutes=10)):
                    continue
                success_id = second.get("eventDataId")
                if not isinstance(success_id, str) or not success_id or success_id in seen:
                    continue
                seen.add(success_id)
                scope = f"/subscriptions/{match.group('sub')}/resourceGroups/{match.group('group')}"
                result.append({
                    "cloud.provider": "azure", "event.source": "azure.activity",
                    "event.name": "rg_owner_self_assignment", "event.outcome": "success",
                    "event.id": success_id, "event.time": second.get("eventTimestamp"),
                    "account.id": match.group("sub").lower(), "actor.id": actor,
                    "target.id": principal, "request.self_grant": True,
                    "request.role_definition_id": role, "scope.type": "resource_group",
                    "scope.id": scope,
                    "correlation_evidence": {
                        "started_event_id": first.get("eventDataId"),
                        "succeeded_event_id": success_id,
                        "operation_id": key[0],
                        "assignment_id": match.group("assignment").lower(),
                    },
                })
                break
    return result
