"""Narrow Microsoft Entra self-grant evidence from directoryAudit records.

Technique: HackTricks Cloud, Azure Entra ID privilege escalation, Privileged
Role Administrator (az-entraid-privesc/README.md#roles). The output describes
an observed successful assignment, not malicious intent or later role use.
Graph audit schema: https://learn.microsoft.com/graph/api/resources/directoryaudit
Global Administrator role template: https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference
Activity names distinguish unscoped, scoped, restricted-AU and PIM grants:
https://learn.microsoft.com/entra/identity/monitoring-health/reference-audit-activities
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any


GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")


def _uuid(value: Any) -> str | None:
    return value.lower() if isinstance(value, str) and _UUID.fullmatch(value) else None


def _new_uuid(properties: Any, name: str) -> str | None:
    if not isinstance(properties, list) or len(properties) > 32:
        return None
    matches = []
    for item in properties:
        if not isinstance(item, Mapping) or item.get("displayName") != name:
            continue
        value = item.get("newValue")
        if not isinstance(value, str) or len(value) > 128:
            return None
        try:
            decoded = json.loads(value)
        except ValueError:
            return None
        matches.append(_uuid(decoded))
    return matches[0] if len(matches) == 1 else None


def _time(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        when = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if when.tzinfo is not None else None


def normalize_entra_global_admin_self_grant(row: Mapping[str, Any], *, tenant: str) -> dict[str, Any] | None:
    """Require a successful direct tenant-wide self-assignment to Global Admin."""
    if (not isinstance(row, Mapping) or _uuid(tenant) is None
            or row.get("category") != "RoleManagement"
            or row.get("loggedByService") != "Core Directory"
            or row.get("activityDisplayName") != "Add member to role"
            or row.get("operationType") != "Assign"
            or row.get("result") != "success"):
        return None
    event_id = row.get("id")
    event_time = _time(row.get("activityDateTime"))
    if not isinstance(event_id, str) or not 0 < len(event_id) <= 256 or event_time is None:
        return None
    initiated = row.get("initiatedBy")
    if not isinstance(initiated, Mapping) or initiated.get("app") is not None:
        return None
    user = initiated.get("user")
    actor = _uuid(user.get("id")) if isinstance(user, Mapping) else None
    if actor is None:
        return None
    resources = row.get("targetResources")
    if not isinstance(resources, list) or len(resources) != 2 or not all(isinstance(item, Mapping) for item in resources):
        return None
    targets = [item for item in resources if item.get("type") == "User"]
    roles = [item for item in resources if item.get("type") == "Role"]
    if len(targets) != 1 or len(roles) != 1:
        return None
    target, role = targets[0], roles[0]
    # Graph v1.0 need not include administrativeUnits. The exact unscoped
    # activity name is the available scope evidence; explicit AU data conflicts.
    if _uuid(target.get("id")) != actor or target.get("administrativeUnits", []) != []:
        return None
    role_id = _uuid(role.get("id"))
    if role_id is None or _new_uuid(target.get("modifiedProperties"), "Role.ObjectID") != role_id:
        return None
    if _new_uuid(target.get("modifiedProperties"), "Role.TemplateId") != GLOBAL_ADMIN_TEMPLATE:
        return None
    return {
        "cloud.provider": "azure",
        "event.source": "entra.directoryAudit",
        "event.name": "global_admin_self_assignment",
        "event.outcome": "success",
        "event.id": event_id,
        "event.time": event_time,
        "account.id": tenant.lower(),
        "actor.id": actor,
        "target.id": actor,
        "scope.type": "tenant",
        "request.self_grant": True,
        "request.role_template_id": GLOBAL_ADMIN_TEMPLATE,
        "request.role_object_id": role_id,
    }
