"""Project exact Microsoft Entra directory audit credential-add evidence."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any


_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")


def _uuid(value: Any) -> str | None:
    return value.lower() if isinstance(value, str) and _UUID.fullmatch(value) else None


def normalize_entra_credential_add(
    row: Mapping[str, Any], *, tenant: str, event_id: str, event_time: str,
) -> dict[str, Any] | None:
    """Observe a successful credential-add audit record; infer no privilege or use."""
    if (not isinstance(row, Mapping) or _uuid(tenant) is None
            or row.get("category") != "ApplicationManagement"
            or row.get("loggedByService") != "Core Directory"
            or row.get("activityDisplayName") != "Add service principal credentials"
            or row.get("result") != "success"
            or not isinstance(event_id, str) or not event_id
            or not isinstance(event_time, str) or not event_time):
        return None
    initiated = row.get("initiatedBy")
    if not isinstance(initiated, Mapping):
        return None
    user = initiated.get("user")
    app = initiated.get("app")
    actors = [identity for identity in (
        _uuid(user.get("id")) if isinstance(user, Mapping) else None,
        _uuid(app.get("servicePrincipalId")) if isinstance(app, Mapping) else None,
    ) if identity is not None]
    if len(actors) != 1:
        return None
    resources = row.get("targetResources")
    if not isinstance(resources, list):
        return None
    targets = [_uuid(item.get("id")) for item in resources
               if isinstance(item, Mapping) and item.get("type") == "ServicePrincipal"]
    if len(targets) != 1 or targets[0] is None:
        return None
    return {
        "cloud.provider": "azure",
        "event.source": "entra.directoryAudit",
        "event.name": "Add service principal credentials",
        "event.outcome": "success",
        "event.id": event_id,
        "event.time": event_time,
        "account.id": tenant.lower(),
        "actor.id": actors[0],
        "target.id": targets[0],
        "credential.add_observed": True,
    }
