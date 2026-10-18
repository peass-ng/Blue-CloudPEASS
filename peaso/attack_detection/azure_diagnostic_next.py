"""Observe successful deletion of a subscription Activity Log export setting.

This is an Azure Activity Log Administrative action. It does not establish that
all Activity Log exports were removed or that the platform Activity Log ended.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any


_GUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_SUBSCRIPTION = re.compile(_GUID + r"\Z", re.IGNORECASE)
_SETTING = re.compile(
    rf"/subscriptions/(?P<subscription>{_GUID})/providers/Microsoft\.Insights/diagnosticSettings/"
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._()-]{0,259})\Z", re.IGNORECASE,
)
_ACTION = "microsoft.insights/diagnosticsettings/delete"


def _field(value: Any) -> str | None:
    if isinstance(value, Mapping):
        value = value.get("value")
    return value if isinstance(value, str) else None


def _time(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 48:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if parsed.tzinfo is not None else None


def normalize_azure_subscription_diagnostic_delete(
    record: Mapping[str, Any], *, subscription: str,
) -> dict[str, Any] | None:
    """Return one exact, successful subscription export setting deletion."""
    if not isinstance(record, Mapping) or not isinstance(subscription, str) or not _SUBSCRIPTION.fullmatch(subscription):
        return None
    declared = record.get("subscriptionId")
    resource = record.get("resourceId")
    match = _SETTING.fullmatch(resource) if isinstance(resource, str) else None
    if (not isinstance(declared, str) or declared.lower() != subscription.lower()
            or match is None or match.group("subscription").lower() != subscription.lower()
            or (_field(record.get("category")) or "").lower() != "administrative"
            or (_field(record.get("operationName")) or "").lower() != _ACTION
            or (_field(record.get("status")) or "").lower() != "succeeded"):
        return None
    resource_type = _field(record.get("resourceType"))
    if resource_type is not None and resource_type.lower() != "microsoft.insights/diagnosticsettings":
        return None
    authorization = record.get("authorization")
    if authorization is not None and (not isinstance(authorization, Mapping)
                                      or not isinstance(authorization.get("action"), str)
                                      or authorization["action"].lower() != _ACTION):
        return None
    event_id = record.get("eventDataId")
    when = _time(record.get("eventTimestamp"))
    caller = record.get("caller")
    if (not isinstance(event_id, str) or not event_id or len(event_id) > 256
            or when is None or not isinstance(caller, str) or not caller or len(caller) > 256):
        return None
    return {
        "cloud.provider": "azure", "event.source": "azure.activity",
        "event.name": "subscription_diagnostic_setting_delete",
        "event.outcome": "success", "event.id": event_id, "event.time": when,
        "account.id": subscription.lower(), "actor.id": caller,
        "target.id": resource, "scope.type": "subscription",
        "request.subscription_activity_export_setting_deleted": True,
    }
