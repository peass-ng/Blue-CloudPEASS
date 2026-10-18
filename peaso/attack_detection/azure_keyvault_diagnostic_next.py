"""Normalize a successful Azure Key Vault diagnostic setting deletion.

Does not prove AuditEvent was enabled before deletion, that no other setting
remains, or that subsequent vault operations occurred without telemetry.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from peaso.attack_detection.azure_diagnostic_next import _field, _time

_GUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_SUBSCRIPTION = re.compile(_GUID + r"\Z", re.I)
_SETTING = re.compile(
    rf"/subscriptions/(?P<subscription>{_GUID})/resourceGroups/(?P<group>[A-Za-z0-9_.()-]{{1,90}})"
    r"/providers/Microsoft\.KeyVault/vaults/(?P<vault>[A-Za-z0-9-]{3,24})"
    r"/providers/Microsoft\.Insights/diagnosticSettings/(?P<name>[A-Za-z0-9][A-Za-z0-9._()-]{0,259})\Z",
    re.I,
)
_ACTION = "microsoft.insights/diagnosticsettings/delete"
_OK = {"ok", "ok (http status code: 200)", "200", "no content", "no content (http status code: 204)", "204"}


def normalize_keyvault_diagnostic_delete(record: Mapping[str, Any], *, subscription: str) -> dict[str, Any] | None:
    if not isinstance(record, Mapping) or not isinstance(subscription, str) or not _SUBSCRIPTION.fullmatch(subscription):
        return None
    resource = record.get("resourceId")
    match = _SETTING.fullmatch(resource) if isinstance(resource, str) else None
    declared = record.get("subscriptionId")
    if (match is None or not isinstance(declared, str)
            or declared.lower() != subscription.lower()
            or match.group("subscription").lower() != subscription.lower()
            or (_field(record.get("category")) or "").lower() != "administrative"
            or (_field(record.get("operationName")) or "").lower() != _ACTION
            or (_field(record.get("status")) or "").lower() != "succeeded"
            or (_field(record.get("subStatus")) or "").lower() not in _OK):
        return None
    auth = record.get("authorization")
    if (not isinstance(auth, Mapping)
            or not isinstance(auth.get("action"), str) or auth["action"].lower() != _ACTION
            or not isinstance(auth.get("scope"), str) or auth["scope"].lower() != resource.lower()):
        return None
    event_id = record.get("eventDataId")
    when = _time(record.get("eventTimestamp"))
    caller = record.get("caller")
    if (not isinstance(event_id, str) or not 0 < len(event_id) <= 256
            or when is None or not isinstance(caller, str) or not 0 < len(caller) <= 256):
        return None
    return {
        "cloud.provider": "azure", "event.source": "azure.activity",
        "event.name": "keyvault_diagnostic_setting_delete", "event.outcome": "success",
        "event.id": event_id, "event.time": when,
        "account.id": subscription.lower(), "actor.id": caller,
        "target.id": resource, "scope.type": "key_vault",
        "request.keyvault_diagnostic_setting_deleted": True,
    }
