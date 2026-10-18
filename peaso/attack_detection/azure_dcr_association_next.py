"""Observe a completed Azure VM data-collection association deletion.

HackTricks Cloud: az-post-exploitation/az-monitor-post-exploitation.md,
"Delete a data collection rule association". This reports one accepted ARM
delete, not malicious intent or proof that all VM telemetry has stopped.
Azure Activity Log schema: https://learn.microsoft.com/azure/azure-monitor/fundamentals/activity-log-schema
Delete API: https://learn.microsoft.com/rest/api/monitor/data-collection-rule-associations/delete
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any


_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_VM_ASSOCIATION = re.compile(
    rf"(?P<vm>/subscriptions/(?P<subscription>{_UUID})/resourceGroups/"
    rf"(?P<group>[A-Za-z0-9_.()-]{{1,90}})/providers/Microsoft\.Compute/virtualMachines/"
    rf"(?P<vm_name>[A-Za-z0-9_.-]{{1,64}}))/providers/Microsoft\.Insights/"
    rf"dataCollectionRuleAssociations/(?P<association>[A-Za-z0-9_.-]{{1,128}})\Z", re.IGNORECASE)
_ACTION = "microsoft.insights/datacollectionruleassociations/delete"
_OID_CLAIM = "http://schemas.microsoft.com/identity/claims/objectidentifier"


def _value(value: Any) -> str | None:
    if isinstance(value, Mapping):
        value = value.get("value")
    return value if isinstance(value, str) else None


def _uuid(value: Any) -> str | None:
    return value.lower() if isinstance(value, str) and re.fullmatch(_UUID, value, re.IGNORECASE) else None


def _time(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if parsed.tzinfo is not None else None


def normalize_azure_vm_dcr_association_delete(record: Mapping[str, Any], *, subscription: str) -> dict[str, Any] | None:
    """Require the exact VM DCRA, Succeeded + HTTP 200, and bound actor."""
    selected = _uuid(subscription)
    if (not isinstance(record, Mapping) or selected is None
            or (_value(record.get("operationName")) or "").lower() != _ACTION
            or (_value(record.get("category")) or "").lower() != "administrative"
            or (_value(record.get("status")) or "").lower() != "succeeded"
            or (_value(record.get("subStatus")) or "").lower() not in {"ok", "ok (http status code: 200)"}):
        return None
    resource = record.get("resourceId")
    match = _VM_ASSOCIATION.fullmatch(resource) if isinstance(resource, str) else None
    if match is None or match.group("subscription").lower() != selected:
        return None
    if _uuid(record.get("subscriptionId")) != selected:
        return None
    claims = record.get("claims")
    if not isinstance(claims, Mapping):
        return None
    actor = _uuid(claims.get(_OID_CLAIM) or claims.get("oid"))
    operation = _uuid(record.get("operationId"))
    event_id = record.get("eventDataId")
    event_time = _time(record.get("eventTimestamp"))
    if actor is None or operation is None or not isinstance(event_id, str) or not event_id or len(event_id) > 256 or event_time is None:
        return None
    return {
        "cloud.provider": "azure", "event.source": "azure.activity",
        "event.name": "vm_dcr_association_delete", "event.outcome": "success",
        "event.id": event_id, "event.time": event_time,
        "account.id": selected, "actor.id": actor,
        "target.id": resource.lower(), "scope.id": match.group("vm").lower(),
        "scope.type": "virtual_machine", "request.vm_dcr_association_deleted": True,
        "correlation.operation_id": operation,
    }
