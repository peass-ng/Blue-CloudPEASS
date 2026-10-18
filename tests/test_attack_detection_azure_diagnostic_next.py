"""Subscription diagnostic export deletion must be an exact ARM success."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection.azure_diagnostic_next import normalize_azure_subscription_diagnostic_delete


SUB = "12345678-1234-1234-1234-123456789abc"
SETTING = f"/subscriptions/{SUB}/providers/Microsoft.Insights/diagnosticSettings/send-activity-to-soc"


def _event() -> dict:
    return {
        "subscriptionId": SUB, "resourceId": SETTING,
        "category": {"value": "Administrative"},
        "operationName": {"value": "Microsoft.Insights/diagnosticSettings/delete"},
        "status": {"value": "Succeeded"},
        "resourceType": {"value": "Microsoft.Insights/diagnosticSettings"},
        "authorization": {"action": "Microsoft.Insights/diagnosticSettings/delete"},
        "eventDataId": "deleted-setting-event", "eventTimestamp": "2026-10-18T12:00:00Z",
        "caller": "security-admin@example.com",
    }


def test_subscription_activity_export_setting_deleted():
    event = normalize_azure_subscription_diagnostic_delete(_event(), subscription=SUB)
    assert event == {
        "cloud.provider": "azure", "event.source": "azure.activity",
        "event.name": "subscription_diagnostic_setting_delete", "event.outcome": "success",
        "event.id": "deleted-setting-event", "event.time": "2026-10-18T12:00:00Z",
        "account.id": SUB, "actor.id": "security-admin@example.com",
        "target.id": SETTING, "scope.type": "subscription",
        "request.subscription_activity_export_setting_deleted": True,
    }


@pytest.mark.parametrize("change", [
    "failed", "started", "wrong_action", "resource_setting", "different_subscription",
    "declared_other_subscription", "non_admin", "wrong_resource_type", "wrong_authorization",
    "missing_id", "naive_time", "missing_caller", "missing_resource", "unexpected_path",
])
def test_other_or_ambiguous_activity_does_not_match(change):
    row = deepcopy(_event())
    if change == "failed": row["status"]["value"] = "Failed"
    if change == "started": row["status"]["value"] = "Started"
    if change == "wrong_action": row["operationName"]["value"] = "Microsoft.Insights/diagnosticSettings/write"
    if change == "resource_setting": row["resourceId"] = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/storage1/providers/Microsoft.Insights/diagnosticSettings/send-activity-to-soc"
    if change == "different_subscription": row["resourceId"] = SETTING.replace(SUB, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    if change == "declared_other_subscription": row["subscriptionId"] = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    if change == "non_admin": row["category"]["value"] = "Security"
    if change == "wrong_resource_type": row["resourceType"]["value"] = "Microsoft.Storage/storageAccounts"
    if change == "wrong_authorization": row["authorization"]["action"] = "Microsoft.Insights/diagnosticSettings/write"
    if change == "missing_id": row.pop("eventDataId")
    if change == "naive_time": row["eventTimestamp"] = "2026-10-18T12:00:00"
    if change == "missing_caller": row.pop("caller")
    if change == "missing_resource": row.pop("resourceId")
    if change == "unexpected_path": row["resourceId"] += "/other"
    assert normalize_azure_subscription_diagnostic_delete(row, subscription=SUB) is None


def test_optional_resource_type_and_authorization_can_be_redacted():
    row = _event()
    row.pop("resourceType")
    row.pop("authorization")
    assert normalize_azure_subscription_diagnostic_delete(row, subscription=SUB) is not None
