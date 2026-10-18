"""Azure Key Vault diagnostic setting deletion: real shape and edge cases."""
from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection.azure_keyvault_diagnostic_next import normalize_keyvault_diagnostic_delete
from peaso.attack_detection.rules import Rule, detect_azure_events
from peaso.server.azure_attack_logs import analyze_azure_source

SUB = "11111111-1111-1111-1111-111111111111"
RESOURCE = f"/subscriptions/{SUB}/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/vault-prod/providers/Microsoft.Insights/diagnosticSettings/audit-export"


def row():
    return {
        "subscriptionId": SUB, "resourceId": RESOURCE,
        "category": {"value": "Administrative"},
        "operationName": {"value": "Microsoft.Insights/diagnosticSettings/delete"},
        "status": {"value": "Succeeded"}, "subStatus": {"value": "OK"},
        "authorization": {"action": "Microsoft.Insights/diagnosticSettings/delete", "scope": RESOURCE},
        "eventDataId": "event-1", "eventTimestamp": "2026-10-18T10:00:00Z",
        "caller": "redacted@example.invalid",
    }


def test_exact_successful_vault_setting_delete_and_sigma():
    event = normalize_keyvault_diagnostic_delete(row(), subscription=SUB)
    assert event is not None
    assert event["target.id"] == RESOURCE
    assert event["request.keyvault_diagnostic_setting_deleted"] is True
    assert event["scope.type"] == "key_vault"
    rules = [Rule(
        id="edec54a1-d91c-4ca2-bb2d-870046fca38b",
        title="Key Vault diagnostic setting delete operation succeeded",
        level="high", description="A successful delete operation was observed.",
        technique_id="azure-keyvault-diagnostic-setting-delete", product="azure",
        selection={
            "event.source": "azure.activity", "event.name": "keyvault_diagnostic_setting_delete",
            "event.outcome": "success", "scope.type": "key_vault",
            "request.keyvault_diagnostic_setting_deleted": True,
        },
    )]
    assert [item.rule_id for item in detect_azure_events([event], rules)] == ["edec54a1-d91c-4ca2-bb2d-870046fca38b"]


def test_activity_log_reader_routes_keyvault_delete_to_rules(monkeypatch):
    class Transport:
        def request(self, url, **kwargs):
            return {"value": [row(), {**row(), "eventDataId": "started",
                                      "status": {"value": "Started"}}]}

        def close(self):
            pass

    rule = Rule(
        id="vault-setting-delete", title="Vault diagnostic setting delete", level="medium",
        description="Observed successful delete; review context.",
        technique_id="azure-keyvault-diagnostic-setting-delete", product="azure",
        selection={"event.source": "azure.activity",
                   "event.name": "keyvault_diagnostic_setting_delete",
                   "request.keyvault_diagnostic_setting_deleted": True},
    )
    monkeypatch.setattr("peaso.server.azure_attack_logs.AzureTransport", lambda auth: Transport())
    monkeypatch.setattr("peaso.attack_detection.detect_azure_events",
                        lambda candidates: detect_azure_events(candidates, [rule]))
    result = analyze_azure_source({}, [SUB], {}, {"kind": "azure_activity_log", "subscription_id": SUB})
    assert result["coverage"]["keyvault_diagnostic_delete_candidates"] == 1
    assert [item["rule_id"] for item in result["detections"]] == ["vault-setting-delete"]


def test_live_shape_200_and_documented_204():
    event = row()
    event["category"]["localizedValue"] = "Administrative"
    event["operationName"]["localizedValue"] = "Delete resource diagnostic setting"
    event["status"]["localizedValue"] = "Succeeded"
    event["subStatus"]["localizedValue"] = "OK (HTTP Status Code: 200)"
    assert normalize_keyvault_diagnostic_delete(event, subscription=SUB)
    event["subStatus"] = {"value": "No Content", "localizedValue": "No Content (HTTP Status Code: 204)"}
    assert normalize_keyvault_diagnostic_delete(event, subscription=SUB)


@pytest.mark.parametrize("change", [
    "wrong_subscription", "cross_scope", "subscription_setting", "wrong_resource_type",
    "wrong_operation", "wrong_category", "started", "failed", "not_found",
    "no_substatus", "wrong_auth", "wrong_auth_scope", "missing_caller", "missing_event_id", "missing_time",
    "bad_subscription", "extra_path", "wrong_method_name",
])
def test_ambiguous_or_unrelated_operation_is_ignored(change):
    event = deepcopy(row())
    subscription = SUB
    if change == "wrong_subscription": event["subscriptionId"] = "22222222-2222-2222-2222-222222222222"
    if change == "cross_scope": subscription = "22222222-2222-2222-2222-222222222222"
    if change == "subscription_setting": event["resourceId"] = f"/subscriptions/{SUB}/providers/Microsoft.Insights/diagnosticSettings/audit-export"
    if change == "wrong_resource_type": event["resourceId"] = RESOURCE.replace("Microsoft.KeyVault/vaults", "Microsoft.Storage/storageAccounts")
    if change == "wrong_operation": event["operationName"]["value"] = "Microsoft.Insights/diagnosticSettings/write"
    if change == "wrong_category": event["category"]["value"] = "Policy"
    if change == "started": event["status"]["value"] = "Started"
    if change == "failed": event["status"]["value"] = "Failed"
    if change == "not_found": event["subStatus"]["value"] = "Not Found"
    if change == "no_substatus": event.pop("subStatus")
    if change == "wrong_auth": event["authorization"]["action"] = "Microsoft.Insights/diagnosticSettings/write"
    if change == "wrong_auth_scope": event["authorization"]["scope"] = RESOURCE.replace("vault-prod", "other-vault")
    if change == "missing_caller": event.pop("caller")
    if change == "missing_event_id": event.pop("eventDataId")
    if change == "missing_time": event.pop("eventTimestamp")
    if change == "bad_subscription": subscription = "bad"
    if change == "extra_path": event["resourceId"] += "/nested"
    if change == "wrong_method_name": event["operationName"] = {"value": "Microsoft.KeyVault/vaults/delete"}
    assert normalize_keyvault_diagnostic_delete(event, subscription=subscription) is None
