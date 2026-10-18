"""Synthetic Azure Activity Log evidence for VM DCR association deletion."""
from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection.azure_dcr_association_next import normalize_azure_vm_dcr_association_delete


SUB = "12345678-1234-1234-1234-123456789abc"
OTHER = "87654321-4321-4321-4321-cba987654321"
OID = "11111111-2222-3333-4444-555555555555"
VM = f"/subscriptions/{SUB}/resourceGroups/ops/providers/Microsoft.Compute/virtualMachines/vm-1"
ASSOCIATION = VM + "/providers/Microsoft.Insights/dataCollectionRuleAssociations/security-logs"


def event():
    return {
        "subscriptionId": SUB, "resourceId": ASSOCIATION,
        "operationName": {"value": "Microsoft.Insights/dataCollectionRuleAssociations/delete"},
        "category": {"value": "Administrative"}, "status": {"value": "Succeeded"},
        "subStatus": {"value": "OK"}, "eventDataId": "event-1",
        "operationId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "eventTimestamp": "2026-10-18T10:00:00Z",
        "claims": {"http://schemas.microsoft.com/identity/claims/objectidentifier": OID},
        "caller": "private@example.test",
    }


def test_confirmed_200_delete_targets_one_vm_association():
    result = normalize_azure_vm_dcr_association_delete(event(), subscription=SUB)
    assert result is not None
    assert result["request.vm_dcr_association_deleted"] is True
    assert result["target.id"] == ASSOCIATION.lower()
    assert result["scope.id"] == VM.lower()
    assert result["scope.type"] == "virtual_machine"
    assert result["actor.id"] == OID
    assert "private@example.test" not in str(result)


@pytest.mark.parametrize("change", [
    "other_subscription", "foreign_resource", "no_content", "started", "failed",
    "unknown_http", "wrong_operation", "wrong_resource", "missing_actor", "bad_actor",
    "missing_event_id", "missing_operation_id", "bad_timestamp", "wrong_category",
    "nested_resource", "lookalike_suffix", "selected_scope_mismatch",
])
def test_ambiguous_or_nonexistent_delete_does_not_match(change):
    candidate = deepcopy(event())
    selected = SUB
    if change == "other_subscription": candidate["subscriptionId"] = OTHER
    if change == "foreign_resource": candidate["resourceId"] = ASSOCIATION.replace(SUB, OTHER)
    if change == "no_content": candidate["subStatus"]["value"] = "No Content"
    if change == "started": candidate["status"]["value"] = "Started"
    if change == "failed": candidate["status"]["value"] = "Failed"
    if change == "unknown_http": candidate["subStatus"]["value"] = "Accepted"
    if change == "wrong_operation": candidate["operationName"]["value"] = "Microsoft.Insights/dataCollectionRuleAssociations/write"
    if change == "wrong_resource": candidate["resourceId"] = VM + "/providers/Microsoft.Insights/dataCollectionRules/security-logs"
    if change == "missing_actor": candidate.pop("claims")
    if change == "bad_actor": candidate["claims"]["http://schemas.microsoft.com/identity/claims/objectidentifier"] = "unknown"
    if change == "missing_event_id": candidate.pop("eventDataId")
    if change == "missing_operation_id": candidate.pop("operationId")
    if change == "bad_timestamp": candidate["eventTimestamp"] = "unknown"
    if change == "wrong_category": candidate["category"]["value"] = "Policy"
    if change == "nested_resource": candidate["resourceId"] = VM + "/extensions/ext" + ASSOCIATION[len(VM):]
    if change == "lookalike_suffix": candidate["resourceId"] += "/extra"
    if change == "selected_scope_mismatch": selected = OTHER
    assert normalize_azure_vm_dcr_association_delete(candidate, subscription=selected) is None
