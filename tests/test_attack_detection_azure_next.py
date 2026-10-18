"""Exact Entra Global Administrator self-grant evidence; synthetic Graph rows."""
from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection.azure_next import (
    GLOBAL_ADMIN_TEMPLATE, normalize_entra_global_admin_self_grant,
)


TENANT = "11111111-1111-1111-1111-111111111111"
ACTOR = "22222222-2222-2222-2222-222222222222"
ROLE = "33333333-3333-3333-3333-333333333333"


def row():
    return {
        "id": "audit-event-1", "activityDateTime": "2026-10-18T10:00:00Z",
        "category": "RoleManagement", "loggedByService": "Core Directory",
        "activityDisplayName": "Add member to role", "operationType": "Assign",
        "result": "success", "initiatedBy": {"user": {"id": ACTOR}},
        "targetResources": [
            {"id": ACTOR, "type": "User",
             "modifiedProperties": [
                 {"displayName": "Role.ObjectID", "newValue": f'"{ROLE}"'},
                 {"displayName": "Role.TemplateId", "newValue": f'"{GLOBAL_ADMIN_TEMPLATE}"'},
             ]},
            {"id": ROLE, "type": "Role", "modifiedProperties": []},
        ],
    }


def test_successful_direct_tenant_global_admin_self_grant():
    event = normalize_entra_global_admin_self_grant(row(), tenant=TENANT)
    assert event is not None
    assert event["request.self_grant"] is True
    assert event["request.role_template_id"] == GLOBAL_ADMIN_TEMPLATE
    assert event["actor.id"] == event["target.id"] == ACTOR
    assert event["scope.type"] == "tenant"
    assert event["event.outcome"] == "success"
    assert "userPrincipalName" not in event


@pytest.mark.parametrize("change", [
    "failed", "app_actor", "other_target", "other_role", "wrong_role_object",
    "admin_unit", "scoped_activity", "restricted_au_activity", "role_without_target", "missing_actor",
    "duplicate_role_template", "malformed_template", "wrong_service", "pim",
    "wrong_operation", "missing_time", "missing_event_id", "other_category",
])
def test_ambiguous_or_non_self_grants_are_ignored(change):
    candidate = deepcopy(row())
    user, role = candidate["targetResources"]
    if change == "failed": candidate["result"] = "failure"
    if change == "app_actor": candidate["initiatedBy"]["app"] = {"servicePrincipalId": ACTOR}
    if change == "other_target": user["id"] = "44444444-4444-4444-4444-444444444444"
    if change == "other_role": user["modifiedProperties"][1]["newValue"] = '"55555555-5555-5555-5555-555555555555"'
    if change == "wrong_role_object": role["id"] = "55555555-5555-5555-5555-555555555555"
    if change == "admin_unit": user["administrativeUnits"] = [{"id": "unit"}]
    if change == "scoped_activity": candidate["activityDisplayName"] = "Add scoped member to role"
    if change == "restricted_au_activity": candidate["activityDisplayName"] = "Add member to role scoped over Restricted Management Administrative Unit"
    if change == "role_without_target": candidate["targetResources"] = [role]
    if change == "missing_actor": candidate["initiatedBy"]["user"].pop("id")
    if change == "duplicate_role_template": user["modifiedProperties"].append(deepcopy(user["modifiedProperties"][1]))
    if change == "malformed_template": user["modifiedProperties"][1]["newValue"] = "{"
    if change == "wrong_service": candidate["loggedByService"] = "Privileged Identity Management"
    if change == "pim": candidate["activityDisplayName"] = "Add member to role completed (PIM activation)"
    if change == "wrong_operation": candidate["operationType"] = "Update"
    if change == "missing_time": candidate.pop("activityDateTime")
    if change == "missing_event_id": candidate.pop("id")
    if change == "other_category": candidate["category"] = "ApplicationManagement"
    assert normalize_entra_global_admin_self_grant(candidate, tenant=TENANT) is None


def test_invalid_tenant_and_untrusted_role_label_do_not_match():
    assert normalize_entra_global_admin_self_grant(row(), tenant="not-a-tenant") is None
    candidate = row()
    candidate["targetResources"][0]["modifiedProperties"][1]["newValue"] = '"not-global-admin"'
    candidate["targetResources"][1]["displayName"] = "Global Administrator"
    assert normalize_entra_global_admin_self_grant(candidate, tenant=TENANT) is None
