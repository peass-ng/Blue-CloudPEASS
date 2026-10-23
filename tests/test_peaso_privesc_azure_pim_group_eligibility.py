"""A Graph PIM eligibility grant needs an activatable, controlled user path."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_azure_graph_group_membership import _snapshot
from tests.test_peaso_privesc_schema_ext import entry, reached


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_pim.yaml").read_text())
    if row["id"] == "azure-entraid-graph-pim-groups-eligibility")
CONTROL = entry("azure-test-control-user-for-pim-eligibility", "azure",
    {"all_of": [{"graph_app_permission": "GroupMember.ReadWrite.All"}]},
    {"kind": "azure_user", "selector": {"any_principal_in_scope": True}, "scope": "tenant"})


def _targets(*, control=True, grant=True, user_enabled=True, user_member=False,
             approval=False, policy_write=False, policy_complete=True, **kwargs):
    snap = _snapshot(app_permission=False, **kwargs)
    roles = next(c for c in snap["collections"] if c["type"] == "directory_app_role_assignment")
    if grant:
        roles["items"].append({"id": "pim-grant", "principalId": "sp-source", "resourceId": "sp-graph",
                             "appRoleValue": "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup",
                             "appRoleEnabled": True})
    if policy_write:
        roles["items"].append({"id": "policy-grant", "principalId": "sp-source", "resourceId": "sp-graph",
                             "appRoleValue": "RoleManagementPolicy.ReadWrite.AzureADGroup", "appRoleEnabled": True})
    user = next(c for c in snap["collections"] if c["type"] == "directory_user")
    user["items"][0]["accountEnabled"] = user_enabled
    if user_member:
        membership = next(c for c in snap["collections"] if c["type"] == "directory_membership")
        membership["items"].append({"id": "u-alice"})
    snap["collections"].append({"type": "directory_group_pim_policy", "scope": "/tenants/t/groups/g-target",
                                "service": "Microsoft.Graph", "status": "collected" if policy_complete else "denied",
                                "items": [{"id": "pim-policy", "scopeId": "g-target", "roleDefinitionId": "member",
                                           "policy": {"rules": [{"id": "Approval_EndUser_Assignment",
                                                                 "setting": {"isApprovalRequired": approval}}]}}] if policy_complete else []})
    return reached(privesc.analyze(snap, entries=[CONTROL, ENTRY] if control else [ENTRY]),
                   "sp-source", ENTRY["id"])


def test_pim_eligibility_reaches_controlled_user_for_security_or_m365_group():
    assert validate_entry(ENTRY)[0] == []
    assert _targets().get("g-target") == "conditional"
    assert _targets(unified=True).get("g-target") == "conditional"


def test_pim_eligibility_requires_grant_controlled_user_and_new_cloud_membership():
    for variant in ({"control": False}, {"grant": False}, {"user_enabled": False},
                    {"user_member": True}, {"synced": True}, {"mail": True},
                    {"restricted": True}, {"au_complete": False}):
        assert "g-target" not in _targets(**variant), variant


def test_approval_blocks_eligibility_unless_source_can_change_policy():
    assert "g-target" not in _targets(approval=True)
    assert _targets(approval=True, policy_write=True).get("g-target") == "conditional"
    assert _targets(policy_complete=False).get("g-target") == "conditional"
