"""Dynamic rule edits need an enabled user who can gain new group access."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import entry, reached
from tests.test_peaso_privesc_azure_graph_group_membership import _snapshot


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_groups.yaml").read_text())
    if row["id"] == "azure-entraid-group-dynamic-rule-update")
CONTROL = entry("azure-test-control-user-for-dynamic-rule", "azure",
    {"all_of": [{"graph_app_permission": "GroupMember.ReadWrite.All"}]},
    {"kind": "azure_user", "selector": {"any_principal_in_scope": True}, "scope": "tenant"})


def _snapshot_for_rule(*, controlled=False, enabled=True, member=False, synced=False,
                       assignable=False, restricted=False):
    snap = _snapshot(app_permission=False, restricted=restricted)
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")
    users["items"][0]["accountEnabled"] = enabled
    groups = next(c for c in snap["collections"] if c["type"] == "directory_group")
    groups["items"][0].update(groupTypes=["DynamicMembership"], membershipRule="user.objectId -eq \"u-other\"",
        isAssignableToRole=assignable, onPremisesSyncEnabled=synced)
    membership = next(c for c in snap["collections"] if c["type"] == "directory_membership")
    membership.update(status="collected" if member else "empty", items=[{"id": "u-alice"}] if member else [])
    grants = next(c for c in snap["collections"] if c["type"] == "directory_app_role_assignment")
    grants["items"].append({"id": "dynamic-rule-grant", "principalId": "sp-source", "resourceId": "sp-graph",
                          "appRoleValue": "Group.ReadWrite.All", "appRoleEnabled": True})
    return snap


def _targets(snap, *, controlled=False):
    return reached(privesc.analyze(snap, entries=[CONTROL, ENTRY] if controlled else [ENTRY]),
                   "sp-source", ENTRY["id"])


def test_app_rule_update_needs_controlled_enabled_nonmember_user():
    assert validate_entry(ENTRY)[0] == []
    assert "g-target" not in _targets(_snapshot_for_rule())
    assert _targets(_snapshot_for_rule(), controlled=True).get("g-target") == "conditional"
    assert "g-target" not in _targets(_snapshot_for_rule(enabled=False), controlled=True)
    assert "g-target" not in _targets(_snapshot_for_rule(member=True), controlled=True)


def test_unwritable_or_restricted_dynamic_group_is_excluded():
    for variant in ({"synced": True}, {"assignable": True}, {"restricted": True}):
        assert "g-target" not in _targets(_snapshot_for_rule(**variant), controlled=True), variant


def test_user_directory_role_must_cover_the_group():
    snap = _snapshot_for_rule()
    role_defs = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    role_defs.update(status="collected", items=[{"id": "rule-role", "displayName": "Rule editor",
        "rolePermissions": [{"allowedResourceActions": ["microsoft.directory/groups/dynamicMembershipRule/update"]}] }])
    role_assignments = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    role_assignments.update(status="collected", items=[{"id": "assignment", "principalId": "u-alice",
        "roleDefinitionId": "rule-role", "directoryScopeId": "/g-target"}])
    assert reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", ENTRY["id"]).get("g-target") == "conditional"
    role_assignments["items"][0]["directoryScopeId"] = "/g-other"
    assert "g-target" not in reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", ENTRY["id"])
