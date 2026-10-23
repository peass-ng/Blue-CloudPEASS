"""Directory group membership writes only add a new eligible member."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_azure_graph_group_membership import _snapshot


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_groups.yaml").read_text())
    if row["id"] == "azure-entraid-group-members-update")


def _case(*, principal="u-alice", member=False, unified=False, mail=False, security=True,
          role_scope="/g-target", enabled=True, app_permission=True):
    snap = _snapshot(app_permission=app_permission, unified=unified, mail=mail, member=False)
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")
    users["items"][0]["accountEnabled"] = enabled
    groups = next(c for c in snap["collections"] if c["type"] == "directory_group")
    groups["items"][0]["securityEnabled"] = security
    membership = next(c for c in snap["collections"] if c["type"] == "directory_membership")
    membership.update(status="collected" if member else "empty", items=[{"id": principal}] if member else [])
    role_defs = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    role_defs.update(status="collected", items=[{"id": "member-role", "displayName": "Member editor",
        "rolePermissions": [{"allowedResourceActions": ["microsoft.directory/groups/members/update"]}]}])
    role_assignments = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    role_assignments.update(status="collected", items=[{"id": "assignment", "principalId": principal,
        "roleDefinitionId": "member-role", "directoryScopeId": role_scope}])
    return snap


def _targets(snap, principal):
    return reached(privesc.analyze(snap, entries=[ENTRY]), principal, ENTRY["id"])


def test_user_membership_write_needs_new_supported_group_and_exact_scope():
    assert validate_entry(ENTRY)[0] == []
    assert _targets(_case(), "u-alice").get("g-target") == "derived"
    for variant in ({"member": True}, {"mail": True}, {"security": False},
                    {"role_scope": "/g-other"}, {"enabled": False}):
        assert "g-target" not in _targets(_case(**variant), "u-alice"), variant
    assert _targets(_case(unified=True), "u-alice").get("g-target") == "derived"


def test_app_membership_write_needs_graph_rights_and_security_group():
    assert _targets(_case(principal="sp-source"), "sp-source").get("g-target") == "derived"
    assert "g-target" not in _targets(_case(principal="sp-source", app_permission=False), "sp-source")
    assert "g-target" not in _targets(_case(principal="sp-source", unified=True), "sp-source")
    assert "g-target" not in _targets(_case(principal="sp-source", member=True), "sp-source")


def test_existing_nested_membership_is_not_a_new_escalation():
    snap = _case()
    groups = next(c for c in snap["collections"] if c["type"] == "directory_group")
    groups["items"].append({"id": "g-child", "displayName": "child", "securityEnabled": True,
        "mailEnabled": False, "groupTypes": [], "isAssignableToRole": False,
        "onPremisesSyncEnabled": False})
    membership = next(c for c in snap["collections"] if c["type"] == "directory_membership")
    membership.update(status="collected", items=[{"id": "g-child"}])
    snap["collections"].append({"type": "directory_membership", "scope": "/tenants/t/groups/g-child",
        "service": "Microsoft.Graph", "status": "collected", "items": [{"id": "u-alice"}]})
    assert "g-target" not in _targets(snap, "u-alice")


def test_incomplete_membership_keeps_possible_new_access_conditional():
    snap = _case()
    membership = next(c for c in snap["collections"] if c["type"] == "directory_membership")
    membership["status"] = "partial"
    assert _targets(snap, "u-alice").get("g-target") == "conditional"
