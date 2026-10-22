"""An observed owner reaches only supported new membership on its owned group."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_azure_graph_group_membership import _snapshot
from tests.test_peaso_privesc_schema_ext_azure import T


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_groups.yaml").read_text())
    if row["id"] == "azure-entraid-group-owner-membership")


def _case(*, owner="u-alice", member=False, enabled=True, role_assignable=False,
          unified=False, synced=False, restricted=False, app_write=True, role_write=False):
    snap = _snapshot(app_permission=app_write, unified=unified, synced=synced, restricted=restricted)
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")
    users["items"][0]["accountEnabled"] = enabled
    group = next(c for c in snap["collections"] if c["type"] == "directory_group")
    group["items"][0]["isAssignableToRole"] = role_assignable
    membership = next(c for c in snap["collections"] if c["type"] == "directory_membership")
    membership.update(status="collected" if member else "empty", items=[{"id": owner}] if member else [])
    snap["collections"].append({"type": "directory_owner", "scope": f"{T}/groups/g-target",
        "service": "Microsoft.Graph", "status": "collected",
        "items": [{"id": "g-target", "objectId": "g-target", "objectType": "group", "ownerIds": [owner]}]})
    if role_write:
        grants = next(c for c in snap["collections"] if c["type"] == "directory_app_role_assignment")
        grants["items"].append({"id": "role-grant", "principalId": "sp-source", "resourceId": "sp-graph",
            "appRoleValue": "RoleManagement.ReadWrite.Directory", "appRoleEnabled": True})
    return snap


def _targets(snap, owner):
    return reached(privesc.analyze(snap, entries=[ENTRY]), owner, ENTRY["id"])


def test_user_owner_can_join_new_group_including_protected_group():
    assert validate_entry(ENTRY)[0] == []
    assert _targets(_case(), "u-alice").get("g-target") == "derived"
    assert _targets(_case(role_assignable=True), "u-alice").get("g-target") == "conditional"
    for variant in ({"member": True}, {"enabled": False}, {"synced": True}, {"restricted": True}):
        assert "g-target" not in _targets(_case(**variant), "u-alice"), variant


def test_app_owner_needs_graph_rights_and_supported_group():
    assert _targets(_case(owner="sp-source"), "sp-source").get("g-target") == "derived"
    assert "g-target" not in _targets(_case(owner="sp-source", app_write=False), "sp-source")
    assert "g-target" not in _targets(_case(owner="sp-source", unified=True), "sp-source")
    assert "g-target" not in _targets(_case(owner="sp-source", role_assignable=True), "sp-source")
    assert _targets(_case(owner="sp-source", role_assignable=True, role_write=True), "sp-source").get("g-target") == "conditional"


def test_unowned_group_does_not_appear():
    snap = _case()
    owners = next(c for c in snap["collections"] if c["type"] == "directory_owner")
    owners["items"][0]["ownerIds"] = ["u-other"]
    assert "g-target" not in _targets(snap, "u-alice")
