"""The user-membership route needs a reachable user outside the group."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import entry, reached
from tests.test_peaso_privesc_azure_graph_group_membership import _snapshot


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_groups.yaml").read_text())
    if row["id"] == "azure-entraid-graph-group-readwrite-all-controlled-user")
CONTROL = entry("azure-test-control-user-for-group", "azure",
    {"all_of": [{"graph_app_permission": "GroupMember.ReadWrite.All"}]},
    {"kind": "azure_user", "selector": {"any_principal_in_scope": True}, "scope": "tenant"})


def _targets(snap, *, control=False):
    return reached(privesc.analyze(snap, entries=[CONTROL, ENTRY] if control else [ENTRY]),
                   "sp-source", ENTRY["id"])


def test_controlled_user_chain_must_reach_user_outside_target_group():
    assert validate_entry(ENTRY)[0] == []
    snap = _snapshot(app_permission=False)
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")
    users["items"][0]["accountEnabled"] = True
    assert "g-target" not in _targets(snap)
    assert _targets(snap, control=True).get("g-target") == "conditional"
    membership = next(c for c in snap["collections"] if c["type"] == "directory_membership")
    membership.update(status="collected", items=[{"id": "u-alice"}])
    assert "g-target" not in _targets(snap, control=True)


def test_disabled_controlled_user_or_unwritable_group_does_not_reach():
    snap = _snapshot(app_permission=False)
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")
    users["items"][0]["accountEnabled"] = False
    assert "g-target" not in _targets(snap, control=True)
    snap = _snapshot(app_permission=False, mail=True)
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")
    users["items"][0]["accountEnabled"] = True
    assert "g-target" not in _targets(snap, control=True)


def test_user_already_member_through_nested_group_is_excluded():
    snap = _snapshot(app_permission=False)
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")
    users["items"][0]["accountEnabled"] = True
    groups = next(c for c in snap["collections"] if c["type"] == "directory_group")
    groups["items"].append({"id": "g-child", "displayName": "child", "securityEnabled": True,
        "mailEnabled": False, "groupTypes": [], "isAssignableToRole": False,
        "onPremisesSyncEnabled": False})
    target = next(c for c in snap["collections"] if c["type"] == "directory_membership")
    target.update(status="collected", items=[{"id": "g-child"}])
    snap["collections"].append({"type": "directory_membership", "scope": "/tenants/t/groups/g-child",
        "service": "Microsoft.Graph", "status": "collected", "items": [{"id": "u-alice"}]})
    assert "g-target" not in _targets(snap, control=True)
