"""Owner-write escalation requires a new owner and new supported membership."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_azure_group_members_update import _case as membership_case
from tests.test_peaso_privesc_schema_ext_azure import T


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_groups.yaml").read_text())
    if row["id"] == "azure-entraid-group-owners-update")


def _case(*, principal="u-alice", owner=False, owner_status="collected", **kwargs):
    snap = membership_case(principal=principal, **kwargs)
    defs = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    defs["items"][0]["rolePermissions"][0]["allowedResourceActions"] = [
        "microsoft.directory/groups/owners/update"]
    snap["collections"].append({"type": "directory_owner", "scope": f"{T}/groups/g-target",
        "service": "Microsoft.Graph", "status": owner_status,
        "items": [{"id": "g-target", "objectId": "g-target", "objectType": "group",
                   "ownerIds": [principal] if owner else []}]})
    return snap


def _targets(snap, principal="u-alice"):
    return reached(privesc.analyze(snap, entries=[ENTRY]), principal, ENTRY["id"])


def test_user_owner_write_requires_new_owner_and_member():
    assert validate_entry(ENTRY)[0] == []
    assert _targets(_case()).get("g-target") == "derived"
    for variant in ({"owner": True}, {"member": True}, {"enabled": False},
                    {"mail": True}, {"security": False}, {"role_scope": "/g-other"}):
        assert "g-target" not in _targets(_case(**variant)), variant
    assert _targets(_case(unified=True)).get("g-target") == "derived"


def test_app_owner_write_needs_app_membership_rights():
    assert _targets(_case(principal="sp-source"), "sp-source").get("g-target") == "conditional"
    assert "g-target" not in _targets(_case(principal="sp-source", app_permission=False), "sp-source")
    assert "g-target" not in _targets(_case(principal="sp-source", unified=True), "sp-source")


def test_incomplete_owner_inventory_retains_conditional_path():
    assert _targets(_case(owner_status="partial")).get("g-target") == "conditional"
    assert "g-target" not in _targets(_case(owner=True, owner_status="partial"))
