"""PIM for Groups self-activation joins live eligibility and the matching policy."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_azure_graph_group_membership import _snapshot
from tests.test_peaso_privesc_schema_ext_azure import T


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_pim.yaml").read_text())
    if row["id"] == "azure-entraid-pim-group-eligible-activation")


def _case(*, access="member", approval=False, policy=True, member=False, owner=False,
          live=True, expired=False, enabled=True, synced=False, restricted=False,
          dynamic=False):
    snap = _snapshot(app_permission=False, synced=synced, restricted=restricted)
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")
    users["items"][0]["accountEnabled"] = enabled
    groups = next(c for c in snap["collections"] if c["type"] == "directory_group")
    groups["items"][0]["groupTypes"] = ["DynamicMembership"] if dynamic else []
    membership = next(c for c in snap["collections"] if c["type"] == "directory_membership")
    membership.update(status="collected" if member else "empty", items=[{"id": "u-alice"}] if member else [])
    snap["collections"].extend([
        {"type": "directory_group_eligibility_schedule", "scope": f"{T}/groups/g-target",
         "service": "Microsoft.Graph", "status": "collected", "items": [{"id": "schedule",
             "principalId": "u-alice", "groupId": "g-target", "accessId": access, "status": "Provisioned"}]},
        {"type": "directory_group_eligibility_instance", "scope": f"{T}/groups/g-target",
         "service": "Microsoft.Graph", "status": "collected" if live else "denied",
         "items": ([{"id": "instance", "principalId": "u-alice", "groupId": "g-target",
                    "accessId": access, **({"endDateTime": "2020-01-01T00:00:00Z"} if expired else {})}]
                   if live else [])},
        {"type": "directory_owner", "scope": f"{T}/groups/g-target", "service": "Microsoft.Graph",
         "status": "collected", "items": [{"id": "g-target", "objectId": "g-target",
             "objectType": "group", "ownerIds": ["u-alice"] if owner else []}]},
        {"type": "directory_group_pim_policy" if access == "member" else "directory_group_pim_owner_policy",
         "scope": f"{T}/groups/g-target", "service": "Microsoft.Graph",
         "status": "collected" if policy else "denied",
         "items": ([{"id": "policy", "scopeId": "g-target", "roleDefinitionId": access,
                    "policy": {"rules": [{"id": "Approval_EndUser_Assignment",
                        "setting": {"isApprovalRequired": approval}}]}}] if policy else [])},
    ])
    return snap


def _targets(snap, source="u-alice"):
    return reached(privesc.analyze(snap, entries=[ENTRY]), source, ENTRY["id"])


def test_member_eligibility_requires_new_membership_and_open_policy():
    assert validate_entry(ENTRY)[0] == []
    assert _targets(_case()).get("g-target") == "conditional"
    for variant in ({"approval": True}, {"member": True}, {"expired": True},
                    {"enabled": False}, {"synced": True}, {"restricted": True}, {"dynamic": True}):
        assert "g-target" not in _targets(_case(**variant)), variant
    assert _targets(_case(policy=False)).get("g-target") == "conditional"
    assert _targets(_case(live=False)).get("g-target") == "conditional"


def test_owner_eligibility_uses_owner_policy_and_requires_new_access():
    assert _targets(_case(access="owner")).get("g-target") == "conditional"
    assert "g-target" not in _targets(_case(access="owner", approval=True))
    assert "g-target" not in _targets(_case(access="owner", owner=True))
    assert "g-target" not in _targets(_case(access="owner", member=True))


def test_service_principal_cannot_activate_user_eligibility():
    assert "g-target" not in _targets(_case(), "sp-source")
