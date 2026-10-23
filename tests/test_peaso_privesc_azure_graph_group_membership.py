"""Graph app self-membership is limited to writable security groups."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T, az


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_groups.yaml").read_text())
    if row["id"] == "azure-entraid-graph-group-readwrite-all")
GRAPH = "00000003-0000-0000-c000-000000000000"


def _snapshot(*, app_permission=True, member=False, mail=False, unified=False, synced=False,
              restricted=False, au_complete=True):
    snap = az(sps=("sp-source", "sp-graph"), groups=[("g-target", "target")], members={
        "g-target": ["sp-source"] if member else []}, extra=[
        ("directory_app_role_assignment", T, [{"id": "group-grant", "principalId": "sp-source",
            "resourceId": "sp-graph", "appRoleValue": "GroupMember.ReadWrite.All", "appRoleEnabled": True},
            *([{"id": "app-grant", "principalId": "sp-source", "resourceId": "sp-graph",
                "appRoleValue": "Application.ReadWrite.All", "appRoleEnabled": True}] if app_permission else [])]),
        ("directory_administrative_unit", T, [{"id": "au1", "isMemberManagementRestricted": True,
            **({"memberIds": ["g-target"] if restricted else []} if au_complete else {})}], "collected")])
    principals = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    for row in principals["items"]:
        row.update(appId=GRAPH if row["id"] == "sp-graph" else "source-app", accountEnabled=True)
    groups = next(c for c in snap["collections"] if c["type"] == "directory_group")
    groups["items"][0].update(groupTypes=["Unified"] if unified else [], mailEnabled=mail,
        securityEnabled=True, isAssignableToRole=False, onPremisesSyncEnabled=synced)
    return snap


def _targets(snap):
    return reached(privesc.analyze(snap, entries=[ENTRY]), "sp-source", ENTRY["id"])


def test_new_service_principal_membership_requires_both_graph_permissions():
    assert validate_entry(ENTRY)[0] == []
    assert _targets(_snapshot()).get("g-target") == "derived"
    assert "g-target" not in _targets(_snapshot(app_permission=False))
    assert "g-target" not in _targets(_snapshot(member=True))


def test_group_type_source_of_authority_and_restricted_au_block():
    for variant in ({"mail": True}, {"unified": True}, {"synced": True}, {"restricted": True},
                    {"au_complete": False}):
        assert "g-target" not in _targets(_snapshot(**variant)), variant
