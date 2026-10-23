"""An app's PIM active assignment must reach only eligible, new group membership."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_azure_graph_group_membership import _snapshot
from tests.test_peaso_privesc_schema_ext import reached


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_pim.yaml").read_text())
    if row["id"] == "azure-entraid-graph-pim-groups-active-assignment")


def _targets(*, grant=True, role_assignable=True, source_enabled=True,
             membership_complete=True, **kwargs):
    snap = _snapshot(**kwargs)
    role_grants = next(c for c in snap["collections"] if c["type"] == "directory_app_role_assignment")
    role_grants["items"] = role_grants["items"][:1] if grant else []
    if grant:
        role_grants["items"][0]["appRoleValue"] = "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup"
    group = next(c for c in snap["collections"] if c["type"] == "directory_group")
    group["items"][0]["isAssignableToRole"] = role_assignable
    if not source_enabled:
        source = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
        next(row for row in source["items"] if row["id"] == "sp-source")["accountEnabled"] = False
    if not membership_complete:
        membership = next(c for c in snap["collections"] if c["type"] == "directory_membership")
        membership["status"] = "partial"
    return reached(privesc.analyze(snap, entries=[ENTRY]), "sp-source", ENTRY["id"])


def test_active_pim_assignment_reaches_cloud_security_group_including_role_assignable():
    assert validate_entry(ENTRY)[0] == []
    assert "g-target" in _targets()
    assert "g-target" in _targets(role_assignable=False)


def test_active_pim_assignment_requires_real_new_membership_and_graph_grant():
    for variant in ({"grant": False}, {"member": True}, {"mail": True}, {"unified": True},
                    {"synced": True}, {"restricted": True}, {"au_complete": False},
                    {"source_enabled": False}, {"membership_complete": False}):
        assert "g-target" not in _targets(**variant), variant
