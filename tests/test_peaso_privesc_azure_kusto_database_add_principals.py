"""Kusto AddPrincipals must authorize the exact database target."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-kusto-database-add-principals"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
CLUSTER = f"{RG}/providers/Microsoft.Kusto/clusters/one"
DB = CLUSTER + "/databases/one"
OTHER = CLUSTER + "/databases/two"
ACTION = "Microsoft.Kusto/Clusters/Databases/AddPrincipals/action"


def _run(scope=DB):
    graph = [{"id": CLUSTER, "type": "Microsoft.Kusto/clusters"},
             {"id": DB, "type": "Microsoft.Kusto/clusters/databases"},
             {"id": OTHER, "type": "Microsoft.Kusto/clusters/databases"},
             {"id": f"{RG}/providers/Microsoft.Compute/virtualMachines/vm",
              "type": "Microsoft.Compute/virtualMachines"}]
    snap = az(assignments=[("u-alice", "User", scope, ROLE_ID)],
              roles={ROLE_ID: ([ACTION], [])}, graph=graph)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TID)


def test_database_and_ancestor_grants_reach_only_database_targets():
    assert validate_entry(ENTRY)[0] == []
    assert set(_run(DB)) == {f"azure_dataplane_admin:{DB.casefold()}"}
    assert set(_run(CLUSTER)) == {f"azure_dataplane_admin:{DB.casefold()}",
                                  f"azure_dataplane_admin:{OTHER.casefold()}"}
    assert set(_run(SUB)) == {f"azure_dataplane_admin:{DB.casefold()}",
                              f"azure_dataplane_admin:{OTHER.casefold()}"}


def test_other_database_does_not_grant_admin_on_first():
    assert _run(OTHER).get(f"azure_dataplane_admin:{DB.casefold()}") != "conditional"
