"""Kusto cluster assignments grant only the exact cluster's data-plane role."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-kusto-cluster-principal-assignment-write"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
CLUSTER = f"{RG}/providers/Microsoft.Kusto/clusters/one"
OTHER = f"{RG}/providers/Microsoft.Kusto/clusters/two"
EXISTING = CLUSTER + "/principalAssignments/existing"
ACTION = "Microsoft.Kusto/clusters/principalAssignments/write"


def _run(scope=CLUSTER, *, include_child=True):
    graph = [{"id": CLUSTER, "type": "Microsoft.Kusto/clusters"},
             {"id": OTHER, "type": "Microsoft.Kusto/clusters"},
             {"id": f"{RG}/providers/Microsoft.Compute/virtualMachines/vm",
              "type": "Microsoft.Compute/virtualMachines"}]
    if include_child:
        graph.append({"id": EXISTING, "type": "Microsoft.Kusto/clusters/principalAssignments"})
    snap = az(assignments=[("u-alice", "User", scope, ROLE_ID)],
              roles={ROLE_ID: ([ACTION], [])}, graph=graph)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TID)


def test_cluster_or_known_child_write_reaches_exact_cluster():
    assert validate_entry(ENTRY)[0] == []
    assert set(_run(CLUSTER)) == {f"azure_dataplane_admin:{CLUSTER.casefold()}"}
    assert set(_run(EXISTING)) == {f"azure_dataplane_admin:{CLUSTER.casefold()}"}
    assert set(_run(SUB)) == {f"azure_dataplane_admin:{CLUSTER.casefold()}",
                              f"azure_dataplane_admin:{OTHER.casefold()}"}


def test_wrong_child_or_other_cluster_cannot_grant_first_cluster():
    assert _run(EXISTING, include_child=False).get(f"azure_dataplane_admin:{CLUSTER.casefold()}") != "conditional"
    assert _run(OTHER).get(f"azure_dataplane_admin:{CLUSTER.casefold()}") != "conditional"
    assert _run(CLUSTER + "/databases/db/principalAssignments/x").get(
        f"azure_dataplane_admin:{CLUSTER.casefold()}") != "conditional"
