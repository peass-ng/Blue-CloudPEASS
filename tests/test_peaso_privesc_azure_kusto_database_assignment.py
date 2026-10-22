"""Kusto database assignment writes must reach one exact database."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-kusto-database-principal-assignment-write"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
CLUSTER = f"{RG}/providers/Microsoft.Kusto/clusters/one"
DB = CLUSTER + "/databases/one"
OTHER = CLUSTER + "/databases/two"
EXISTING = DB + "/principalAssignments/existing"
ACTION = "Microsoft.Kusto/clusters/databases/principalAssignments/write"


def _run(scope=DB, *, include_child=True):
    graph = [{"id": CLUSTER, "type": "Microsoft.Kusto/clusters"},
             {"id": DB, "type": "Microsoft.Kusto/clusters/databases"},
             {"id": OTHER, "type": "Microsoft.Kusto/clusters/databases"}]
    if include_child:
        graph.append({"id": EXISTING,
                      "type": "Microsoft.Kusto/clusters/databases/principalAssignments"})
    snap = az(assignments=[("u-alice", "User", scope, ROLE_ID)],
              roles={ROLE_ID: ([ACTION], [])}, graph=graph)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TID)


def test_database_or_known_child_write_reaches_only_its_database():
    assert validate_entry(ENTRY)[0] == []
    assert set(_run(DB)) == {f"azure_dataplane_admin:{DB.casefold()}"}
    assert set(_run(EXISTING)) == {f"azure_dataplane_admin:{DB.casefold()}"}
    assert set(_run(SUB)) == {f"azure_dataplane_admin:{DB.casefold()}",
                              f"azure_dataplane_admin:{OTHER.casefold()}"}


def test_uncollected_child_and_other_database_do_not_grant_first_database():
    assert _run(EXISTING, include_child=False).get(f"azure_dataplane_admin:{DB.casefold()}") != "conditional"
    assert _run(OTHER).get(f"azure_dataplane_admin:{DB.casefold()}") != "conditional"
