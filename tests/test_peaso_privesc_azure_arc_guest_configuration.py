"""Arc guest-configuration writes must reach the identity's assignment path."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TID = "azure-guestconfiguration-assignment-write-arc"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
HOST = f"{RG}/providers/Microsoft.HybridCompute/machines/arc-one"
OTHER = f"{RG}/providers/Microsoft.HybridCompute/machines/arc-other"
CHILD = HOST + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/existing"
ACTION = "Microsoft.GuestConfiguration/guestConfigurationAssignments/write"


def _run(scope=HOST, *, status="Connected", child=True):
    machines = [{"id": HOST, "type": "Microsoft.HybridCompute/machines",
                 "identity": {"principalId": "mi-one"}},
                {"id": OTHER, "type": "Microsoft.HybridCompute/machines",
                 "identity": {"principalId": "mi-other"}}]
    graph = [*machines]
    if child:
        graph.append({"id": CHILD, "type": "Microsoft.GuestConfiguration/guestConfigurationAssignments"})
    native = [{"id": HOST, "properties": {"status": status}}]
    snap = az(assignments=[("u-alice", "User", scope, "role-write")],
              roles={"role-write": ([ACTION], [])}, graph=graph,
              extra=[("arc_machine", SUB, native)])
    return reached(privesc.analyze(snap, entries=[ENTRY], include_unknown=True), "u-alice", TID)


def test_parent_or_known_child_write_reaches_only_its_arc_identity():
    assert validate_entry(ENTRY)[0] == []
    assert _run(HOST).get("mi-one") == "conditional"
    assert _run(CHILD).get("mi-one") == "conditional"
    assert _run(SUB).get("mi-one") == "conditional"
    assert _run(HOST).get("mi-other") != "conditional"


def test_wrong_child_or_machine_and_disconnected_agent_are_not_claimed():
    assert _run(HOST + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/other",
                child=False).get("mi-one") != "conditional"
    assert _run(OTHER).get("mi-one") != "conditional"
    assert _run(HOST, status="Disconnected").get("mi-one") != "conditional"
