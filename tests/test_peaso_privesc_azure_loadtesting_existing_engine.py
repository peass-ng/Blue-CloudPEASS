"""Existing Load Testing identity needs both data actions on its own host."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TID = "azure-loadtesting-test-engine-identity"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
LOAD = f"{RG}/providers/Microsoft.LoadTestService/loadtests/one"
OTHER = f"{RG}/providers/Microsoft.LoadTestService/loadtests/two"
WRITE_TEST = "Microsoft.LoadTestService/loadtests/writeTest/action"
START_TEST = "Microsoft.LoadTestService/loadtests/startTest/action"


def _run(write_scope=LOAD, start_scope=LOAD, *, data_actions=True):
    graph = [{"id": LOAD, "type": "Microsoft.LoadTestService/loadtests",
              "identity": {"principalId": "mi-one"}},
             {"id": OTHER, "type": "Microsoft.LoadTestService/loadtests",
              "identity": {"principalId": "mi-other"}}]
    snap = az(assignments=[("u-alice", "User", write_scope, "role-write"),
                           ("u-alice", "User", start_scope, "role-start")],
              roles={"role-write": ([], [WRITE_TEST]) if data_actions else ([WRITE_TEST], []),
                     "role-start": ([], [START_TEST]) if data_actions else ([START_TEST], [])},
              graph=graph)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TID)


def test_same_host_data_actions_reach_only_its_identity():
    assert validate_entry(ENTRY)[0] == []
    assert _run() == {"mi-one": "conditional"}
    assert _run(SUB, SUB) == {"mi-one": "conditional", "mi-other": "conditional"}


def test_split_hosts_and_control_plane_actions_do_not_reach_identity():
    assert _run(LOAD, OTHER).get("mi-one") != "conditional"
    assert _run(OTHER, LOAD).get("mi-one") != "conditional"
    assert _run(data_actions=False).get("mi-one") != "conditional"
