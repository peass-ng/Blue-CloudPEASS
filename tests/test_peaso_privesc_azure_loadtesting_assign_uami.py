"""Load test identity assignment needs one runnable resource and exact UAMI."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TID = "azure-loadtesting-assign-user-assigned-identity"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
LOAD = f"{RG}/providers/Microsoft.LoadTestService/loadtests/one"
OTHER = f"{RG}/providers/Microsoft.LoadTestService/loadtests/two"
UAMI = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/target"
WRITE = "Microsoft.LoadTestService/loadTests/write"
WRITE_TEST = "Microsoft.LoadTestService/loadtests/writeTest/action"
START_TEST = "Microsoft.LoadTestService/loadtests/startTest/action"
ASSIGN = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"


def _run(*, write_scope=LOAD, test_scope=LOAD, start_scope=LOAD, assign_scope=UAMI,
         include_load=True, data_actions=True):
    assignments = [("u-alice", "User", write_scope, "role-write"),
                   ("u-alice", "User", test_scope, "role-test"),
                   ("u-alice", "User", start_scope, "role-start"),
                   ("u-alice", "User", assign_scope, "role-assign")]
    identities = [{"id": UAMI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                   "properties": {"principalId": "mi-target"}}]
    graph = ([{"id": LOAD, "type": "Microsoft.LoadTestService/loadtests"},
              {"id": OTHER, "type": "Microsoft.LoadTestService/loadtests"}]
             if include_load else [])
    roles = {"role-write": ([WRITE], []),
             "role-test": ([], [WRITE_TEST]) if data_actions else ([WRITE_TEST], []),
             "role-start": ([], [START_TEST]) if data_actions else ([START_TEST], []),
             "role-assign": ([ASSIGN], [])}
    snap = az(assignments=assignments, roles=roles, graph=graph,
              extra=[("managed_identity", SUB, identities),
                     ("resource_group", SUB, [{"id": RG}])])
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TID)


def test_existing_and_creatable_resource_reach_exact_assignable_uami():
    assert validate_entry(ENTRY)[0] == []
    assert _run().get("mi-target") == "conditional"
    assert _run(write_scope=RG, test_scope=RG, start_scope=RG,
                include_load=False).get("mi-target") == "conditional"


def test_split_or_wrong_plane_rights_and_wrong_uami_do_not_form_path():
    assert _run(write_scope=LOAD, test_scope=OTHER, start_scope=LOAD).get("mi-target") != "conditional"
    assert _run(write_scope=LOAD, test_scope=LOAD, start_scope=OTHER).get("mi-target") != "conditional"
    assert _run(assign_scope=OTHER).get("mi-target") != "conditional"
    assert _run(data_actions=False).get("mi-target") != "conditional"
