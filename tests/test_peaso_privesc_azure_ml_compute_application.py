"""Application access must reach the exact usable ML compute instance."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TID = "azure-ml-compute-application-access"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
WORKSPACE = f"{RG}/providers/Microsoft.MachineLearningServices/workspaces/ml"
COMPUTE = f"{WORKSPACE}/computes/one"
OTHER = f"{WORKSPACE}/computes/two"
READ = "Microsoft.MachineLearningServices/workspaces/read"
ACCESS = "Microsoft.MachineLearningServices/workspaces/computes/applicationaccess/action"
START = "Microsoft.MachineLearningServices/workspaces/computes/start/action"


def _run(*, sharing="Personal", user="u-alice", state="Running", compute_type="ComputeInstance",
         access_scope=COMPUTE, read_scope=WORKSPACE, start=False, native=True):
    instance = {"id": COMPUTE, "type": "Microsoft.MachineLearningServices/workspaces/computes",
                "identity": {"principalId": "mi-compute"},
                "properties": {"computeType": compute_type,
                               "properties": {"applicationSharingPolicy": sharing, "state": state,
                                              "personalComputeInstanceSettings": {"assignedUser": {"objectId": user}}}}}
    graph = [{"id": OTHER, "type": "Microsoft.MachineLearningServices/workspaces/computes",
              "identity": {"principalId": "mi-other"},
              "properties": {"computeType": "ComputeInstance", "properties": {"state": "Running"}}}]
    extra = [("ml_compute", SUB, [instance])] if native else []
    assignments = [("u-alice", "User", read_scope, "role-read"),
                   ("u-alice", "User", access_scope, "role-access")]
    if start:
        assignments.append(("u-alice", "User", COMPUTE, "role-start"))
    snap = az(assignments=assignments, roles={"role-read": ([READ], []),
                                              "role-access": ([ACCESS], []),
                                              "role-start": ([START], [])},
              graph=graph, extra=extra)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TID)


def test_personal_and_shared_running_compute_exact_access():
    assert validate_entry(ENTRY)[0] == []
    assert _run().get("mi-compute") == "conditional"
    assert _run(sharing="Shared", user="u-other").get("mi-compute") == "conditional"
    assert _run().get("mi-other") != "conditional"


def test_wrong_user_scope_or_compute_type_do_not_reach_identity():
    assert _run(user="u-other").get("mi-compute") != "conditional"
    assert _run(access_scope=OTHER).get("mi-compute") != "conditional"
    assert _run(read_scope=OTHER).get("mi-compute") != "conditional"
    assert _run(compute_type="AmlCompute").get("mi-compute") != "conditional"


def test_stopped_requires_start_and_missing_native_settings_are_unresolved():
    assert _run(state="Stopped").get("mi-compute") != "conditional"
    assert _run(state="Stopped", start=True).get("mi-compute") == "conditional"
    assert _run(native=False).get("mi-compute") != "conditional"
