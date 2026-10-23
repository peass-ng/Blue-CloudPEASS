"""A Container App assignment needs an exact writable and executable app."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-containerapp-assign-user-assigned-identity"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)
APP = RG + "/providers/Microsoft.App/containerApps/main"
OTHER = RG + "/providers/Microsoft.App/containerApps/other"
UAI = RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/worker"
WRITE_ROLE = "22222222-2222-2222-2222-222222222222"
WRITE = "Microsoft.App/containerApps/write"
START = "Microsoft.App/containerApps/start/action"
ASSIGN = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"


def _run(*, write_scope=APP, assign=True, start=False, running="Running", state="Succeeded",
         template=True, attached=False, graph_status="collected", identity_status="collected"):
    app = {"id": APP, "type": "Microsoft.App/containerApps", "name": "main",
           "identity": {"type": "UserAssigned", "userAssignedIdentities": {UAI: {"principalId": "mi-worker"}}}
           if attached else {"type": "None"},
           "properties": {"provisioningState": state, "runningStatus": running}}
    if template:
        app["properties"]["template"] = {"containers": [{"name": "main", "image": "example.org/app:1"}]}
    identity = {"id": UAI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                "properties": {"principalId": "mi-worker", "clientId": "worker-client"}}
    assignments = [("u-alice", "User", write_scope, WRITE_ROLE)]
    if assign:
        assignments.append(("u-alice", "User", UAI, ROLE_ID))
    snap = az(assignments, roles={ROLE_ID: ([ASSIGN], []),
                                  WRITE_ROLE: ([WRITE] + ([START] if start else []), [])},
              graph=[app] if graph_status == "collected" else [],
              extra=[("managed_identity", SUB, [identity] if identity_status == "collected" else [], identity_status)])
    if graph_status != "collected":
        graph_collection = next(c for c in snap["collections"] if c["type"] == "resource_graph")
        graph_collection["status"] = graph_status
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True)


def test_running_app_exact_write_and_assign_reaches_uami():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-worker": "conditional"}
    assert reached(_run(running="Stopped", start=True), "u-alice", TID) == {
        "mi-worker": "conditional"}


def test_wrong_app_missing_permission_or_no_execution_path_is_excluded():
    assert reached(_run(write_scope=OTHER), "u-alice", TID) == {}
    assert reached(_run(assign=False), "u-alice", TID) == {}
    assert reached(_run(running="Stopped"), "u-alice", TID) == {}
    assert reached(_run(state="Failed"), "u-alice", TID) == {}
    assert reached(_run(attached=True), "u-alice", TID) == {}


def test_missing_app_or_identity_details_stay_unresolved():
    for case in ({"template": False}, {"running": None}, {"state": None},
                 {"graph_status": "not_collected"}, {"identity_status": "not_collected"}):
        result = reached(_run(**case), "u-alice", TID)
        assert result and set(result.values()) == {"unknown"}
