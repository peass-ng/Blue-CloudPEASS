"""Container App write reaches only the exact app's current identity."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-containerapp-write-existing"
APP = RG + "/providers/Microsoft.App/containerApps/main"
OTHER = RG + "/providers/Microsoft.App/containerApps/other"
UAI = RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/worker"
WRITE = "Microsoft.App/containerApps/write"
START = "Microsoft.App/containerApps/start/action"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _app(*, app_id=APP, principal="mi-main", uai=False, running="Running", state="Succeeded"):
    identity = ({"type": "UserAssigned", "userAssignedIdentities": {UAI: {"principalId": principal}}}
                if uai else {"type": "SystemAssigned", "principalId": principal})
    return {"id": app_id, "type": "Microsoft.App/containerApps", "identity": identity,
            "properties": {"provisioningState": state, "runningStatus": running,
                           "configuration": {"identitySettings": [
                               {"identity": UAI if uai else "system", "lifecycle": "None"}]}},
            "revisions": []}


def _run(*, app=None, graph=None, actions=(WRITE,), scope=APP, status="collected"):
    app = app or _app()
    graph = graph if graph is not None else [{"id": app["id"], "type": app["type"],
                                              "name": "main", "identity": app["identity"]}]
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=graph, extra=[("container_app_runtime", SUB,
                                   [app] if status == "collected" else [], status)])
    return reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True),
                   "u-alice", TID)


def test_write_on_exact_running_app_with_current_identity_is_conditional():
    assert validate_entry(ENTRY)[0] == []
    assert _run() == {"mi-main": "conditional"}
    assert _run(app=_app(principal="mi-worker", uai=True)) == {"mi-worker": "conditional"}
    assert _run(app=_app(principal="mi-current"), graph=[{"id": APP, "type": "Microsoft.App/containerApps",
                                                         "identity": {"type": "SystemAssigned", "principalId": "mi-old"}}]) == {
        "mi-current": "conditional"}


def test_stopped_app_needs_start_permission_and_bad_state_has_no_path():
    assert _run(app=_app(running="Stopped")) == {}
    assert _run(app=_app(running="Stopped"), actions=(WRITE, START)) == {"mi-main": "conditional"}
    assert _run(app=_app(state="Failed")) == {}
    assert set(_run(app=_app(running="Unknown")).values()) == {"unknown"}


def test_wrong_scope_stale_identity_and_missing_native_read_do_not_make_edge():
    assert _run(scope=OTHER) == {}
    assert _run(actions=(START,)) == {}
    assert _run(app=_app(principal="mi-new"), graph=[{"id": APP, "type": "Microsoft.App/containerApps",
                                                     "identity": {"type": "SystemAssigned", "principalId": "mi-old"}}]) == {
        "mi-new": "conditional"}
    assert set(_run(status="denied").values()) == {"unknown"}
