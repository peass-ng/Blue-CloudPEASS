"""Console privilege paths require one runnable app and its usable identity."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-containerapp-exec"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)
APP = RG + "/providers/Microsoft.App/containerApps/main"
OTHER = RG + "/providers/Microsoft.App/containerApps/other"
UAI = RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/worker"
TOKEN = "Microsoft.App/containerApps/getAuthToken/action"
EXEC = "Microsoft.App/containerApps/exec/action"
DEBUG = "Microsoft.App/containerApps/debug/action"


def _app(app_id=APP, *, principal="mi-main", uai=False, lifecycle=None, replicas=1,
         running="Running", revision_state="Running"):
    identity = ({"type": "UserAssigned", "userAssignedIdentities": {UAI: {"principalId": principal}}}
                if uai else {"type": "SystemAssigned", "principalId": principal})
    settings = None if lifecycle is None else [{"identity": UAI if uai else "system", "lifecycle": lifecycle}]
    return {"id": app_id, "type": "Microsoft.App/containerApps", "identity": identity,
            "properties": {"provisioningState": "Succeeded", "runningStatus": running,
                           "configuration": {"identitySettings": settings}},
            "revisions": [{"id": app_id + "/revisions/rev1", "properties": {
                "active": True, "runningState": revision_state, "replicas": replicas}}]}


def _run(*, app=None, graph=None, actions=(TOKEN,), data_actions=(EXEC,), scope=APP,
         runtime_status="collected", uai=False):
    app = app or _app(uai=uai)
    graph = graph if graph is not None else [{"id": app["id"], "type": "Microsoft.App/containerApps",
                                              "name": app["id"].rsplit("/", 1)[-1],
                                              "identity": app["identity"], "properties": {}}]
    extra = [("container_app_runtime", SUB, [app] if runtime_status == "collected" else [], runtime_status)]
    return privesc.analyze(
        az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), list(data_actions))},
           graph=graph, extra=extra), entries=[copy.deepcopy(ENTRY)], include_unknown=True)


def test_exec_and_debug_use_azure_data_actions_on_the_same_running_app():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-main": "conditional"}
    assert reached(_run(data_actions=(DEBUG,)), "u-alice", TID) == {"mi-main": "conditional"}
    assert reached(_run(actions=(TOKEN, EXEC), data_actions=()), "u-alice", TID) == {}
    assert reached(_run(actions=(EXEC,), data_actions=(TOKEN,)), "u-alice", TID) == {}


def test_console_excludes_no_replica_or_identity_outside_main_lifecycle():
    assert reached(_run(app=_app(replicas=0)), "u-alice", TID) == {}
    assert reached(_run(app=_app(running="Running", replicas=0)), "u-alice", TID) == {}
    assert reached(_run(app=_app(running="Stopped", replicas=1)), "u-alice", TID) == {}
    assert reached(_run(app=_app(lifecycle="None")), "u-alice", TID) == {}
    assert reached(_run(app=_app(lifecycle="Init")), "u-alice", TID) == {}
    graph_identity = {"type": "SystemAssigned", "principalId": "mi-main"}
    graph = [{"id": APP, "type": "Microsoft.App/containerApps", "name": "main",
              "identity": graph_identity, "properties": {}}]
    assert reached(_run(app=_app(principal="mi-other"), graph=graph), "u-alice", TID) == {
        "mi-other": "conditional"}


def test_console_keeps_valid_uai_and_incomplete_revision_unknown():
    assert reached(_run(app=_app(principal="mi-worker", uai=True), uai=True), "u-alice", TID) == {
        "mi-worker": "conditional"}
    assert reached(_run(app=_app(principal="mi-worker", uai=True), graph=[], uai=True),
                   "u-alice", TID) == {"mi-worker": "conditional"}
    assert set(reached(_run(app=_app(replicas=None)), "u-alice", TID).values()) == {"unknown"}
    assert set(reached(_run(runtime_status="denied"), "u-alice", TID).values()) == {"unknown"}
    missing_principal = _app()
    missing_principal["identity"].pop("principalId")
    graph = [{"id": APP, "type": "Microsoft.App/containerApps", "name": "main",
              "identity": {"type": "SystemAssigned", "principalId": "mi-main"}, "properties": {}}]
    assert set(reached(_run(app=missing_principal, graph=graph), "u-alice", TID).values()) == {
        "unknown"}


def test_permissions_split_across_apps_do_not_form_a_console_path():
    graph = [{"id": app_id, "type": "Microsoft.App/containerApps",
              "identity": {"type": "SystemAssigned", "principalId": "mi-main"}, "properties": {}}
             for app_id in (APP, OTHER)]
    one = _app(APP)
    other = _app(OTHER)
    extra = [("container_app_runtime", SUB, [one, other], "collected")]
    snap = az([("u-alice", "User", APP, ROLE_ID),
               ("u-alice", "User", OTHER, "22222222-2222-2222-2222-222222222222")],
              roles={ROLE_ID: ([TOKEN], []),
                     "22222222-2222-2222-2222-222222222222": ([], [EXEC])},
              graph=graph, extra=extra)
    assert reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)]), "u-alice", TID) == {}


def test_native_projection_rejects_foreign_revision_and_does_not_store_template():
    path = Path(__file__).resolve().parents[1] / "peaso/collectors/azure_containerapp_runtime.py"
    spec = importlib.util.spec_from_file_location("azure_containerapp_runtime_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    app = _app()
    app["properties"]["template"] = {"containers": [{"env": [{"name": "SECRET", "value": "private"}]}]}
    revision = {"id": APP + "/revisions/rev1", "properties": {"active": True,
                "runningState": "Running", "replicas": 1, "template": app["properties"]["template"]}}
    projected = module._project(app, [revision], APP)
    assert "private" not in repr(projected)
    assert projected["revisions"][0]["properties"]["replicas"] == 1
    with pytest.raises(ValueError):
        module._project(app, [{**revision, "id": OTHER + "/revisions/rev1"}], APP)


def test_native_collection_lists_apps_then_reads_each_app_and_its_revisions():
    path = Path(__file__).resolve().parents[1] / "peaso/collectors/azure_containerapp_runtime.py"
    spec = importlib.util.spec_from_file_location("azure_containerapp_runtime_collect_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    app = _app()
    calls = []

    class Reader:
        def __init__(self):
            self.collections = []

        def call(self, request, url):
            calls.append(url)
            assert url == module.ARM + APP + "?api-version=" + module.VERSION
            return app

        def pages(self, request, url):
            calls.append(url)
            if url == module.ARM + SUB + "/providers/Microsoft.App/containerApps?api-version=" + module.VERSION:
                yield [{"id": APP, "type": "Microsoft.App/containerApps"}]
            elif url == module.ARM + APP + "/revisions?api-version=" + module.VERSION:
                yield app["revisions"]
            else:
                raise AssertionError(url)

        def run(self, jobs):
            for kind, scope, _, fetch in jobs:
                rows = [row for page in fetch() for row in page]
                self.collections.append({"type": kind, "scope": scope,
                                         "status": "collected" if rows else "empty", "items": rows})

    reader = Reader()
    module.collect(reader, None, [SUB], {module.KIND})
    assert len(calls) == 3
    assert reader.collections[0]["items"][0]["revisions"][0]["properties"]["replicas"] == 1
    assert reader.collections[0]["items"][0]["identity"]["principalId"] == "mi-main"
