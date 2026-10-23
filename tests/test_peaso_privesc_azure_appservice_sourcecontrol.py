"""Source-control code deployment must target the identity's code app."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-appservice-sourcecontrols-write"
APP = f"{RG}/providers/Microsoft.Web/sites/app"
OTHER = f"{RG}/providers/Microsoft.Web/sites/other"
SOURCE = "Microsoft.Web/sites/sourcecontrols/write"
START = "Microsoft.Web/sites/start/action"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _run(*, grant=APP, kind="app,linux", fx="NODE|22", state="Running",
         actions=(SOURCE,), include_app=True, include_unknown=False):
    app = {"id": APP, "type": "Microsoft.Web/sites", "name": "app", "kind": kind,
           "identity": {"principalId": "mi-app"}, "properties": {"state": state}}
    other = {"id": OTHER, "type": "Microsoft.Web/sites", "name": "other",
             "kind": "app,linux", "identity": {"principalId": "mi-other"}}
    config = {"id": APP + "/config/web", "parent_id": APP,
              "type": "Microsoft.Web/sites/config", "properties": {"linuxFxVersion": fx}}
    snap = az([("u-alice", "User", grant, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=[app, other], extra=[("app_service", SUB, [app, other] if include_app else [other]),
                                          ("app_service_config", SUB, [config])])
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=include_unknown)


def test_parent_and_exact_child_grants_reach_matching_app_only():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-app": "conditional"}
    assert reached(_run(grant=APP + "/sourcecontrols/web"), "u-alice", TID) == {
        "mi-app": "conditional"}
    assert "mi-other" not in reached(_run(), "u-alice", TID)


def test_wrong_child_and_other_app_do_not_authorize_source_control():
    assert "mi-app" not in reached(_run(grant=APP + "/config/web"), "u-alice", TID)
    assert "mi-app" not in reached(_run(grant=OTHER + "/sourcecontrols/web"), "u-alice", TID)


def test_container_runtime_does_not_claim_repository_code_execution():
    for kind, fx in (("app,linux,container", "DOCKER|image"),
                     ("app,linux", "DOCKER|image"), ("app,linux", "sitecontainers")):
        result = reached(_run(kind=kind, fx=fx, include_unknown=True), "u-alice", TID)
        assert result.get("mi-app") != "conditional"
    assert reached(_run(fx="", include_unknown=True), "u-alice", TID).get("mi-app") != "conditional"


def test_stopped_app_needs_start_and_missing_app_inventory_is_unresolved():
    assert reached(_run(state="Stopped", include_unknown=True), "u-alice", TID).get("mi-app") != "conditional"
    assert reached(_run(state="Stopped", actions=(SOURCE, START)), "u-alice", TID) == {
        "mi-app": "conditional"}
    assert reached(_run(include_app=False, include_unknown=True), "u-alice", TID).get("mi-app") != "conditional"
