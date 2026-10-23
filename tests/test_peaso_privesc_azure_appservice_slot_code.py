"""Slot code routes must be executable on the slot carrying the identity."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-appservice-slot-code-execution"
APP = f"{RG}/providers/Microsoft.Web/sites/app"
SLOT = APP + "/slots/staging"
OTHER = APP + "/slots/other"
PUBLISH = "Microsoft.Web/sites/slots/publish/action"
SOURCE = "Microsoft.Web/sites/slots/sourcecontrols/write"
CONTAINER = "Microsoft.Web/sites/slots/sitecontainers/write"
CONFIG = "Microsoft.Web/sites/slots/config/write"
START = "Microsoft.Web/sites/slots/start/action"
KEYS = "Microsoft.Web/sites/slots/host/listkeys/action"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _run(*, actions=(PUBLISH,), grant=SLOT, identity_host=SLOT, kind="app,linux",
         state="Running", fx="sitecontainers", include_unknown=False):
    production = {"id": APP, "type": "Microsoft.Web/sites", "name": "app",
                  "kind": "app,linux", "identity": {"principalId": "mi-prod"}}
    slots = [{"id": SLOT, "type": "Microsoft.Web/sites/slots", "name": "app/staging",
              "kind": kind, "properties": {"state": state, "siteConfig": {"linuxFxVersion": fx}}},
             {"id": OTHER, "type": "Microsoft.Web/sites/slots", "name": "app/other",
              "kind": "app,linux", "properties": {"state": "Running"}}]
    next(slot for slot in slots if slot["id"] == identity_host)["identity"] = {
        "principalId": "mi-slot"}
    snap = az([("u-alice", "User", grant, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=[production, *slots], extra=[("app_service", SUB, [production]),
                                                  ("app_service_slot", SUB, slots)])
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=include_unknown)


def test_exact_slot_publish_source_config_and_sitecontainer_routes():
    assert validate_entry(ENTRY)[0] == []
    cases = ((PUBLISH, SLOT), (SOURCE, SLOT + "/sourcecontrols/web"),
             (CONFIG, SLOT + "/config/web"),
             (CONTAINER, SLOT + "/sitecontainers/main"))
    for action, grant in cases:
        assert reached(_run(actions=(action,), grant=grant), "u-alice", TID) == {
            "mi-slot": "conditional"}
    assert reached(_run(actions=(CONFIG,), grant=SLOT + "/config/web", kind="app"),
                   "u-alice", TID) == {"mi-slot": "conditional"}
    assert reached(_run(actions=(CONFIG,), grant=SLOT + "/config/appsettings",
                        kind="functionapp,linux"), "u-alice", TID) == {
        "mi-slot": "conditional"}


def test_other_slot_and_master_key_do_not_prove_code_execution():
    assert "mi-slot" not in reached(_run(identity_host=OTHER), "u-alice", TID)
    assert "mi-slot" not in reached(_run(grant=OTHER), "u-alice", TID)
    assert "mi-slot" not in reached(_run(actions=(KEYS,), kind="functionapp"), "u-alice", TID)
    assert "mi-slot" not in reached(_run(actions=(CONFIG,), grant=SLOT + "/config/appsettings"),
                                    "u-alice", TID)


def test_sitecontainer_mode_and_container_source_control_limitations():
    assert "mi-slot" not in reached(_run(actions=(CONTAINER,), fx="DOCKER|image"),
                                    "u-alice", TID)
    for result in (_run(actions=(CONTAINER,), fx="", include_unknown=True),
                   _run(actions=(SOURCE,), kind="app,linux,container", include_unknown=True)):
        targets = reached(result, "u-alice", TID)
        assert "mi-slot" not in targets
        assert "unknown" in targets.values()


def test_stopped_slot_requires_slot_start_permission():
    assert "mi-slot" not in reached(_run(state="Stopped"), "u-alice", TID)
    assert reached(_run(state="Stopped", actions=(PUBLISH, START)), "u-alice", TID) == {
        "mi-slot": "conditional"}
