"""Site extension installation must reach code on the identity's Windows app."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-appservice-siteextensions-write"
APP = f"{RG}/providers/Microsoft.Web/sites/app"
OTHER = f"{RG}/providers/Microsoft.Web/sites/other"
WRITE = "Microsoft.Web/sites/siteextensions/write"
START = "Microsoft.Web/sites/start/action"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _run(*, kind="app", state="Running", grant=APP, identity_host=APP,
         actions=(WRITE,), include_unknown=False):
    apps = [{"id": APP, "type": "Microsoft.Web/sites", "name": "app", "kind": kind,
             "properties": {"state": state}},
            {"id": OTHER, "type": "Microsoft.Web/sites", "name": "other", "kind": "app"}]
    next(app for app in apps if app["id"] == identity_host)["identity"] = {"principalId": "mi-app"}
    snap = az([("u-alice", "User", grant, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=apps, extra=[("app_service", SUB, apps)])
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=include_unknown)


def test_site_level_write_on_exact_windows_app_is_conditional():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-app": "conditional"}
    assert reached(_run(kind="functionapp"), "u-alice", TID) == {"mi-app": "conditional"}


def test_wrong_app_and_linux_or_container_app_are_not_paths():
    for result in (_run(identity_host=OTHER), _run(grant=OTHER),
                   _run(kind="app,linux"), _run(kind="app,container")):
        assert "mi-app" not in reached(result, "u-alice", TID)


def test_named_child_grant_stays_unresolved_without_package_control():
    targets = reached(_run(grant=APP + "/siteextensions/specific-package",
                           include_unknown=True), "u-alice", TID)
    assert "mi-app" not in targets
    assert "unknown" in targets.values()


def test_stopped_app_needs_start_permission():
    assert "mi-app" not in reached(_run(state="Stopped"), "u-alice", TID)
    assert reached(_run(state="Stopped", actions=(WRITE, START)), "u-alice", TID) == {
        "mi-app": "conditional"}
