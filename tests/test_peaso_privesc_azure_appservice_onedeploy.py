"""OneDeploy maps only an executable package path on the identity's site."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-appservice-onedeploy-extensions-write"
APP = f"{RG}/providers/Microsoft.Web/sites/app"
OTHER = f"{RG}/providers/Microsoft.Web/sites/other"
DEPLOY = "Microsoft.Web/sites/extensions/write"
START = "Microsoft.Web/sites/start/action"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _run(*, kind="app,linux", state="Running", grant=APP,
         identity_host=APP, actions=(DEPLOY,), include_unknown=False,
         linux_fx=None):
    apps = [{"id": APP, "type": "Microsoft.Web/sites", "name": "app", "kind": kind,
             "properties": {"state": state}},
            {"id": OTHER, "type": "Microsoft.Web/sites", "name": "other", "kind": "app,linux"}]
    next(app for app in apps if app["id"] == identity_host)["identity"] = {"principalId": "mi-app"}
    extra = [("app_service", SUB, apps)]
    if linux_fx is not None:
        extra.append(("app_service_config", APP, [{"id": APP + "/config/web",
            "parent_id": APP, "type": "Microsoft.Web/sites/config",
            "properties": {"linuxFxVersion": linux_fx}}]))
    snap = az([("u-alice", "User", grant, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=apps, extra=extra)
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=include_unknown)


def test_onedeploy_for_exact_code_app_is_conditional():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-app": "conditional"}
    assert reached(_run(grant=APP + "/extensions/onedeploy"), "u-alice", TID) == {
        "mi-app": "conditional"}


def test_flex_function_onedeploy_is_kept_even_without_kudu_advanced_tools():
    assert reached(_run(kind="functionapp,linux"), "u-alice", TID) == {
        "mi-app": "conditional"}


def test_wrong_site_or_extension_child_cannot_reach_identity():
    for result in (_run(identity_host=OTHER), _run(grant=APP + "/extensions/other")):
        assert "mi-app" not in reached(result, "u-alice", TID)


def test_custom_container_package_execution_stays_unresolved():
    result = reached(_run(kind="app,linux,container", include_unknown=True), "u-alice", TID)
    assert "mi-app" not in result
    assert any(value == "unknown" for value in result.values())
    result = reached(_run(linux_fx="DOCKER|example/image", include_unknown=True), "u-alice", TID)
    assert "mi-app" not in result
    assert any(value == "unknown" for value in result.values())


def test_stopped_app_needs_start_permission():
    assert "mi-app" not in reached(_run(state="Stopped"), "u-alice", TID)
    assert reached(_run(state="Stopped", actions=(DEPLOY, START)), "u-alice", TID) == {
        "mi-app": "conditional"}
