"""Config write must reach a code-bearing child of the exact identity host."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-appservice-config-write"
APP = f"{RG}/providers/Microsoft.Web/sites/app"
OTHER = f"{RG}/providers/Microsoft.Web/sites/other"
PLAN = f"{RG}/providers/Microsoft.Web/serverfarms/plan"
WRITE = "Microsoft.Web/sites/config/write"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _run(*, kind="app,linux", assigned_app=APP, grant=APP + "/config/web",
         plan_sku="P1v3", plan_present=True, site_kind=True, function_config=False,
         include_unknown=False):
    app = {"id": APP, "type": "Microsoft.Web/sites", "name": "app",
           "identity": {"principalId": "mi-app"},
           "properties": {"serverFarmId": PLAN}}
    if site_kind:
        app["kind"] = kind
    if function_config:
        app["properties"]["functionAppConfig"] = {"runtime": {"name": "python"}}
    other = {"id": OTHER, "type": "Microsoft.Web/sites", "name": "other", "kind": "app,linux"}
    apps = [app, other]
    if assigned_app == OTHER:
        app.pop("identity")
        other["identity"] = {"principalId": "mi-app"}
    extra = [("app_service", SUB, apps),
             ("app_service_plan", SUB, [{"id": PLAN, "type": "Microsoft.Web/serverfarms",
                                          "sku": {"name": plan_sku, "tier": "FlexConsumption" if plan_sku == "FC1" else "PremiumV3"}}]
              if plan_present else [], "collected" if plan_present else "empty")]
    snap = az([("u-alice", "User", grant, ROLE_ID)], roles={ROLE_ID: ([WRITE], [])},
              graph=apps, extra=extra)
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=include_unknown)


def test_linux_app_config_web_reaches_attached_identity_conditionally():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-app": "conditional"}


def test_wrong_app_and_non_code_config_child_do_not_reach_identity():
    for result in (_run(assigned_app=OTHER), _run(grant=APP + "/config/authsettingsV2")):
        assert "mi-app" not in reached(result, "u-alice", TID)


def test_linux_appsettings_only_is_unresolved_instead_of_assumed_executable():
    result = reached(_run(grant=APP + "/config/appsettings", include_unknown=True), "u-alice", TID)
    assert "mi-app" not in result
    assert any(value == "unknown" for value in result.values())


def test_windows_container_can_replace_image_but_plain_windows_is_unresolved():
    assert reached(_run(kind="app,container,windows"), "u-alice", TID) == {
        "mi-app": "conditional"}
    assert "mi-app" not in reached(_run(kind="app"), "u-alice", TID)


def test_function_package_route_requires_non_flex_plan():
    assert reached(_run(kind="functionapp", grant=APP + "/config/appsettings"), "u-alice", TID) == {
        "mi-app": "conditional"}
    for result in (_run(kind="functionapp", plan_sku="FC1"),
                   _run(kind="functionapp", function_config=True),
                   _run(kind="functionapp", plan_present=False)):
        assert "mi-app" not in reached(result, "u-alice", TID)


def test_unknown_site_kind_does_not_claim_code_execution():
    assert "mi-app" not in reached(_run(site_kind=False), "u-alice", TID)
