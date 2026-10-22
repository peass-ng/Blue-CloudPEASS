"""Kudu publishing must bind to the identity host and a supported plan."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-appservice-kudu-publish-action"
APP = f"{RG}/providers/Microsoft.Web/sites/app"
OTHER = f"{RG}/providers/Microsoft.Web/sites/other"
PLAN = f"{RG}/providers/Microsoft.Web/serverfarms/plan"
PUBLISH = "Microsoft.Web/sites/publish/action"
START = "Microsoft.Web/sites/start/action"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _run(*, kind="app,linux", grant=APP, identity_host=APP, state="Running",
         sku="P1v3", tier="PremiumV3", plan=True, actions=(PUBLISH,), include_unknown=False):
    apps = [{"id": APP, "type": "Microsoft.Web/sites", "name": "app", "kind": kind,
             "properties": {"serverFarmId": PLAN, "state": state}},
            {"id": OTHER, "type": "Microsoft.Web/sites", "name": "other", "kind": "app,linux",
             "properties": {"serverFarmId": PLAN, "state": "Running"}}]
    next(app for app in apps if app["id"] == identity_host)["identity"] = {"principalId": "mi-app"}
    extra = [("app_service", SUB, apps),
             ("app_service_plan", SUB, [{"id": PLAN, "type": "Microsoft.Web/serverfarms",
                                          "sku": {"name": sku, "tier": tier}}] if plan else [],
              "collected" if plan else "empty")]
    snap = az([("u-alice", "User", grant, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=apps, extra=extra)
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=include_unknown)


def test_publishing_on_exact_running_app_is_conditional():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-app": "conditional"}


def test_publish_permission_on_another_app_cannot_reach_identity():
    assert "mi-app" not in reached(_run(identity_host=OTHER), "u-alice", TID)


def test_linux_functions_consumption_and_flex_have_no_named_kudu_edge():
    for sku, tier in (("Y1", "Dynamic"), ("FC1", "FlexConsumption")):
        assert "mi-app" not in reached(_run(kind="functionapp,linux", sku=sku, tier=tier),
                                       "u-alice", TID)


def test_supported_function_plans_remain_in_scope():
    for kind, sku, tier in (("functionapp,linux", "EP1", "ElasticPremium"),
                            ("functionapp", "Y1", "Dynamic")):
        assert reached(_run(kind=kind, sku=sku, tier=tier), "u-alice", TID) == {
            "mi-app": "conditional"}


def test_stopped_app_needs_start_permission():
    assert "mi-app" not in reached(_run(state="Stopped"), "u-alice", TID)
    assert reached(_run(state="Stopped", actions=(PUBLISH, START)), "u-alice", TID) == {
        "mi-app": "conditional"}


def test_missing_function_plan_is_unresolved():
    result = reached(_run(kind="functionapp,linux", plan=False, include_unknown=True), "u-alice", TID)
    assert "mi-app" not in result
    assert any(value == "unknown" for value in result.values())
