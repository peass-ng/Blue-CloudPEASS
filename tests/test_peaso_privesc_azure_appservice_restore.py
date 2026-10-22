"""Backup restore needs an eligible exact app and a plausible code path."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-appservice-restore-from-backup-blob"
APP = f"{RG}/providers/Microsoft.Web/sites/app"
OTHER = f"{RG}/providers/Microsoft.Web/sites/other"
PLAN = f"{RG}/providers/Microsoft.Web/serverfarms/plan"
RESTORE = "Microsoft.Web/sites/restoreFromBackupBlob/action"
START = "Microsoft.Web/sites/start/action"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _run(*, tier="Basic", kind="app,linux", state="Running", grant=APP,
         identity_host=APP, plan_present=True, linux_fx=None, actions=(RESTORE,),
         include_unknown=False):
    apps = [{"id": APP, "type": "Microsoft.Web/sites", "name": "app", "kind": kind,
             "properties": {"state": state, "serverFarmId": PLAN}},
            {"id": OTHER, "type": "Microsoft.Web/sites", "name": "other", "kind": "app,linux",
             "properties": {"serverFarmId": PLAN}}]
    next(app for app in apps if app["id"] == identity_host)["identity"] = {"principalId": "mi-app"}
    extra = [("app_service", SUB, apps)]
    if plan_present:
        extra.append(("app_service_plan", SUB, [{"id": PLAN,
            "type": "Microsoft.Web/serverfarms", "sku": {"tier": tier}}]))
    if linux_fx is not None:
        extra.append(("app_service_config", APP, [{"id": APP + "/config/web",
            "parent_id": APP, "type": "Microsoft.Web/sites/config",
            "properties": {"linuxFxVersion": linux_fx}}]))
    snap = az([("u-alice", "User", grant, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=apps, extra=extra)
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=include_unknown)


def test_supported_web_and_dedicated_function_plans_are_conditional():
    assert validate_entry(ENTRY)[0] == []
    for tier, kind in (("Basic", "app,linux"), ("PremiumV3", "app"),
                       ("Standard", "functionapp"), ("IsolatedV2", "functionapp,linux")):
        assert reached(_run(tier=tier, kind=kind), "u-alice", TID) == {
            "mi-app": "conditional"}


def test_unsupported_tiers_and_wrong_identity_host_do_not_escalate():
    for tier in ("Free", "Shared", "Dynamic", "FlexConsumption", "ElasticPremium"):
        assert "mi-app" not in reached(_run(tier=tier), "u-alice", TID)
    assert "mi-app" not in reached(_run(identity_host=OTHER), "u-alice", TID)


def test_missing_plan_and_container_execution_remain_unresolved():
    for result in (_run(plan_present=False, include_unknown=True),
                   _run(linux_fx="DOCKER|example/image", include_unknown=True)):
        targets = reached(result, "u-alice", TID)
        assert "mi-app" not in targets
        assert "unknown" in targets.values()


def test_stopped_app_needs_start_permission():
    assert "mi-app" not in reached(_run(state="Stopped"), "u-alice", TID)
    assert reached(_run(state="Stopped", actions=(RESTORE, START)), "u-alice", TID) == {
        "mi-app": "conditional"}
