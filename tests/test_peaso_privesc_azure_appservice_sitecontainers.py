"""SiteContainer writes require the target app's active sidecar mode."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-appservice-sitecontainers-write"
APP = f"{RG}/providers/Microsoft.Web/sites/app"
OTHER = f"{RG}/providers/Microsoft.Web/sites/other"
WRITE = "Microsoft.Web/sites/sitecontainers/write"
START = "Microsoft.Web/sites/start/action"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _run(*, mode="sitecontainers", embedded=True, typed=False, kind="app,linux,container",
         grant=APP, identity_host=APP, state="Running", actions=(WRITE,),
         include_unknown=False, typed_mode=None):
    apps = [{"id": APP, "type": "Microsoft.Web/sites", "name": "app", "kind": kind,
             "properties": {"state": state}},
            {"id": OTHER, "type": "Microsoft.Web/sites", "name": "other", "kind": "app,linux"}]
    next(app for app in apps if app["id"] == identity_host)["identity"] = {"principalId": "mi-app"}
    if embedded and mode is not None:
        apps[0]["configuration"] = {"properties": {"linuxFxVersion": mode}}
    extra = [("app_service", SUB, apps)]
    if typed:
        extra.append(("app_service_config", APP, [{"id": APP + "/config/web",
            "parent_id": APP, "type": "Microsoft.Web/sites/config",
            "properties": {"linuxFxVersion": typed_mode if typed_mode is not None else mode}}]))
    snap = az([("u-alice", "User", grant, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=apps, extra=extra)
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=include_unknown)


def test_sitecontainers_mode_allows_parent_and_existing_child_grants():
    assert validate_entry(ENTRY)[0] == []
    for grant in (APP, APP + "/sitecontainers/main"):
        assert reached(_run(grant=grant), "u-alice", TID) == {"mi-app": "conditional"}
    assert reached(_run(embedded=False, typed=True), "u-alice", TID) == {
        "mi-app": "conditional"}


def test_other_app_classic_docker_and_windows_are_not_paths():
    for result in (_run(identity_host=OTHER), _run(grant=OTHER),
                   _run(mode="DOCKER|example/image"), _run(kind="app,container")):
        assert "mi-app" not in reached(result, "u-alice", TID)


def test_missing_or_conflicting_runtime_mode_is_unresolved():
    for result in (_run(mode=None, include_unknown=True),
                   _run(typed=True, typed_mode="DOCKER|example/image", include_unknown=True)):
        targets = reached(result, "u-alice", TID)
        assert "mi-app" not in targets
        assert "unknown" in targets.values()


def test_stopped_app_requires_start_permission():
    assert "mi-app" not in reached(_run(state="Stopped"), "u-alice", TID)
    assert reached(_run(state="Stopped", actions=(WRITE, START)), "u-alice", TID) == {
        "mi-app": "conditional"}
