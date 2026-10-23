"""Publishing credentials require an enabled policy on the identity's own app."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-appservice-publishing-credentials-basic-auth-enabled"
APP = f"{RG}/providers/Microsoft.Web/sites/app"
OTHER = f"{RG}/providers/Microsoft.Web/sites/other"
PUBLISH_XML = "Microsoft.Web/sites/publishxml/action"
CONFIG_LIST = "Microsoft.Web/sites/config/list/action"
START = "Microsoft.Web/sites/start/action"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _run(*, policy=True, policy_present=True, grant=APP, identity_host=APP,
         actions=(PUBLISH_XML,), kind="app,linux", state="Running",
         linux_fx=None, include_unknown=False):
    apps = [{"id": APP, "type": "Microsoft.Web/sites", "name": "app", "kind": kind,
             "properties": {"state": state}},
            {"id": OTHER, "type": "Microsoft.Web/sites", "name": "other", "kind": "app,linux"}]
    next(app for app in apps if app["id"] == identity_host)["identity"] = {"principalId": "mi-app"}
    if policy_present:
        apps[0]["scmBasicAuthPolicy"] = {"properties": {"allow": policy}}
    extra = [("app_service", SUB, apps)]
    if linux_fx is not None:
        extra.append(("app_service_config", APP, [{"id": APP + "/config/web",
            "parent_id": APP, "type": "Microsoft.Web/sites/config",
            "properties": {"linuxFxVersion": linux_fx}}]))
    snap = az([("u-alice", "User", grant, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=apps, extra=extra)
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=include_unknown)


def test_each_credential_read_route_on_exact_enabled_app():
    assert validate_entry(ENTRY)[0] == []
    for action in (PUBLISH_XML, CONFIG_LIST):
        assert reached(_run(actions=(action,)), "u-alice", TID) == {"mi-app": "conditional"}


def test_disabled_policy_or_wrong_identity_host_has_no_path():
    assert "mi-app" not in reached(_run(policy=False), "u-alice", TID)
    assert "mi-app" not in reached(_run(identity_host=OTHER), "u-alice", TID)


def test_missing_policy_and_custom_container_remain_unresolved():
    for result in (_run(policy_present=False, include_unknown=True),
                   _run(linux_fx="DOCKER|example/image", include_unknown=True)):
        reached_targets = reached(result, "u-alice", TID)
        assert "mi-app" not in reached_targets
        assert "unknown" in reached_targets.values()


def test_stopped_app_requires_start_permission():
    assert "mi-app" not in reached(_run(state="Stopped"), "u-alice", TID)
    assert reached(_run(state="Stopped", actions=(PUBLISH_XML, START)), "u-alice", TID) == {
        "mi-app": "conditional"}
