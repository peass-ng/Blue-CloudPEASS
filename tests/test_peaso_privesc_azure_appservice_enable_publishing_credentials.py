"""Enable SCM auth only on the same app whose credentials can be read."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TID = "azure-appservice-publishing-credentials-enable-basic-auth"
APP = f"{RG}/providers/Microsoft.Web/sites/app"
OTHER = f"{RG}/providers/Microsoft.Web/sites/other"
SCM = APP + "/basicPublishingCredentialsPolicies/scm"
PUBLISH_XML = "Microsoft.Web/sites/publishxml/action"
CONFIG_LIST = "Microsoft.Web/sites/config/list/action"
ENABLE = "Microsoft.Web/sites/basicPublishingCredentialsPolicies/write"
START = "Microsoft.Web/sites/start/action"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _run(*, credentials_at=APP, enable_at=SCM, credential_action=PUBLISH_XML,
         enable=True, policy=False, policy_present=True, identity_host=APP,
         kind="app,linux", state="Running", linux_fx=None, include_unknown=False,
         extra_actions=()):
    apps = [{"id": APP, "type": "Microsoft.Web/sites", "name": "app", "kind": kind,
             "properties": {"state": state}},
            {"id": OTHER, "type": "Microsoft.Web/sites", "name": "other", "kind": "app,linux"}]
    next(app for app in apps if app["id"] == identity_host)["identity"] = {"principalId": "mi-app"}
    if policy_present:
        apps[0]["scmBasicAuthPolicy"] = {"properties": {"allow": policy}}
    assignments = [("u-alice", "User", credentials_at, "creds")]
    roles = {"creds": ([credential_action, *extra_actions], [])}
    if enable:
        assignments.append(("u-alice", "User", enable_at, "policy"))
        roles["policy"] = ([ENABLE], [])
    extra = [("app_service", SUB, apps)]
    if linux_fx is not None:
        extra.append(("app_service_config", APP, [{"id": APP + "/config/web",
            "parent_id": APP, "type": "Microsoft.Web/sites/config",
            "properties": {"linuxFxVersion": linux_fx}}]))
    snap = az(assignments, roles=roles, graph=apps, extra=extra)
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=include_unknown)


def test_exact_child_and_either_credential_action_reach_same_app():
    assert validate_entry(ENTRY)[0] == []
    for credential_action in (PUBLISH_XML, CONFIG_LIST):
        assert reached(_run(credential_action=credential_action), "u-alice", TID) == {
            "mi-app": "conditional"}
    assert reached(_run(enable_at=APP), "u-alice", TID) == {"mi-app": "conditional"}


def test_unrelated_app_or_ftp_child_cannot_enable_scm_for_identity():
    for result in (_run(identity_host=OTHER), _run(credentials_at=OTHER),
                   _run(enable_at=APP + "/basicPublishingCredentialsPolicies/ftp"),
                   _run(enable=False)):
        assert "mi-app" not in reached(result, "u-alice", TID)


def test_already_enabled_routes_to_other_technique_and_missing_policy_can_be_enabled():
    assert "mi-app" not in reached(_run(policy=True), "u-alice", TID)
    assert reached(_run(policy_present=False), "u-alice", TID) == {"mi-app": "conditional"}


def test_custom_container_unresolved_and_stopped_app_needs_start():
    result = reached(_run(linux_fx="DOCKER|example/image", include_unknown=True), "u-alice", TID)
    assert "mi-app" not in result
    assert "unknown" in result.values()
    assert "mi-app" not in reached(_run(state="Stopped"), "u-alice", TID)
    assert reached(_run(state="Stopped", extra_actions=(START,)), "u-alice", TID) == {
        "mi-app": "conditional"}
