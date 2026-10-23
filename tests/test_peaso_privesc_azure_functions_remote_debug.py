"""Remote debugger access needs exact publishing credentials and a supported host."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TID = "azure-functions-remote-debugging"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
APP = f"{RG}/providers/Microsoft.Web/sites/debug-app"
OTHER = f"{RG}/providers/Microsoft.Web/sites/other-app"
PLAN = f"{RG}/providers/Microsoft.Web/serverfarms/plan"
PROFILE = "Microsoft.Web/sites/publishxml/action"
CREDENTIALS = "Microsoft.Web/sites/config/list/action"
CONFIG = "Microsoft.Web/sites/config/write"
ENABLE_SCM = "Microsoft.Web/sites/basicPublishingCredentialsPolicies/write"
START = "Microsoft.Web/sites/start/action"


def _snapshot(*, grants=None, kind="functionapp", tier="ElasticPremium",
              debugging=False, scm=True, state="Running", attached=APP):
    grants = grants if grants is not None else [(PROFILE, APP), (CONFIG, APP)]
    app = {"id": APP, "type": "Microsoft.Web/sites", "kind": kind, "name": "debug-app",
           "properties": {"serverFarmId": PLAN, "state": state},
           "scmBasicAuthPolicy": {"properties": {"allow": scm}}}
    other = {"id": OTHER, "type": "Microsoft.Web/sites", "kind": "functionapp", "name": "other-app",
             "properties": {"serverFarmId": PLAN, "state": "Running"},
             "scmBasicAuthPolicy": {"properties": {"allow": True}}}
    (app if attached == APP else other)["identity"] = {"principalId": "mi-app"}
    assignments = [("u-alice", "User", scope, f"role-{index}")
                   for index, (_, scope) in enumerate(grants)]
    roles = {f"role-{index}": ([action], []) for index, (action, _) in enumerate(grants)}
    extra = [("app_service", SUB, [app, other]),
             ("app_service_plan", SUB, [{"id": PLAN, "type": "Microsoft.Web/serverfarms",
                                        "sku": {"name": "EP1" if tier == "ElasticPremium" else "Y1",
                                                "tier": tier}}]),
             ("app_service_config", APP, [{"id": APP + "/config/web", "parent_id": APP,
                                            "properties": {"remoteDebuggingEnabled": debugging}}])]
    return az(assignments=assignments, roles=roles, graph=[app, other], extra=extra)


def _reached(**kwargs):
    return reached(privesc.analyze(_snapshot(**kwargs), entries=[ENTRY]), "u-alice", TID)


def test_supported_windows_host_with_profile_and_config_write():
    assert validate_entry(ENTRY)[0] == []
    assert _reached() == {"mi-app": "conditional"}
    assert _reached(grants=[(CREDENTIALS, APP + "/config/publishingcredentials"),
                            (CONFIG, APP + "/config/web")]) == {"mi-app": "conditional"}
    assert _reached(grants=[(PROFILE, APP)], debugging=True) == {"mi-app": "conditional"}


def test_wrong_scope_and_missing_configuration_authority():
    assert _reached(grants=[(PROFILE, OTHER), (CONFIG, APP)]) == {}
    assert _reached(grants=[(PROFILE, APP), (CONFIG, OTHER)]) == {}
    assert _reached(grants=[(CREDENTIALS, APP + "/config/appsettings"),
                            (CONFIG, APP)]) == {}
    assert _reached(grants=[(PROFILE, APP)]) == {}
    assert _reached(attached=OTHER) == {}


def test_unsupported_host_or_disabled_scm_basic_auth():
    assert _reached(kind="functionapp,linux") == {}
    assert _reached(kind="functionapp,container,windows") == {}
    assert _reached(tier="Dynamic") == {}
    assert _reached(tier="FlexConsumption") == {}
    assert _reached(scm=False) == {}
    assert _reached(scm=False, grants=[(PROFILE, APP), (CONFIG, APP),
                                         (ENABLE_SCM, APP + "/basicPublishingCredentialsPolicies/scm")]) == {
        "mi-app": "conditional"}
    assert _reached(state="Stopped") == {}
    assert _reached(state="Stopped", grants=[(PROFILE, APP), (CONFIG, APP), (START, APP)]) == {
        "mi-app": "conditional"}
