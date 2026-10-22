"""Function writes reach only a runnable, writable identity host."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-functions-functions-write"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
APP = f"{RG}/providers/Microsoft.Web/sites/functions-a"
OTHER = f"{RG}/providers/Microsoft.Web/sites/functions-b"
PLAN = f"{RG}/providers/Microsoft.Web/serverfarms/plan"
WRITE = "Microsoft.Web/sites/functions/write"


def _snapshot(*, grant=APP, kind="functionapp", sku="EP1", package=None,
              plan=True, function_config=False, other_identity=False, action=WRITE):
    app = {"id": APP, "type": "Microsoft.Web/sites", "name": "functions-a", "kind": kind,
           "identity": {"principalId": "mi-app"},
           "properties": {"serverFarmId": PLAN}}
    if package is not None:
        app["properties"]["siteConfig"] = {"appSettings": [
            {"name": "WEBSITE_RUN_FROM_PACKAGE", "value": package}]}
    if function_config:
        app["properties"]["functionAppConfig"] = {"runtime": {"name": "python"}}
    other = {"id": OTHER, "type": "Microsoft.Web/sites", "name": "functions-b",
             "kind": "functionapp", "properties": {"serverFarmId": PLAN}}
    if other_identity:
        other["identity"] = app.pop("identity")
    extra = [("app_service", SUB, [app, other]),
             ("app_service_plan", SUB, [{"id": PLAN, "type": "Microsoft.Web/serverfarms",
                                        "sku": {"name": sku,
                                                "tier": "FlexConsumption" if sku == "FC1" else "ElasticPremium"}}]
              if plan else [], "collected" if plan else "empty")]
    return az(assignments=[("u-alice", "User", grant, ROLE_ID)],
              roles={ROLE_ID: ([action], [])}, graph=[app, other], extra=extra)


def _reached(**kwargs):
    return reached(privesc.analyze(_snapshot(**kwargs), entries=[ENTRY]), "u-alice", TID)


def test_exact_function_site_and_child_scope():
    assert validate_entry(ENTRY)[0] == []
    assert _reached() == {"mi-app": "conditional"}
    assert _reached(grant=APP + "/functions/existing") == {"mi-app": "conditional"}
    assert _reached(grant=OTHER) == {}
    assert _reached(grant=APP + "/config/web") == {}


def test_package_flex_and_container_hosts_do_not_use_file_edit_route():
    assert _reached(package="1") == {}
    assert _reached(package="https://example.com/code.zip") == {}
    assert _reached(sku="FC1") == {}
    assert _reached(function_config=True) == {}
    assert _reached(kind="functionapp,container,linux") == {}


def test_unresolved_plan_and_wrong_host_do_not_claim_escalation():
    assert _reached(plan=False) == {}
    assert _reached(grant=APP, other_identity=True) == {}
    assert _reached(kind="app,linux") == {}
