"""Graph app write grants need the real Graph resource and a usable app target."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_azure_app_credentials_update import _inventory


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_apps.yaml").read_text())
    if row["id"] == "azure-entraid-graph-application-readwrite-all")


def _snapshot(*, resource="sp-graph", enabled=True, permission="Application.ReadWrite.All"):
    snap = _inventory()
    principals = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    principals["items"].extend([
        {"id": "sp-source", "appId": "client-source", "servicePrincipalType": "Application", "accountEnabled": True},
        {"id": "sp-graph", "appId": "00000003-0000-0000-c000-000000000000",
         "servicePrincipalType": "Application", "accountEnabled": True}])
    snap["collections"].append({"type": "directory_app_role_assignment", "scope": "/tenants/t",
        "service": "Microsoft.Graph", "status": "collected", "items": [{"id": "grant", "principalId": "sp-source",
            "resourceId": resource, "appRoleValue": permission, "appRoleEnabled": enabled}]})
    return snap


def _targets(snap):
    return reached(privesc.analyze(snap, entries=[ENTRY]), "sp-source", ENTRY["id"])


def test_enabled_graph_app_role_reaches_local_apps_only():
    assert validate_entry(ENTRY)[0] == []
    found = _targets(_snapshot())
    assert found.get("sp-a") == "conditional"
    assert found.get("sp-b") == "conditional"
    assert "sp-external" not in found


def test_wrong_resource_disabled_or_unrelated_permission_does_not_reach():
    assert _targets(_snapshot(resource="sp-a")) == {}
    assert _targets(_snapshot(enabled=False)) == {}
    assert _targets(_snapshot(permission="Application.Read.All")) == {}
    snap = _snapshot()
    principals = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    principals["items"] = [row for row in principals["items"] if row["id"] != "sp-graph"]
    principals["status"] = "partial"
    assert not any(target in _targets(snap) for target in ("sp-a", "sp-b"))


def test_disabled_target_or_source_and_incomplete_app_inventory():
    snap = _snapshot()
    principals = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    next(row for row in principals["items"] if row["id"] == "sp-a")["accountEnabled"] = False
    assert "sp-a" not in _targets(snap)
    next(row for row in principals["items"] if row["id"] == "sp-source")["accountEnabled"] = False
    assert _targets(snap) == {}
    snap = _snapshot()
    app = next(c for c in snap["collections"] if c["type"] == "directory_application")
    app.update(status="access_denied", items=[])
    assert not any(target in _targets(snap) for target in ("sp-a", "sp-b", "sp-external"))
