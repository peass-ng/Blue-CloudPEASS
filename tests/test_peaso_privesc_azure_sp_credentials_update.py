"""Service-principal credentials require an authorized caller and a usable target."""
from __future__ import annotations

from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_azure_app_credentials_update import _inventory
from tests.test_peaso_privesc_schema_ext_azure import T


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_apps.yaml").read_text())
    if row["id"] == "azure-entraid-sp-credentials-update")
ACTION = "microsoft.directory/servicePrincipals/credentials/update"


def _reached(snap, source="u-alice"):
    return reached(privesc.analyze(snap, entries=[ENTRY]), source, ENTRY["id"])


def _sp_collection(snap):
    return next(c for c in snap["collections"] if c["type"] == "directory_service_principal")


def test_object_scope_and_tenant_scope():
    assert validate_entry(ENTRY)[0] == []
    assert _reached(_inventory(action=ACTION, role_scope="/sp-a")) == {"sp-a": "conditional"}
    assert _reached(_inventory(action=ACTION, role_scope="/")) == {
        "sp-a": "conditional", "sp-b": "conditional", "sp-external": "conditional"}
    assert _reached(_inventory(action=ACTION, role_scope="/app-a")) == {}


def test_disabled_target_source_and_managed_identity_do_not_reach():
    snap = _inventory(action=ACTION, role_scope="/sp-a")
    next(row for row in _sp_collection(snap)["items"] if row["id"] == "sp-a")["accountEnabled"] = False
    assert _reached(snap) == {}
    snap = _inventory(action=ACTION, role_scope="/sp-a")
    next(row for row in _sp_collection(snap)["items"] if row["id"] == "sp-a")["servicePrincipalType"] = "ManagedIdentity"
    assert _reached(snap) == {}
    snap = _inventory(action=ACTION, role_scope="/sp-a")
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")
    users["items"][0]["accountEnabled"] = False
    assert _reached(snap) == {}


def test_home_application_credential_lock():
    snap = _inventory(action=ACTION, role_scope="/sp-a")
    app = next(c for c in snap["collections"] if c["type"] == "directory_application")
    app["items"][0]["servicePrincipalLockConfiguration"] = {
        "isEnabled": True, "credentialsWithUsageVerify": True}
    assert _reached(snap) == {}
    app["items"][0]["servicePrincipalLockConfiguration"]["isEnabled"] = False
    assert _reached(snap) == {"sp-a": "conditional"}


def test_app_only_directory_role_needs_graph_application_permission():
    snap = _inventory(action=ACTION, role_scope="/sp-b")
    assignment = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    assignment["items"][0]["principalId"] = "sp-a"
    grant = {"type": "directory_app_role_assignment", "scope": T,
             "status": "empty", "items": []}
    snap["collections"].append(grant)
    assert _reached(snap, "sp-a") == {}
    _sp_collection(snap)["items"].append({"id": "graph-sp", "appId":
        "00000003-0000-0000-c000-000000000000", "servicePrincipalType": "Application",
        "accountEnabled": True})
    grant["status"] = "collected"
    grant["items"] = [{"id": "grant-1", "principalId": "sp-a", "resourceId": "graph-sp",
                       "appRoleValue": "Application.ReadWrite.All", "appRoleEnabled": True}]
    assert _reached(snap, "sp-a").get("sp-b") == "conditional"
    assignment["items"] = []
    assert _reached(snap, "sp-a").get("sp-b") == "conditional"
    grant["items"][0]["appRoleValue"] = "Directory.ReadWrite.All"
    assert _reached(snap, "sp-a").get("sp-b") == "conditional"
    grant["items"][0]["appRoleValue"] = "Application.Read.All"
    assert _reached(snap, "sp-a") == {}
