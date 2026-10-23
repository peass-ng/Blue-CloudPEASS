"""App-scoped Entra credential roles must name the application object, not its SP."""
from __future__ import annotations

from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T, az


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_apps.yaml").read_text())
    if row["id"] == "azure-entraid-app-credentials-update")
ACTION = "microsoft.directory/applications/credentials/update"
ALL_PROPERTIES = "microsoft.directory/applications/allProperties/update"


def _inventory(*, role_scope="/app-a", action=ACTION, applications=None, app_status="collected"):
    applications = applications if applications is not None else [
        {"id": "app-a", "appId": "client-a", "signInAudience": "AzureADMyOrg"},
        {"id": "app-b", "appId": "client-b", "signInAudience": "AzureADMultipleOrgs"},
    ]
    snap = az(sps=("sp-a", "sp-b", "sp-external"), extra=[
        ("directory_application", T, applications, app_status),
    ])
    sp = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    for row in sp["items"]:
        row["appId"] = {"sp-a": "client-a", "sp-b": "client-b",
                        "sp-external": "client-external"}[row["id"]]
        row["accountEnabled"] = True
    role = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    role.update(status="collected", items=[{"id": "role-app-credentials",
        "displayName": "App credentials", "rolePermissions": [{"allowedResourceActions": [action]}]}])
    assignment = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    assignment.update(status="collected", items=[{"id": "role-grant", "principalId": "u-alice",
        "roleDefinitionId": "role-app-credentials", "directoryScopeId": role_scope}])
    return snap


def _reached(snap):
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", ENTRY["id"])


def test_exact_app_scope_reaches_only_matching_local_app_service_principal():
    assert validate_entry(ENTRY)[0] == []
    assert _reached(_inventory()) == {"sp-a": "conditional"}
    assert _reached(_inventory(role_scope="/app-b")) == {"sp-b": "conditional"}
    assert _reached(_inventory(role_scope="/")) == {
        "sp-a": "conditional", "sp-b": "conditional"}


def test_service_principal_scope_unrelated_app_and_missing_local_app_are_excluded():
    assert _reached(_inventory(role_scope="/sp-a")) == {}
    assert _reached(_inventory(role_scope="/unrelated")) == {}
    assert _reached(_inventory(applications=[{"id": "app-b", "appId": "client-b"}])) == {}
    assert _reached(_inventory(applications=[], app_status="empty")) == {}


def test_disabled_service_principal_is_not_a_credential_takeover_target():
    snap = _inventory()
    sp = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    next(row for row in sp["items"] if row["id"] == "sp-a")["accountEnabled"] = False
    assert _reached(snap) == {}
    snap = _inventory()
    sp = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    next(row for row in sp["items"] if row["id"] == "sp-a")["servicePrincipalType"] = "ManagedIdentity"
    assert _reached(snap) == {}


def test_all_properties_can_update_credentials_but_unrelated_property_cannot():
    assert _reached(_inventory(action=ALL_PROPERTIES)) == {"sp-a": "conditional"}
    assert _reached(_inventory(action="microsoft.directory/applications/basic/update")) == {}


def test_directory_role_alone_does_not_grant_an_app_only_graph_call():
    snap = _inventory()
    assignment = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    assignment["items"][0]["principalId"] = "sp-a"
    assert reached(privesc.analyze(snap, entries=[ENTRY]), "sp-a", ENTRY["id"]) == {}
