"""Self-granted Graph authorization must expose a real directory-role path."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T, az


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_apps.yaml").read_text())
    if row["id"] == "azure-entraid-graph-approleassignment-readwrite-all")
GRAPH = "00000003-0000-0000-c000-000000000000"


def _snapshot(*, read_permission="Application.Read.All", role_enabled=True,
              role_members=("Application",), grant_resource="sp-graph"):
    snap = az(sps=("sp-source", "sp-graph"), extra=[("directory_app_role_assignment", T, [
        {"id": "grant-write", "principalId": "sp-source", "resourceId": grant_resource,
         "appRoleValue": "AppRoleAssignment.ReadWrite.All", "appRoleEnabled": True},
        {"id": "grant-read", "principalId": "sp-source", "resourceId": "sp-graph",
         "appRoleValue": read_permission, "appRoleEnabled": True}])])
    principals = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    for row in principals["items"]:
        row.update(appId=GRAPH if row["id"] == "sp-graph" else "source-app", accountEnabled=True)
    graph = next(row for row in principals["items"] if row["id"] == "sp-graph")
    graph["appRoles"] = [{"id": "role-rw", "value": "RoleManagement.ReadWrite.Directory",
                          "isEnabled": role_enabled, "allowedMemberTypes": list(role_members)}]
    definitions = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    definitions.update(status="collected", items=[{"id": "role-global", "templateId": "role-global",
        "displayName": "Global Administrator", "isBuiltIn": True, "rolePermissions": []}])
    return snap


def _targets(snap):
    return reached(privesc.analyze(snap, entries=[ENTRY]), "sp-source", ENTRY["id"])


def test_exact_graph_grants_and_enabled_target_role_reach_existing_directory_role():
    assert validate_entry(ENTRY)[0] == []
    assert _targets(_snapshot()).get("entra_role:role-global") == "conditional"
    assert _targets(_snapshot(read_permission="Directory.Read.All")).get("entra_role:role-global") == "conditional"


def test_missing_read_grant_wrong_resource_or_disabled_graph_role_excludes_edge():
    assert _targets(_snapshot(read_permission="Mail.Read")) == {}
    assert _targets(_snapshot(grant_resource="sp-source")) == {}
    assert _targets(_snapshot(role_enabled=False)) == {}
    assert _targets(_snapshot(role_members=("User",))) == {}


def test_missing_role_definition_or_disabled_source_excludes_named_edge():
    snap = _snapshot()
    definitions = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    definitions.update(status="access_denied", items=[])
    assert "entra_role:role-global" not in _targets(snap)
    snap = _snapshot()
    principals = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    next(row for row in principals["items"] if row["id"] == "sp-source")["accountEnabled"] = False
    assert _targets(snap) == {}
