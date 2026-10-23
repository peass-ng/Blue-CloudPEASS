"""Agent blueprint credentials reach only the blueprint principal and its children."""
from __future__ import annotations

from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T, az


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_apps.yaml").read_text())
    if row["id"] == "azure-entraid-agent-blueprint-credentials")
BLUEPRINT_A = "app-blueprint-a"
BLUEPRINT_B = "app-blueprint-b"


def _inventory(*, app_permission="AgentIdentityBlueprint.AddRemoveCreds.All", role_scope=None,
               agents_status="collected", first_child_blueprint=BLUEPRINT_A,
               first_principal_enabled=True, duplicate_app=False):
    blueprints = [
        {"id": "blueprint-a", "appId": BLUEPRINT_A},
        {"id": "blueprint-b", "appId": BLUEPRINT_B},
    ]
    if duplicate_app:
        blueprints.append({"id": "blueprint-a-duplicate", "appId": BLUEPRINT_A})
    principals = [
        {"id": "sp-blueprint-a", "appId": BLUEPRINT_A,
         "accountEnabled": first_principal_enabled},
        {"id": "sp-blueprint-b", "appId": BLUEPRINT_B, "accountEnabled": True},
    ]
    agents = [
        {"id": "sp-agent-a", "appId": "agent-a", "agentIdentityBlueprintId": first_child_blueprint,
         "accountEnabled": True},
        {"id": "sp-agent-b", "appId": "agent-b", "agentIdentityBlueprintId": BLUEPRINT_B,
         "accountEnabled": True},
    ]
    extra = [
        ("directory_agent_blueprint", T, blueprints),
        ("directory_agent_blueprint_principal", T, principals),
        ("directory_agent_identity", T, agents if agents_status == "collected" else [], agents_status),
        ("directory_app_role_assignment", T,
         [{"id": "grant-a", "principalId": "sp-source", "resourceId": "sp-graph",
           "appRoleValue": app_permission, "appRoleEnabled": True}]
         if app_permission else [], "collected" if app_permission else "empty"),
    ]
    snap = az(sps=("sp-source", "sp-graph", "sp-blueprint-a", "sp-blueprint-b", "sp-agent-a", "sp-agent-b"),
              extra=extra)
    graph_sp = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    next(row for row in graph_sp["items"] if row["id"] == "sp-graph")["appId"] = \
        "00000003-0000-0000-c000-000000000000"
    if role_scope is not None:
        snap["collections"].append({"type": "directory_role_definition", "scope": T,
            "service": "Microsoft.Graph", "status": "collected", "items": [
                {"id": "role-agent-admin", "displayName": "Agent ID Administrator",
                 "rolePermissions": [{"allowedResourceActions": [
                     "microsoft.directory/agentIdentityBlueprints/credentials/update"]}]}]})
        snap["collections"].append({"type": "directory_role_assignment", "scope": T,
            "service": "Microsoft.Graph", "status": "collected", "items": [
                {"id": "role-grant", "principalId": "u-alice", "roleDefinitionId": "role-agent-admin",
                 "directoryScopeId": role_scope}]})
    return snap


def _reached(snap, source="sp-source"):
    return reached(privesc.analyze(snap, entries=[ENTRY]), source, ENTRY["id"])


def test_app_permission_reaches_exact_blueprint_principals_and_children():
    assert validate_entry(ENTRY)[0] == []
    expected = {id_: "conditional" for id_ in
                ("sp-blueprint-a", "sp-blueprint-b", "sp-agent-a", "sp-agent-b")}
    assert _reached(_inventory()) == expected
    assert _reached(_inventory(app_permission="AgentIdentityBlueprint.ReadWrite.All")) == expected


def test_directory_role_scope_reaches_only_that_blueprint_and_child():
    result = _reached(_inventory(app_permission="", role_scope="/blueprint-a"), "u-alice")
    assert result == {"sp-blueprint-a": "conditional", "sp-agent-a": "conditional"}
    result = _reached(_inventory(app_permission="", role_scope="/blueprint-b"), "u-alice")
    assert result == {"sp-blueprint-b": "conditional", "sp-agent-b": "conditional"}
    assert _reached(_inventory(app_permission="", role_scope="/unrelated"), "u-alice") == {}


def test_user_owner_reaches_only_owned_blueprint_and_its_child():
    snap = _inventory(app_permission="")
    snap["collections"].append({"type": "directory_owner", "scope": T,
        "service": "Microsoft.Graph", "status": "collected", "items": [
            {"objectId": "blueprint-a", "objectType": "application", "ownerIds": ["u-alice"]}]})
    assert _reached(snap, "u-alice") == {
        "sp-blueprint-a": "conditional", "sp-agent-a": "conditional"}
    snap["collections"][-1]["items"][0]["objectId"] = "unrelated-app"
    assert _reached(snap, "u-alice") == {}


def test_cross_blueprint_disabled_duplicate_and_missing_child_inventory():
    assert "sp-agent-a" not in _reached(_inventory(first_child_blueprint="unknown"))
    assert "sp-blueprint-a" not in _reached(_inventory(first_principal_enabled=False))
    assert "sp-agent-a" not in _reached(_inventory(first_principal_enabled=False))
    assert "sp-blueprint-a" not in _reached(_inventory(duplicate_app=True))
    assert "sp-agent-a" not in _reached(_inventory(duplicate_app=True))
    result = _reached(_inventory(agents_status="access_denied"))
    assert "sp-blueprint-a" in result and "sp-agent-a" not in result
    snap = _inventory()
    agent = next(c for c in snap["collections"] if c["type"] == "directory_agent_identity")
    agent["items"][0]["accountEnabled"] = False
    assert "sp-agent-a" not in _reached(snap)
    snap = _inventory()
    blueprint = next(c for c in snap["collections"] if c["type"] == "directory_agent_blueprint")
    blueprint["status"] = "access_denied"
    assert _reached(snap) == {}


def test_missing_source_permission_does_not_reach_blueprint():
    assert _reached(_inventory(app_permission="")) == {}
    snap = _inventory()
    grant = next(c for c in snap["collections"] if c["type"] == "directory_app_role_assignment")
    grant["items"][0]["resourceId"] = "sp-blueprint-a"
    assert _reached(snap) == {}
    grant["items"][0]["resourceId"] = "sp-graph"
    grant["items"][0]["appRoleEnabled"] = False
    assert _reached(snap) == {}
