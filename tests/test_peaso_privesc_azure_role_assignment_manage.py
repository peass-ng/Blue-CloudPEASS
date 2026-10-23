"""Directory role management only reports new, enabled self-grants."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T, az


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_roles.yaml").read_text())
    if row["id"] == "azure-entraid-role-assignment-manage")
ALL_TASKS = "microsoft.directory/roleAssignments/allProperties/allTasks"


def _case(*, source_role="Privileged Role Administrator", action=ALL_TASKS,
          target_role="Global Administrator", target_enabled=True, already=False,
          source_enabled=True, app=False, graph_permission=False, assignment_complete=True):
    snap = az(users=() if app else ("u-source",), sps=("sp-source", "sp-graph") if app else (),
              extra=[("directory_app_role_assignment", T,
                      [{"id": "graph-grant", "principalId": "sp-source", "resourceId": "sp-graph",
                        "appRoleValue": "RoleManagement.ReadWrite.Directory", "appRoleEnabled": True}]
                      if app and graph_permission else [],
                      "collected" if app and graph_permission else "empty")])
    if not app:
        next(c for c in snap["collections"] if c["type"] == "directory_user")["items"][0]["accountEnabled"] = source_enabled
    else:
        service = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
        for row in service["items"]:
            row["accountEnabled"] = source_enabled if row["id"] == "sp-source" else True
            if row["id"] == "sp-graph":
                row["appId"] = "00000003-0000-0000-c000-000000000000"
    defs = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    defs.update(status="collected", items=[{"id": "source-role", "templateId": "source-role",
        "displayName": source_role, "isBuiltIn": True, "isEnabled": True,
        "rolePermissions": [{"allowedResourceActions": [action]}]},
        {"id": "target-role", "templateId": "target-role", "displayName": target_role,
         "isBuiltIn": True, "isEnabled": target_enabled, "rolePermissions": []}])
    ras = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    ras.update(status="collected" if assignment_complete else "partial", items=[
        {"id": "source-assignment", "principalId": "sp-source" if app else "u-source",
         "roleDefinitionId": "source-role", "directoryScopeId": "/"},
        *([{"id": "existing", "principalId": "sp-source" if app else "u-source",
            "roleDefinitionId": "target-role", "directoryScopeId": "/"}] if already else [])])
    return snap


def _targets(snap, *, app=False):
    return reached(privesc.analyze(snap, entries=[ENTRY]), "sp-source" if app else "u-source", ENTRY["id"])


def test_privileged_role_admin_can_assign_new_enabled_role():
    assert validate_entry(ENTRY)[0] == []
    assert _targets(_case()).get("entra_role:target-role") == "derived"


def test_update_only_disabled_redundant_and_global_admin_are_not_escalation():
    assert "entra_role:target-role" not in _targets(_case(source_role="Custom role manager",
        action="microsoft.directory/roleAssignments/allProperties/update"))
    assert "entra_role:target-role" not in _targets(_case(target_enabled=False))
    assert "entra_role:target-role" not in _targets(_case(already=True))
    assert "entra_role:target-role" not in _targets(_case(source_role="Global Administrator",
        target_role="Privileged Role Administrator"))
    assert "entra_role:target-role" not in _targets(_case(source_enabled=False))


def test_application_source_needs_graph_role_management_grant():
    assert "entra_role:target-role" not in _targets(_case(app=True), app=True)
    assert _targets(_case(app=True, graph_permission=True), app=True).get("entra_role:target-role") == "derived"
    snap = _case(app=True)
    next(c for c in snap["collections"] if c["type"] == "directory_app_role_assignment")["status"] = "access_denied"
    assert _targets(snap, app=True).get("entra_role:target-role") == "conditional"


def test_incomplete_assignment_inventory_is_conditional():
    assert _targets(_case(assignment_complete=False)).get("entra_role:target-role") == "conditional"
    snap = _case(source_role="Custom role manager")
    definitions = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    definitions["items"][0]["isBuiltIn"] = False
    assert _targets(snap).get("entra_role:target-role") == "conditional"
