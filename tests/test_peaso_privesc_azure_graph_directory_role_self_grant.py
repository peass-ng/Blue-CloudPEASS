"""Graph directory-role write reaches only a new, enabled role for the caller."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T, az


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_roles.yaml").read_text())
    if row["id"] == "azure-entraid-graph-rolemanagement-readwrite-directory")
GRAPH = "00000003-0000-0000-c000-000000000000"


def _targets(*, permission=True, role_enabled=True, source_enabled=True,
             already_assigned=False, definition_complete=True, assignment_complete=True,
             graph_resource=True):
    snap = az(sps=("sp-source", "sp-graph"), extra=[("directory_app_role_assignment", T,
        [{"id": "graph-grant", "principalId": "sp-source", "resourceId": "sp-graph",
          "appRoleValue": "RoleManagement.ReadWrite.Directory", "appRoleEnabled": True}] if permission else [])])
    principals = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    for row in principals["items"]:
        row.update(accountEnabled=source_enabled if row["id"] == "sp-source" else True,
                   appId=GRAPH if row["id"] == "sp-graph" and graph_resource else "other-app")
    definitions = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    definitions.update(status="collected" if definition_complete else "denied",
                       items=[{"id": "role-global", "templateId": "role-global",
                               "displayName": "Global Administrator", "isBuiltIn": True,
                               "isEnabled": role_enabled, "rolePermissions": []}] if definition_complete else [])
    assignments = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    assignments.update(status="collected" if already_assigned else "empty" if assignment_complete else "denied",
                       items=[{"id": "existing", "principalId": "sp-source", "roleDefinitionId": "role-global",
                               "directoryScopeId": "/"}] if already_assigned else [])
    return reached(privesc.analyze(snap, entries=[ENTRY]), "sp-source", ENTRY["id"])


def test_graph_role_write_can_assign_enabled_role_to_own_service_principal():
    assert validate_entry(ENTRY)[0] == []
    assert _targets().get("entra_role:role-global") == "derived"


def test_graph_role_write_excludes_invalid_or_redundant_assignment():
    for variant in ({"permission": False}, {"role_enabled": False}, {"source_enabled": False},
                    {"already_assigned": True}, {"graph_resource": False}):
        assert "entra_role:role-global" not in _targets(**variant), variant


def test_incomplete_role_or_assignment_inventory_does_not_claim_derived_access():
    assert list(_targets(definition_complete=False).values()) == ["conditional"]
    assert _targets(assignment_complete=False).get("entra_role:role-global") == "conditional"
