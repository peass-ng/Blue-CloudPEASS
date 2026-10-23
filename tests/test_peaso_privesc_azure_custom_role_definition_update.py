"""Custom role edits only name an active custom role held by the source."""
from __future__ import annotations

from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T, az


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_roles.yaml").read_text())
    if row["id"] == "azure-entraid-custom-role-definition-update")
ACTION = "microsoft.directory/roleDefinitions/allProperties/update"


def _inventory(*, update_scope="/", assigned=True, builtin=False, via_group=False,
               role_status="collected", assignment_status="collected"):
    snap = az(groups=(("g-editors", "Editors"),) if via_group else (),
              members={"g-editors": ["u-alice"]} if via_group else None)
    defs = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    defs.update(status=role_status, items=[
        {"id": "role-editor", "displayName": "Role editor", "isBuiltIn": True,
         "rolePermissions": [{"allowedResourceActions": [ACTION]}]},
        {"id": "role-custom", "templateId": "template-custom", "displayName": "Custom app operator",
         "isBuiltIn": builtin, "rolePermissions": [{"allowedResourceActions": [
             "microsoft.directory/applications/basic/read"]}]},
        {"id": "role-other", "displayName": "Other custom role", "isBuiltIn": False,
         "rolePermissions": [{"allowedResourceActions": ["microsoft.directory/groups/basic/read"]}]},
    ])
    grants = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    grants.update(status=assignment_status, items=[
        {"id": "grant-editor", "principalId": "u-alice", "roleDefinitionId": "role-editor",
         "directoryScopeId": update_scope},
        *([{"id": "grant-custom", "principalId": "g-editors" if via_group else "u-alice",
            "roleDefinitionId": "role-custom", "directoryScopeId": "/"}] if assigned else []),
    ])
    return snap


def _reached(snap, source="u-alice"):
    return reached(privesc.analyze(snap, entries=[ENTRY]), source, ENTRY["id"])


def test_exact_assigned_custom_role_only():
    assert validate_entry(ENTRY)[0] == []
    assert _reached(_inventory()) == {"entra_role:template-custom": "conditional"}
    assert _reached(_inventory(via_group=True)) == {"entra_role:template-custom": "conditional"}


def test_builtin_unassigned_or_non_tenant_editor_role_excluded():
    assert _reached(_inventory(builtin=True)) == {}
    assert _reached(_inventory(assigned=False)) == {}
    assert _reached(_inventory(update_scope="/app-a")) == {}
    assert _reached(_inventory(update_scope="/administrativeUnits/au-a")) == {}


def test_missing_or_denied_collections_and_app_only_source_excluded():
    assert _reached(_inventory(role_status="access_denied")) == {}
    assert _reached(_inventory(assignment_status="access_denied")) == {}
    snap = _inventory()
    grants = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    grants["items"][0]["principalId"] = "sp-a"
    assert _reached(snap, "sp-a") == {}
