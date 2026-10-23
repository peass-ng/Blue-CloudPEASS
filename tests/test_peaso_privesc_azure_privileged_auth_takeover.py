"""Privileged credential reset requires a usable source, scope, and auth route."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T, az


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_roles.yaml").read_text())
    if row["id"] == "azure-entraid-reset-credentials-privileged-auth-admin")


def _case(*, app=False, grant=None, role="Privileged Authentication Administrator",
          source_scope="/", restricted=False, target_role=None, federated=False,
          tap_enabled=True):
    snap = az(users=("u-target",) if app else ("u-source", "u-target"),
              sps=("sp-source", "sp-graph") if app else (), extra=[
                  ("directory_administrative_unit", T, [{"id": "au-1", "memberIds": ["u-target"],
                      "isMemberManagementRestricted": restricted}], "collected"),
                  ("directory_domain", T, [{"id": "t.com", "authenticationType":
                      "Federated" if federated else "Managed"}], "collected"),
                  ("temporary_access_pass_policy", T, [{"id": "TemporaryAccessPass", "state":
                      "enabled" if tap_enabled else "disabled",
                      "includeTargets": [{"targetType": "group", "id": "all_users"}],
                      "excludeTargets": []}], "collected")])
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")
    for row in users["items"]:
        row["accountEnabled"] = True
    if app:
        service = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
        for row in service["items"]:
            row["accountEnabled"] = True
            if row["id"] == "sp-graph":
                row["appId"] = "00000003-0000-0000-c000-000000000000"
        snap["collections"].append({"type": "directory_app_role_assignment", "scope": T,
            "service": "Microsoft.Graph", "status": "collected" if grant else "empty", "items":
            ([{"id": "app-grant", "principalId": "sp-source", "resourceId": "sp-graph",
               "appRoleValue": grant, "appRoleEnabled": True}] if grant else [])})
    definitions = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    definitions.update(status="collected", items=[{"id": "source-role", "displayName": role,
        "rolePermissions": [{"allowedResourceActions": ["microsoft.directory/users/password/update"]}]},
        *([{"id": "target-role", "displayName": target_role,
            "rolePermissions": [{"allowedResourceActions": []}]}] if target_role else [])])
    assignments = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    assignments.update(status="collected", items=[{"id": "role-assignment",
        "principalId": "sp-source" if app else "u-source", "roleDefinitionId": "source-role",
        "directoryScopeId": source_scope}, *([{"id": "target-role-assignment",
        "principalId": "u-target", "roleDefinitionId": "target-role", "directoryScopeId": "/"}]
        if target_role else [])])
    return snap


def _targets(snap, *, app=False):
    return reached(privesc.analyze(snap, entries=[ENTRY]), "sp-source" if app else "u-source", ENTRY["id"])


def test_privileged_role_scope_and_restricted_unit():
    assert validate_entry(ENTRY)[0] == []
    assert "u-target" in _targets(_case(target_role="Global Administrator"))
    assert "u-target" not in _targets(_case(source_scope="/administrativeUnits/au-2"))
    assert "u-target" not in _targets(_case(restricted=True))
    assert "u-target" in _targets(_case(restricted=True, source_scope="/administrativeUnits/au-1"))
    assert _targets(_case(restricted=True, source_scope="/administrativeUnits/au-1",
                         target_role="Global Administrator"))["u-target"] == "conditional"
    assert "u-target" not in _targets(_case(restricted=True,
        source_scope="/administrativeUnits/au-1", target_role="Global Administrator",
        tap_enabled=False))


def test_app_only_password_reset_requires_graph_application_permission():
    assert "u-target" not in _targets(_case(app=True), app=True)
    assert "u-target" in _targets(_case(app=True, grant="User-PasswordProfile.ReadWrite.All"), app=True)
    assert "u-target" in _targets(_case(app=True, grant="UserAuthMethod-TAP.ReadWrite.All"), app=True)
    assert _targets(_case(app=True, grant="User-PasswordProfile.ReadWrite.All",
                          source_scope="/administrativeUnits/au-1"), app=True)["u-target"] == "conditional"


def test_missing_app_permission_inventory_is_conditional():
    snap = _case(app=True)
    grants = next(c for c in snap["collections"] if c["type"] == "directory_app_role_assignment")
    grants["status"] = "access_denied"
    assert _targets(snap, app=True)["u-target"] == "conditional"


def test_federated_target_needs_tap_route():
    assert "u-target" not in _targets(_case(federated=True, tap_enabled=False))
    assert "u-target" in _targets(_case(federated=True, tap_enabled=True))
    assert "u-target" not in _targets(_case(app=True, grant="User-PasswordProfile.ReadWrite.All",
                                            federated=True, tap_enabled=False), app=True)
