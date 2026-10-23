"""User Administrator password reset checks role matrix and app-only grants."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T
from tests.test_peaso_privesc_azure_helpdesk_password_reset import _case as limited_case


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_roles.yaml").read_text())
    if row["id"] == "azure-entraid-reset-password-user-admin")


def _case(*, graph_grant=None, target_enabled=True, **kwargs):
    snap = limited_case(**kwargs)
    defs = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    defs["items"][0]["displayName"] = "User Administrator"
    defs["items"][0]["rolePermissions"][0]["allowedResourceActions"].append(
        "microsoft.directory/users/enable")
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")
    next(row for row in users["items"] if row["id"] == "u-target")["accountEnabled"] = target_enabled
    if kwargs.get("app"):
        service = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
        service["items"].append({"id": "sp-graph", "appId":
            "00000003-0000-0000-c000-000000000000", "accountEnabled": True,
            "servicePrincipalType": "Application"})
        snap["collections"].append({"type": "directory_app_role_assignment", "scope": T,
            "service": "Microsoft.Graph", "status": "collected" if graph_grant else "empty",
            "items": ([{"id": "app-grant", "principalId": "sp-source", "resourceId": "sp-graph",
                       "appRoleValue": graph_grant, "appRoleEnabled": True}] if graph_grant else [])})
    return snap


def _targets(snap, *, app=False):
    return reached(privesc.analyze(snap, entries=[ENTRY]), "sp-source" if app else "u-source", ENTRY["id"])


def _conditions(snap):
    edges = privesc.analyze(snap, entries=[ENTRY])["graph"]["edges"]
    return edges[0]["technique_details"][0]["conditions"] if edges else []


def test_user_admin_role_matrix_and_protected_owner():
    assert validate_entry(ENTRY)[0] == []
    for role in (None, "Groups Administrator", "User Experience Success Manager", "User Administrator"):
        assert "u-target" in _targets(_case(target_role=role))
    for role in ("Global Reader", "Authentication Administrator"):
        assert "u-target" not in _targets(_case(target_role=role))
    assert "u-target" not in _targets(_case(owner=True))


def test_user_admin_scope_restrictions():
    assert "u-target" in _targets(_case(source_scope="/administrativeUnits/au-1"))
    assert "u-target" not in _targets(_case(source_scope="/administrativeUnits/au-2"))
    assert "u-target" not in _targets(_case(source_scope="/administrativeUnits/au-1",
                                            target_role="User Administrator"))
    assert "u-target" not in _targets(_case(restricted=True))
    assert "u-target" in _targets(_case(restricted=True, source_scope="/administrativeUnits/au-1"))


def test_app_only_password_update_needs_graph_grant():
    assert "u-target" not in _targets(_case(app=True), app=True)
    assert "u-target" in _targets(_case(app=True, graph_grant="User-PasswordProfile.ReadWrite.All"), app=True)
    assert "au_scoped_source_directory_read_not_verified" in _conditions(_case(
        app=True, graph_grant="User-PasswordProfile.ReadWrite.All",
        source_scope="/administrativeUnits/au-1"))
    snap = _case(app=True)
    next(c for c in snap["collections"] if c["type"] == "directory_app_role_assignment")["status"] = "access_denied"
    assert "graph_password_application_grant_not_collected" in _conditions(snap)


def test_au_scoped_guest_needs_directory_read():
    snap = _case(source_scope="/administrativeUnits/au-1")
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")
    next(row for row in users["items"] if row["id"] == "u-source")["creationType"] = "Invitation"
    assert "au_scoped_source_directory_read_not_verified" in _conditions(snap)


def test_password_origin_and_disabled_user():
    assert "u-target" not in _targets(_case(federated=True))
    assert "password_writeback_required" in _conditions(_case(synced=True))
    assert "target_enable_required" in _conditions(_case(target_enabled=False))
    assert "u-target" not in _targets(_case(app=True, target_enabled=False,
                                            graph_grant="User-PasswordProfile.ReadWrite.All"), app=True)
    snap = _case(app=True, target_enabled=False, graph_grant="User-PasswordProfile.ReadWrite.All")
    grants = next(c for c in snap["collections"] if c["type"] == "directory_app_role_assignment")
    for permission in ("User.EnableDisableAccount.All", "User.Read.All"):
        grants["items"].append({"id": permission, "principalId": "sp-source",
            "resourceId": "sp-graph", "appRoleValue": permission, "appRoleEnabled": True})
    assert "target_enable_required" in _conditions(snap)
