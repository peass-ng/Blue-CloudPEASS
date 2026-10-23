"""Catalog self-grants need an actual group role and matching authority."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T, az


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_governance.yaml").read_text())
    if row["id"] == "azure-entraid-entitlement-catalog-self-grant-group")
CATALOG_OWNER = "ae79f266-94d4-4dab-b730-feca7e132178"
ASSIGNMENT_MANAGER = "e2182095-804a-4656-ae11-64734e9b7ae5"


def _snapshot(*, role=CATALOG_OWNER, group_role="Member", packaged=False, catalog="cat1"):
    extra = [("entitlement_role_assignment", T, [{"id": "assignment1", "principalId": "u-alice",
              "roleDefinitionId": role, "appScopeId": "/AccessPackageCatalog/cat1"}]),
             ("entitlement_catalog_resource", f"{T}/catalogs/{catalog}", [
                 {"id": "resource1", "catalogId": catalog, "originId": "g-in", "originSystem": "AadGroup",
                  "roles": [{"displayName": group_role}]}]),
             ("entitlement_access_package_resource", f"{T}/accessPackages/ap1",
              [{"id": "role1", "catalogId": catalog, "accessPackageId": "ap1", "originId": "g-in",
                "originSystem": "AadGroup", "roleName": group_role}] if packaged else [])]
    return az(groups=[("g-in", "in"), ("g-out", "out")], members={}, extra=extra)


def _targets(snapshot):
    return reached(privesc.analyze(snapshot, entries=[ENTRY]), "u-alice", ENTRY["id"])


def test_catalog_owner_needs_exact_group_and_usable_group_role():
    assert validate_entry(ENTRY)[0] == []
    assert _targets(_snapshot()).get("g-in") == "conditional"
    assert "g-out" not in _targets(_snapshot())
    assert "g-in" not in _targets(_snapshot(group_role="Reader"))
    assert "g-in" not in _targets(_snapshot(catalog="cat2"))


def test_assignment_manager_needs_existing_package_with_same_group_role():
    assert "g-in" not in _targets(_snapshot(role=ASSIGNMENT_MANAGER))
    assert _targets(_snapshot(role=ASSIGNMENT_MANAGER, packaged=True)).get("g-in") == "conditional"
    assert "g-in" not in _targets(_snapshot(role=ASSIGNMENT_MANAGER, packaged=True, group_role="Reader"))


def test_tenant_admin_role_scope_and_incomplete_catalog():
    snap = _snapshot(role="unrelated")
    defs = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    defs.update(status="collected", items=[{"id": "iga", "displayName": "Identity Governance Administrator",
                                            "isBuiltIn": True, "rolePermissions": []}])
    assignments = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    assignments.update(status="collected", items=[{"id": "iga-grant", "principalId": "u-alice",
                                                   "roleDefinitionId": "iga", "directoryScopeId": "/applications/app1"}])
    assert "g-in" not in _targets(snap)
    assignments["items"][0]["directoryScopeId"] = "/"
    assert _targets(snap).get("g-in") == "conditional"
    catalog = next(c for c in snap["collections"] if c["type"] == "entitlement_catalog_resource")
    catalog.update(status="access_denied", items=[])
    assert "g-in" not in _targets(snap)


def test_app_permission_needs_controlled_user_path():
    from tests.test_peaso_privesc_azure_entitlement_auto_assignment import _inventory
    from tests.test_peaso_privesc_schema_ext import entry
    snap = _inventory()
    snap["collections"].append({"type": "entitlement_catalog_resource", "scope": f"{T}/catalogs/cat1",
        "service": "Microsoft.Graph", "status": "collected", "items": [{"id": "resource1",
            "catalogId": "cat1", "originId": "g-in", "originSystem": "AadGroup",
            "roles": [{"displayName": "Member"}]}]})
    assert reached(privesc.analyze(snap, entries=[ENTRY]), "sp-source", ENTRY["id"]) == {}
    control = entry("azure-test-control-user", "azure",
        {"all_of": [{"graph_app_permission": "EntitlementManagement.ReadWrite.All"}]},
        {"kind": "azure_user", "selector": {"any_principal_in_scope": True}, "scope": "tenant"})
    assert reached(privesc.analyze(snap, entries=[control, ENTRY]), "sp-source", ENTRY["id"]).get("g-in") == "conditional"
