"""The Entra role path needs a cataloged DirectoryRole grant."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T, az


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_governance.yaml").read_text())
    if row["id"] == "azure-entraid-entitlement-catalog-self-grant-role")
OWNER = "ae79f266-94d4-4dab-b730-feca7e132178"
ASSIGNMENT_MANAGER = "e2182095-804a-4656-ae11-64734e9b7ae5"


def _snapshot(*, authority=OWNER, role_name="Eligible Member", packaged=False,
              catalog="cat1", origin="instance-role1"):
    snap = az(groups=[], members={}, extra=[
        ("entitlement_role_assignment", T, [{"id": "grant1", "principalId": "u-alice",
            "roleDefinitionId": authority, "appScopeId": "/AccessPackageCatalog/cat1"}]),
        ("entitlement_catalog_resource", f"{T}/catalogs/{catalog}", [{"id": "catalog-role1",
            "catalogId": catalog, "originId": origin, "originSystem": "DirectoryRole",
            "roles": [{"displayName": role_name}]}]),
        ("entitlement_access_package_resource", f"{T}/accessPackages/ap1", [{"id": "package-role1",
            "catalogId": catalog, "accessPackageId": "ap1", "originId": origin,
            "originSystem": "DirectoryRole", "roleName": role_name}] if packaged else []),
        ("directory_role", T, [{"id": "instance-role1", "roleTemplateId": "template-role1"}])])
    defs = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    defs.update(status="collected", items=[{"id": "definition-role1", "templateId": "template-role1",
        "displayName": "Test privileged role", "isBuiltIn": True, "rolePermissions": []}])
    return snap


def _targets(snap):
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", ENTRY["id"])


def test_catalog_owner_reaches_exact_cataloged_directory_role():
    assert validate_entry(ENTRY)[0] == []
    assert _targets(_snapshot()).get("entra_role:template-role1") == "conditional"
    assert "entra_role:template-role1" not in _targets(_snapshot(catalog="cat2"))
    assert "entra_role:template-role1" not in _targets(_snapshot(role_name="Reader"))
    assert "entra_role:template-role1" not in _targets(_snapshot(origin="unrelated-role"))


def test_assignment_manager_needs_existing_exact_role_package():
    assert "entra_role:template-role1" not in _targets(_snapshot(authority=ASSIGNMENT_MANAGER))
    assert _targets(_snapshot(authority=ASSIGNMENT_MANAGER, packaged=True)).get("entra_role:template-role1") == "conditional"
    assert "entra_role:template-role1" not in _targets(_snapshot(authority=ASSIGNMENT_MANAGER,
        packaged=True, role_name="Reader"))
