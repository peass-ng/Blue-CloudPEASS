"""Automatic assignment needs a real package Member grant and controlled user."""
from __future__ import annotations

from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T, az


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_governance.yaml").read_text())
    if row["id"] == "azure-entraid-entitlement-auto-assignment-persistence")
GRAPH = "00000003-0000-0000-c000-000000000000"


def _inventory(*, role="Member", package="ap1", status="collected"):
    snap = az(groups=(("g-in", "In"), ("g-out", "Out")), sps=("sp-source", "sp-graph"), extra=[
        ("entitlement_access_package_resource", f"{T}/accessPackages/ap1",
         [{"id": "rrs1", "accessPackageId": package, "originId": "g-in",
           "roleName": role, "originSystem": "AadGroup"}], status)])
    defs = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    defs.update(status="collected", items=[{"id": "role-iga",
        "displayName": "Identity Governance Administrator", "isBuiltIn": True,
        "rolePermissions": [{"allowedResourceActions": []}]}])
    grants = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    grants.update(status="collected", items=[{"id": "grant-iga", "principalId": "u-alice",
        "roleDefinitionId": "role-iga", "directoryScopeId": "/"}])
    sp = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    for row in sp["items"]:
        row["appId"] = GRAPH if row["id"] == "sp-graph" else "source-app"
        row["accountEnabled"] = True
    snap["collections"].append({"type": "directory_app_role_assignment",
        "scope": f"{T}/servicePrincipals/sp-source", "service": "Microsoft.Graph",
        "status": "collected", "items": [{"id": "app-grant", "principalId": "sp-source",
            "resourceId": "sp-graph", "appRoleValue": "EntitlementManagement.ReadWrite.All",
            "appRoleEnabled": True}]})
    return snap


def _named(snap, source="u-alice", entries=(ENTRY,)):
    return {k: v for k, v in reached(privesc.analyze(snap, entries=list(entries)), source, ENTRY["id"]).items()
            if k.startswith("g-")}


def test_user_with_governance_role_reaches_only_group_member_role_in_package():
    assert validate_entry(ENTRY)[0] == []
    assert _named(_inventory()) == {"g-in": "conditional"}
    assert _named(_inventory(role="Owner")) == {}
    assert _named(_inventory(package="ap-other")) == {}
    assert _named(_inventory(status="access_denied")) == {}


def test_restricted_governance_role_or_dynamic_group_excluded():
    snap = _inventory()
    grants = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    grants["items"][0]["directoryScopeId"] = "/applications/app1"
    assert _named(snap) == {}
    snap = _inventory()
    groups = next(c for c in snap["collections"] if c["type"] == "directory_group")
    next(row for row in groups["items"] if row["id"] == "g-in")["groupTypes"] = ["DynamicMembership"]
    assert _named(snap) == {}
    snap = _inventory()
    groups = next(c for c in snap["collections"] if c["type"] == "directory_group")
    next(row for row in groups["items"] if row["id"] == "g-in")["onPremisesSyncEnabled"] = True
    assert _named(snap) == {}


def test_app_only_needs_graph_role_and_a_path_to_a_user():
    assert _named(_inventory(), "sp-source") == {}
    # The gate is tested with an existing SP-to-user path from another entry.
    from tests.test_peaso_privesc_schema_ext import entry
    control = entry("azure-test-control-user", "azure",
        {"all_of": [{"graph_app_permission": "EntitlementManagement.ReadWrite.All"}]},
        {"kind": "azure_user", "selector": {"any_principal_in_scope": True}, "scope": "tenant"})
    assert _named(_inventory(), "sp-source", (control, ENTRY)) == {"g-in": "conditional"}
    snap = _inventory()
    grant = next(c for c in snap["collections"] if c["type"] == "directory_app_role_assignment")
    grant["items"][0]["resourceId"] = "sp-source"
    assert _named(snap, "sp-source", (control, ENTRY)) == {}
