"""Federation takeover requires the exact verified domain and target user."""
from __future__ import annotations

from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T, az


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_roles.yaml").read_text())
    if row["id"] == "azure-entraid-domain-federation-backdoor")
CREATE = "microsoft.directory/domains/federationConfiguration/create"
UPDATE = "microsoft.directory/domains/federation/update"
GRAPH = "00000003-0000-0000-c000-000000000000"


def _inventory(*, authentication="Managed", action=CREATE, scope="/",
               verified=True, initial=False, immutable="immutable-target"):
    snap = az(users=("u-admin", "u-other"), extra=[
        ("directory_domain", T, [
            {"id": "contoso.com", "isVerified": verified, "isInitial": initial,
             "authenticationType": authentication},
            {"id": "other.com", "isVerified": True, "isInitial": False,
             "authenticationType": "Managed"}], "collected")])
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")
    users["items"][0].update(userPrincipalName="admin@contoso.com", accountEnabled=True,
                            onPremisesImmutableId=immutable)
    users["items"][1].update(userPrincipalName="other@other.com", accountEnabled=True,
                            onPremisesImmutableId="immutable-other")
    defs = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    defs.update(status="collected", items=[{"id": "role-fed", "displayName": "Federation manager",
        "rolePermissions": [{"allowedResourceActions": [action]}]}])
    grants = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    grants.update(status="collected", items=[{"id": "grant-fed", "principalId": "u-other",
        "roleDefinitionId": "role-fed", "directoryScopeId": scope}])
    return snap


def _named(snap, source="u-other"):
    return {k: v for k, v in reached(privesc.analyze(snap, entries=[ENTRY]), source, ENTRY["id"]).items()
            if k.startswith("u-")}


def _app_only(snap, permission):
    sp = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    sp.update(status="collected", items=[
        {"id": "sp-source", "appId": "source-app", "servicePrincipalType": "Application",
         "accountEnabled": True},
        {"id": "sp-graph", "appId": GRAPH, "servicePrincipalType": "Application",
         "accountEnabled": True},
    ])
    snap["collections"].append({"type": "directory_app_role_assignment",
        "scope": f"{T}/servicePrincipals/sp-source", "service": "Microsoft.Graph",
        "status": "collected", "items": [{"id": "graph-grant", "principalId": "sp-source",
            "resourceId": "sp-graph", "appRoleValue": permission, "appRoleEnabled": True}]})
    return snap


def test_managed_domain_creation_and_federated_domain_update():
    assert validate_entry(ENTRY)[0] == []
    assert _named(_inventory()) == {"u-admin": "conditional"}
    assert _named(_inventory(authentication="Federated", action=UPDATE)) == {
        "u-admin": "conditional"}


def test_wrong_action_scope_or_domain_state_excluded():
    assert _named(_inventory(action=UPDATE)) == {}
    assert _named(_inventory(authentication="Federated", action=CREATE)) == {}
    assert _named(_inventory(scope="/some-app")) == {}
    assert _named(_inventory(verified=False)) == {}
    assert _named(_inventory(initial=True)) == {}
    snap = _inventory()
    domain = next(c for c in snap["collections"] if c["type"] == "directory_domain")
    domain["status"] = "access_denied"
    assert _named(snap) == {}


def test_missing_immutable_id_and_disabled_target_do_not_name_user():
    assert _named(_inventory(immutable=None)) == {}
    snap = _inventory()
    user = next(c for c in snap["collections"] if c["type"] == "directory_user")
    user["items"][0].pop("onPremisesImmutableId")
    assert _named(snap) == {}
    user["items"][0]["accountEnabled"] = False
    assert _named(snap) == {}


def test_graph_app_role_uses_exact_resource_and_managed_domain_permission():
    assert _named(_app_only(_inventory(), "Domain-InternalFederation.ReadWrite.All"),
                  "sp-source") == {"u-admin": "conditional", "u-other": "conditional"}
    assert _named(_app_only(_inventory(), "Domain.ReadWrite.All"), "sp-source") == {}
    assert _named(_app_only(_inventory(authentication="Federated", action=UPDATE),
                            "Domain.ReadWrite.All"), "sp-source") == {"u-admin": "conditional"}
    snap = _app_only(_inventory(), "Domain-InternalFederation.ReadWrite.All")
    grant = next(c for c in snap["collections"] if c["type"] == "directory_app_role_assignment")
    grant["items"][0]["resourceId"] = "sp-source"
    assert _named(snap, "sp-source") == {}
    grant["items"][0]["resourceId"] = "sp-graph"
    grant["items"][0]["appRoleEnabled"] = False
    assert _named(snap, "sp-source") == {}
