"""Bind federation authority to an existing verified domain and its users."""
from __future__ import annotations

from . import inventory_status, items


GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
GRAPH_FEDERATION = "domain-internalfederation.readwrite.all"
GRAPH_DOMAIN_WRITE = "domain.readwrite.all"
CREATE_ACTIONS = (
    "microsoft.directory/domains/federationConfiguration/create",
    "microsoft.directory/domains/allProperties/allTasks",
)
UPDATE_ACTIONS = (
    "microsoft.directory/domains/federation/update",
    "microsoft.directory/domains/allProperties/allTasks",
)


def _graph_roles(model, source):
    graph_ids = {
        str(row.get("id") or "").casefold()
        for _, row in items(model.snapshot, "directory_service_principal")
        if isinstance(row, dict) and str(row.get("appId") or "").casefold() == GRAPH_APP_ID
    }
    if not graph_ids:
        return set()
    scope = f"/tenants/{model.tenant}/servicePrincipals/{source.id}"
    status = inventory_status(model.snapshot, "directory_app_role_assignment")
    if status.get(scope) not in ("collected", "partial"):
        return set()
    return {
        str(row.get("appRoleValue") or "").casefold()
        for row_scope, row in items(model.snapshot, "directory_app_role_assignment")
        if str(row_scope).casefold() == scope.casefold() and isinstance(row, dict)
        and str(row.get("principalId") or "").casefold() == source.id.casefold()
        and str(row.get("resourceId") or "").casefold() in graph_ids
        and row.get("appRoleEnabled") is True
    }


def _can_federate(model, source, auth_type, graph_roles):
    if source.kind == "azure_user":
        actions = CREATE_ACTIONS if auth_type == "managed" else UPDATE_ACTIONS
        return any(model._entra(source, {"entra_permission": action}, "dir:/") is not None
                   for action in actions)
    if source.kind in ("azure_service_principal", "azure_managed_identity"):
        return GRAPH_FEDERATION in graph_roles or (
            auth_type == "federated" and GRAPH_DOMAIN_WRITE in graph_roles)
    return False


def select(model, candidates, source):
    if source is None or source.attrs.get("account_enabled") is False:
        return {}
    tenant_scope = f"/tenants/{model.tenant}"
    if inventory_status(model.snapshot, "directory_domain").get(tenant_scope) not in (
            "collected", "partial"):
        return {}
    domains = {}
    for scope, row in items(model.snapshot, "directory_domain"):
        if str(scope).casefold() != tenant_scope.casefold() or not isinstance(row, dict):
            continue
        name = str(row.get("id") or "").casefold()
        if (not name or name.endswith(".onmicrosoft.com") or row.get("isVerified") is not True
                or row.get("isInitial") is not False):
            continue
        auth_type = str(row.get("authenticationType") or "").casefold()
        if auth_type in ("managed", "federated"):
            domains[name] = auth_type
    graph_roles = _graph_roles(model, source) if source.kind != "azure_user" else set()
    out = {}
    for target_id, target in candidates.items():
        if target.kind != "azure_user" or target.attrs.get("account_enabled") is False:
            continue
        upn = str(target.attrs.get("upn") or "").casefold()
        if "@" not in upn or "#ext#" in upn:
            continue
        domain = upn.rsplit("@", 1)[1]
        auth_type = domains.get(domain)
        if not auth_type or not _can_federate(model, source, auth_type, graph_roles):
            continue
        if target.attrs.get("immutable_id_recorded") is not True:
            out[target_id] = ("unknown", "immutable_id_not_collected")
        elif target.attrs.get("immutable_id"):
            out[target_id] = ("conditional", "federation_issuer_and_sign_in_required")
    return out
