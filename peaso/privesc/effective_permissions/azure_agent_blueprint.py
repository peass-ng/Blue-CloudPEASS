"""Resolve Agent ID blueprint credentials to their exact tenant principals."""
from __future__ import annotations

from . import inventory_status, items


APP_PERMISSIONS = ("AgentIdentityBlueprint.AddRemoveCreds.All", "AgentIdentityBlueprint.ReadWrite.All")
ROLE_PERMISSION = "microsoft.directory/agentIdentityBlueprints/credentials/update"
KINDS = ("directory_agent_blueprint", "directory_agent_blueprint_principal",
         "directory_agent_identity")
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"


def _active(row):
    return (row.get("accountEnabled") is True
            and row.get("disabledByMicrosoftStatus") in (None, "NotDisabled"))


def _blueprint_available(row):
    return row.get("disabledByMicrosoftStatus") in (None, "NotDisabled")


def _rows(snapshot, kind, tenant_scope):
    status = inventory_status(snapshot, kind).get(tenant_scope)
    if status not in ("collected", "empty"):
        return None
    return [row for scope, row in items(snapshot, kind)
            if str(scope).casefold() == tenant_scope and isinstance(row, dict)]


def _unique_by(rows, field):
    unique, duplicate = {}, set()
    for row in rows:
        key = str(row.get(field) or "").casefold()
        if not key or key in unique:
            duplicate.add(key)
        else:
            unique[key] = row
    return {key: row for key, row in unique.items() if key not in duplicate}


def _graph_app_granted(model, source):
    if source.kind not in ("azure_service_principal", "azure_managed_identity"):
        return False
    resource_ids = {str(row.get("id") or "").casefold()
                    for _, row in items(model.snapshot, "directory_service_principal")
                    if isinstance(row, dict) and str(row.get("appId") or "").casefold() == GRAPH_APP_ID}
    return any(
        str(row.get("principalId") or "").casefold() == source.id.casefold()
        and str(row.get("resourceId") or "").casefold() in resource_ids
        and str(row.get("appRoleValue") or "").casefold() in
        {permission.casefold() for permission in APP_PERMISSIONS}
        and row.get("appRoleEnabled") is True
        for _, row in items(model.snapshot, "directory_app_role_assignment")
        if isinstance(row, dict)
    )


def _owns_blueprint(model, source, blueprint_id):
    if source.kind != "azure_user":
        return False
    return any(
        str(row.get("objectId") or "").casefold() == blueprint_id.casefold()
        and str(row.get("objectType") or "").casefold() == "application"
        and source.id.casefold() in {str(owner).casefold() for owner in row.get("ownerIds") or ()}
        for _, row in items(model.snapshot, "directory_owner") if isinstance(row, dict)
    )


def select(model, candidates, source):
    if source is None:
        return {}
    tenant_scope = f"/tenants/{model.tenant}".casefold()
    blueprints = _rows(model.snapshot, KINDS[0], tenant_scope)
    principals = _rows(model.snapshot, KINDS[1], tenant_scope)
    agents = _rows(model.snapshot, KINDS[2], tenant_scope)
    if blueprints is None or principals is None:
        return {}

    app_granted = _graph_app_granted(model, source)
    if not app_granted and source.kind != "azure_user":
        return {}

    by_app = _unique_by(blueprints, "appId")
    by_principal = _unique_by(principals, "appId")
    by_agent_id = _unique_by(agents, "id") if agents is not None else {}
    candidate_ids = {str(identifier).casefold(): identifier for identifier in candidates}
    out = {}
    for app_id, blueprint in by_app.items():
        principal = by_principal.get(app_id)
        if (principal is None or not _blueprint_available(blueprint) or not _active(principal)
                or not isinstance(blueprint.get("id"), str) or not blueprint["id"]):
            continue
        if not app_granted:
            role = model.check(source, {"entra_permission": ROLE_PERMISSION}, "dir:" + blueprint["id"])
            if role is not None and role.confidence in ("derived", "conditional"):
                reason = "delegated_graph_permission_and_sign_in_not_verified"
            elif _owns_blueprint(model, source, blueprint["id"]):
                reason = "blueprint_owner_delegated_graph_permission_and_sign_in_not_verified"
            else:
                continue
        else:
            reason = "new_blueprint_credential_and_sign_in_required"
        principal_id = candidate_ids.get(str(principal.get("id") or "").casefold())
        if (principal_id is not None and candidates[principal_id].kind == "azure_service_principal"
                and candidates[principal_id].attrs.get("account_enabled") is not False
                and str(candidates[principal_id].attrs.get("app_id") or app_id).casefold() == app_id):
            out[principal_id] = ("conditional", reason)
        for agent_id, agent in by_agent_id.items():
            target_id = candidate_ids.get(agent_id)
            if (str(agent.get("agentIdentityBlueprintId") or "").casefold() == app_id
                    and isinstance(agent.get("appId"), str) and bool(agent["appId"])
                    and _active(agent) and target_id is not None
                    and candidates[target_id].kind == "azure_service_principal"
                    and candidates[target_id].attrs.get("account_enabled") is not False
                    and str(candidates[target_id].attrs.get("app_id") or agent.get("appId") or "").casefold()
                    == str(agent.get("appId") or "").casefold()):
                out[target_id] = ("conditional", "blueprint_agent_token_exchange_required")
    return out
