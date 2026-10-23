"""Bind an application owner to the exact app and its usable service principal."""
from __future__ import annotations

from . import inventory_status, items


GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
APP_WRITE_PERMISSIONS = {
    "application.readwrite.ownedby", "application.readwrite.all", "directory.readwrite.all",
}


def _app_only_authorized(model, source):
    graph_resources = {str(row.get("id") or "").casefold()
                       for _, row in items(model.snapshot, "directory_service_principal")
                       if isinstance(row, dict) and
                       str(row.get("appId") or "").casefold() == GRAPH_APP_ID}
    return any(
        str(row.get("principalId") or "").casefold() == source.id.casefold()
        and str(row.get("resourceId") or "").casefold() in graph_resources
        and str(row.get("appRoleValue") or "").casefold() in APP_WRITE_PERMISSIONS
        and row.get("appRoleEnabled") is True
        for _, row in items(model.snapshot, "directory_app_role_assignment")
        if isinstance(row, dict)
    )


def select(model, candidates, source):
    if source is None or source.kind not in (
            "azure_user", "azure_service_principal", "azure_managed_identity"):
        return {}
    if source.attrs.get("account_enabled") is False:
        return {}
    if source.kind != "azure_user" and not _app_only_authorized(model, source):
        return {}
    tenant_scope = f"/tenants/{model.tenant}".casefold()
    app_ids = model.app_ids or {}
    owner_status = {str(scope).casefold(): status for scope, status in
                    inventory_status(model.snapshot, "directory_owner").items()}
    owned = set()
    for scope, row in items(model.snapshot, "directory_owner"):
        if not isinstance(row, dict) or str(row.get("objectType") or "").casefold() != "application":
            continue
        app_object = str(row.get("objectId") or "").casefold()
        expected_scope = f"{tenant_scope}/applications/{app_object}"
        if (str(scope).casefold() != expected_scope
                or owner_status.get(expected_scope) not in ("collected", "partial")
                or source.id.casefold() not in {str(owner).casefold() for owner in row.get("ownerIds") or ()}):
            continue
        owned.add(app_object)
    out = {}
    for target_id, target in candidates.items():
        if (target.kind != "azure_service_principal" or target.attrs.get("directory") is not True
                or target.attrs.get("account_enabled") is not True
                or target.attrs.get("sp_type") != "Application"):
            continue
        app = app_ids.get(str(target.attrs.get("app_id") or "").casefold())
        if app is not None and str(app.get("id") or "").casefold() in owned:
            out[target_id] = ("conditional", "owner_graph_credential_write_and_sign_in_required")
    return out
