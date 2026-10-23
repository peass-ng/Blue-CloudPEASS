"""Bind an automatic assignment policy to an exact packaged group Member role."""
from __future__ import annotations

from . import inventory_status, items


GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
WRITE_ROLE = "entitlementmanagement.readwrite.all"


def _app_only_authorized(model, source):
    graph_ids = {
        str(row.get("id") or "").casefold()
        for _, row in items(model.snapshot, "directory_service_principal")
        if isinstance(row, dict) and str(row.get("appId") or "").casefold() == GRAPH_APP_ID
    }
    scope = f"/tenants/{model.tenant}/servicePrincipals/{source.id}"
    if (not graph_ids or inventory_status(model.snapshot, "directory_app_role_assignment").get(scope)
            not in ("collected", "partial")):
        return False
    return any(
        str(row_scope).casefold() == scope.casefold()
        and isinstance(row, dict)
        and str(row.get("principalId") or "").casefold() == source.id.casefold()
        and str(row.get("resourceId") or "").casefold() in graph_ids
        and str(row.get("appRoleValue") or "").casefold() == WRITE_ROLE
        and row.get("appRoleEnabled") is True
        for row_scope, row in items(model.snapshot, "directory_app_role_assignment")
    )


def select(model, candidates, source):
    if source is None or source.attrs.get("account_enabled") is False:
        return {}
    if source.kind not in ("azure_user", "azure_service_principal", "azure_managed_identity"):
        return {}
    if source.kind != "azure_user" and not _app_only_authorized(model, source):
        return {}
    status = inventory_status(model.snapshot, "entitlement_access_package_resource")
    if not status:
        return None
    group_ids = set()
    for scope, row in items(model.snapshot, "entitlement_access_package_resource"):
        if status.get(scope) not in ("collected", "partial") or not isinstance(row, dict):
            continue
        package_id = str(row.get("accessPackageId") or "")
        if (not package_id or str(scope).casefold() !=
                f"/tenants/{model.tenant}/accessPackages/{package_id}".casefold()):
            continue
        if str(row.get("roleName") or "").casefold() == "member":
            group_ids.add(str(row.get("originId") or "").casefold())
    return {
        target_id: ("conditional", "auto_policy_rule_license_and_evaluation_required")
        for target_id, target in candidates.items()
        if (target.kind == "entra_group" and target.id.casefold() in group_ids
            and "DynamicMembership" not in (target.attrs.get("group_types") or ())
            and target.attrs.get("on_prem_sync") is not True)
    }
