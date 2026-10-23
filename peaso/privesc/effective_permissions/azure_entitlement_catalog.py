"""Match catalog self-grants to the exact group role and the source's catalog."""
from __future__ import annotations

from . import ANY, inventory_status, items, unavailable


def _low(value):
    return str(value or "").casefold()


def _proved(grant):
    return grant is not None and grant.confidence != "unknown"


def select(model, candidates, source):
    return _select(model, candidates, source, "aadgroup", {"member", "owner"})


def select_role(model, candidates, source):
    return _select(model, candidates, source, "directoryrole", {"active member", "eligible member"})


def _select(model, candidates, source, origin_system, role_names):
    if source is None:
        return None
    catalog_status = inventory_status(model.snapshot, "entitlement_catalog_resource")
    if not catalog_status:
        return None
    assignment_status = inventory_status(model.snapshot, "entitlement_role_assignment")
    package_status = inventory_status(model.snapshot, "entitlement_access_package_resource")
    package_roles = {(_low(row.get("catalogId")), _low(row.get("originId")))
        for _, row in items(model.snapshot, "entitlement_access_package_resource")
        if _low(row.get("originSystem")) == origin_system
        and _low(row.get("roleName")) in role_names}
    global_admin = _proved(model.cached_check(source, {"entra_role": "Identity Governance Administrator"}, "dir:/"))
    graph_admin = (source.kind in ("azure_service_principal", "azure_managed_identity") and
                   _proved(model.cached_check(source, {"graph_app_permission": "EntitlementManagement.ReadWrite.All"}, ANY)))
    out = {}
    for tid, target in candidates.items():
        ids = model._target_object_ids(target)
        matched = False
        unknown = unavailable(catalog_status)
        for _, resource in items(model.snapshot, "entitlement_catalog_resource"):
            catalog, origin = _low(resource.get("catalogId")), _low(resource.get("originId"))
            if (origin not in ids or _low(resource.get("originSystem")) != origin_system
                    or not catalog or not isinstance(resource.get("roles"), list)
                    or not any(_low(role.get("displayName")) in role_names
                               for role in resource["roles"] if isinstance(role, dict))):
                continue
            if global_admin or graph_admin:
                matched = True
                break
            if not assignment_status:
                unknown = True
                continue
            ref = "catalog:" + catalog
            if (_proved(model.cached_check(source, {"entra_catalog_role": "Catalog owner", "catalog": "{target.catalog}"}, ref))
                    or _proved(model.cached_check(source, {"entra_catalog_role": "Access package manager", "catalog": "{target.catalog}"}, ref))):
                matched = True
                break
            if (package_status and (catalog, origin) in package_roles
                    and _proved(model.cached_check(source, {"entra_catalog_role": "Access package assignment manager",
                                                    "catalog": "{target.catalog}"}, ref))):
                matched = True
                break
            unknown = unknown or unavailable(assignment_status) or not package_status or unavailable(package_status)
        if matched:
            out[tid] = ("conditional", "catalog_group_grant_requires_user_assignment")
        elif unknown:
            out[tid] = ("unknown", "entitlement_catalog_grant_evidence_incomplete")
    return out
