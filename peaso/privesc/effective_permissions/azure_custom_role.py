"""Select custom Entra roles actively assigned to the source."""
from __future__ import annotations

from . import inventory_status


def select(model, candidates, source):
    if source is None or source.kind != "azure_user" or source.attrs.get("account_enabled") is False:
        return {}
    role_status = inventory_status(model.snapshot, "directory_role_definition")
    assignment_status = inventory_status(model.snapshot, "directory_role_assignment")
    tenant_scope = f"/tenants/{model.tenant}"
    if (role_status.get(tenant_scope) not in ("collected", "partial")
            or assignment_status.get(tenant_scope) not in ("collected", "partial")):
        return {}
    member_ids = {source.id, *(source.attrs.get("groups") or ())}
    assigned = set()
    for principal_id in member_ids:
        for role_id, scope, assignment_id in model.dir_assignments.get(principal_id, ()):
            if not assignment_id:
                continue
            info = model.dir_roles.get(role_id)
            if info and info.get("builtin") is False:
                assigned.add(info["id"])
    return {target_id: ("conditional", "graph_scope_license_and_permission_expansion_required")
            for target_id, target in candidates.items()
            if target.kind == "entra_role" and target.attrs.get("template_id") in assigned}
