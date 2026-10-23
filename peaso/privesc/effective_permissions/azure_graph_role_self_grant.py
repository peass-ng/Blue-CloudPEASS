"""Verify that the Graph self-grant chain can reach a directory role."""
from __future__ import annotations

from . import inventory_status, items, unavailable


GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"


def _low(value):
    return str(value or "").casefold()


def select(model, candidates, source):
    if (source is None or source.kind not in ("azure_service_principal", "azure_managed_identity")
            or source.attrs.get("account_enabled") is not True):
        return {}
    principal_status = inventory_status(model.snapshot, "directory_service_principal")
    role_status = inventory_status(model.snapshot, "directory_role_definition")
    if not principal_status or not role_status:
        return None
    graph = [row for _, row in items(model.snapshot, "directory_service_principal")
             if _low(row.get("appId")) == GRAPH_APP_ID]
    if len(graph) != 1 or not isinstance(graph[0].get("appRoles"), list):
        return {tid: ("unknown", "graph_role_definition_unavailable") for tid in candidates}
    grant_role = [role for role in graph[0]["appRoles"]
                  if isinstance(role, dict) and _low(role.get("value")) == "rolemanagement.readwrite.directory"
                  and role.get("isEnabled") is True and "Application" in (role.get("allowedMemberTypes") or ())]
    if not grant_role:
        return {}
    if unavailable(role_status):
        # A verified role definition still gives a path; missing definitions stay unresolved.
        incomplete = True
    else:
        incomplete = False
    known = {_low(row.get("templateId") or row.get("id")) for _, row in items(model.snapshot, "directory_role_definition")}
    out = {}
    for tid, target in candidates.items():
        if target.kind != "entra_role":
            continue
        identity = _low(target.attrs.get("template_id"))
        if identity in known:
            out[tid] = ("conditional", "self_grant_requires_new_graph_token_and_role_assignment")
        elif incomplete:
            out[tid] = ("unknown", "directory_role_definitions_incomplete")
    return out


def select_directory_role_self_grant(model, candidates, source):
    """Bind a direct Graph role assignment to an enabled, new directory role."""
    if source is None or source.kind not in ("azure_service_principal", "azure_managed_identity"):
        return {}
    if source.attrs.get("account_enabled") is False:
        return {}
    role_status = inventory_status(model.snapshot, "directory_role_definition")
    assignment_status = inventory_status(model.snapshot, "directory_role_assignment")
    assignments_complete = bool(assignment_status) and not unavailable(assignment_status)
    source_ids = {source.id, *source.attrs.get("groups", ())}
    out = {}
    for tid, target in candidates.items():
        if target.kind != "entra_role":
            continue
        role_id = _low(target.attrs.get("template_id"))
        role = model.dir_roles.get(role_id)
        if role is None:
            out[tid] = ("conditional", "directory_role_definition_not_collected")
            continue
        if role.get("enabled") is False:
            continue
        aliases = {role_id, _low(role.get("def_id"))}
        already_assigned = any(_low(assigned_role) in aliases and scope == "/"
                               for principal_id in source_ids
                               for assigned_role, scope, _ in model.dir_assignments.get(principal_id, ()))
        if already_assigned:
            continue
        if (source.attrs.get("account_enabled") is not True or role.get("enabled") is not True
                or not role_status or unavailable(role_status) or not assignments_complete):
            out[tid] = ("conditional", "directory_role_or_assignment_state_incomplete")
        else:
            out[tid] = None
    return out
