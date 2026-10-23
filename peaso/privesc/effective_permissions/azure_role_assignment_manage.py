"""Bind directory-role assignment authority to an enabled, new target role."""
from __future__ import annotations

from . import ANY, inventory_status, unavailable


ROLE_WRITE = "microsoft.directory/roleassignments/allproperties/alltasks"
GRAPH_WRITE = "RoleManagement.ReadWrite.Directory"
SOURCE_ROLES = {"privileged role administrator", "global administrator"}


def _low(value):
    return str(value or "").casefold()


def select(model, candidates, source):
    if source is None or source.kind not in ("azure_user", "azure_service_principal", "azure_managed_identity"):
        return {}
    if source.attrs.get("account_enabled") is False:
        return {}
    source_ids = (source.id, *source.attrs.get("groups", ()))
    active_roles = []
    for pid in source_ids:
        for role, scope, _ in model.dir_assignments.get(pid, ()):
            info = model.dir_roles.get(role)
            if info and _low(scope or "/") == "/" and info.get("enabled") is not False:
                if _low(info.get("name")) in SOURCE_ROLES or ROLE_WRITE in {_low(action) for action in info["actions"]}:
                    active_roles.append(info)
    if not active_roles:
        return {}
    if any(_low(info.get("name")) == "global administrator" and info.get("enabled") is True
           for info in active_roles):
        return {}  # Already has the highest directory role.

    app = source.kind != "azure_user"
    graph_write = False
    graph_status = inventory_status(model.snapshot, "directory_app_role_assignment")
    if app:
        grant = model.check(source, {"graph_app_permission": GRAPH_WRITE}, ANY)
        graph_write = grant is not None and grant.confidence == "derived"
        if not graph_write and graph_status and not unavailable(graph_status):
            return {}

    definitions = inventory_status(model.snapshot, "directory_role_definition")
    assignments = inventory_status(model.snapshot, "directory_role_assignment")
    complete = bool(definitions) and not unavailable(definitions) and bool(assignments) and not unavailable(assignments)
    membership = model.membership_status
    membership_incomplete = bool(membership) and any(status not in ("collected", "empty")
                                                 for status in membership.values())
    source_unknown = source.attrs.get("account_enabled") is not True or any(
        info.get("enabled") is not True for info in active_roles)
    custom_only = all(info.get("builtin") is not True for info in active_roles)
    out = {}
    for tid, target in candidates.items():
        if target.kind != "entra_role":
            continue
        role_id = _low(target.attrs.get("template_id"))
        role = model.dir_roles.get(role_id)
        if role is None:
            out[tid] = ("unknown", "directory_role_definition_not_collected")
            continue
        if role.get("enabled") is False:
            continue
        aliases = {role_id, _low(role.get("def_id"))}
        if any(_low(assigned_role) in aliases and _low(scope or "/") == "/"
               for pid in source_ids for assigned_role, scope, _ in model.dir_assignments.get(pid, ())):
            continue
        reasons = []
        if not complete or source_unknown or role.get("enabled") is not True:
            reasons.append("role_or_assignment_state_incomplete")
        if custom_only:
            reasons.append("custom_role_assignment_management_unverified")
        if membership_incomplete:
            reasons.append("source_group_membership_incomplete")
        if app and not graph_write:
            reasons.append("graph_role_management_grant_not_collected")
        out[tid] = (("conditional", ",".join(reasons)) if reasons else None)
    return out
