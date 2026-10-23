"""Non-administrator-only directory password reset paths."""
from __future__ import annotations

from . import inventory_status, items, unavailable
from .azure_graph_tap import _external_user


ROLES = {"partner tier1 support", "security operator", "entra soc identity responder"}


def _low(value):
    return str(value or "").casefold()


def select(model, candidates, source):
    # Graph app-only password changes require User Administrator or higher in
    # addition to an application permission. These three roles alone do not do it.
    if source is None or source.kind != "azure_user" or source.attrs.get("account_enabled") is False:
        return {}
    roles = []
    for pid in (source.id, *source.attrs.get("groups", ())):
        for role, scope, _ in model.dir_assignments.get(pid, ()):
            info = model.dir_roles.get(role)
            if info and _low(info.get("name")) in ROLES:
                roles.append((_low(scope or "/"), info))
    if not roles:
        return {}
    scopes = [scope for scope, _ in roles]

    units = [row for _, row in items(model.snapshot, "directory_administrative_unit")]
    au_status = inventory_status(model.snapshot, "directory_administrative_unit")
    owner_status = inventory_status(model.snapshot, "directory_owner")
    group_status = inventory_status(model.snapshot, "directory_group")
    protected_groups = {_low(gid) for gid, group in model.principals.items()
                        if group.kind == "entra_group" and group.attrs.get("assignable_to_role") is True}
    protected_owners = {_low(owner) for _, row in items(model.snapshot, "directory_owner")
                        if _low(row.get("objectType")) == "group"
                        and _low(row.get("objectId")) in protected_groups
                        for owner in row.get("ownerIds") or ()}
    domains = {_low(row.get("id")): _low(row.get("authenticationType"))
               for _, row in items(model.snapshot, "directory_domain") if row.get("id")}
    out = {}
    for tid, user in candidates.items():
        if user.kind != "azure_user" or _external_user(user):
            continue
        groups = {_low(gid) for gid in model._groups(tid)}
        if _low(tid) in protected_owners or groups & protected_groups:
            continue
        reasons = []
        if not owner_status or unavailable(owner_status):
            reasons.append("role_assignable_group_ownership_not_collected")
        if not group_status or unavailable(group_status):
            reasons.append("role_assignable_group_inventory_not_collected")
        if not model.membership_status or any(status not in ("collected", "empty")
                                              for status in model.membership_status.values()):
            reasons.append("group_membership_incomplete")
        if any(group.attrs.get("assignable_to_role") is None for gid in groups
               if (group := model.principals.get(gid)) is not None):
            reasons.append("role_assignable_group_status_not_collected")

        restricted = set()
        member_units = set()
        au_incomplete = not au_status or bool(unavailable(au_status))
        for unit in units:
            members = unit.get("memberIds")
            if not isinstance(members, list) or unit.get("isMemberManagementRestricted") is None:
                au_incomplete = True
                continue
            if _low(tid) in {_low(member) for member in members}:
                unit_scope = "/administrativeunits/" + _low(unit.get("id"))
                member_units.add(unit_scope)
                if unit["isMemberManagementRestricted"] is True:
                    restricted.add(unit_scope)
        if not any(scope in ("/", "/" + _low(tid)) or scope in member_units for scope in scopes):
            if not au_incomplete:
                continue
            reasons.append("source_au_scope_membership_not_collected")
        if restricted and not any(scope in restricted for scope in scopes):
            continue
        if au_incomplete:
            reasons.append("administrative_unit_membership_not_collected")

        # The reset matrix's no-admin column checks role assignments. Explicitly
        # protect a target with a role scoped to a restricted AU as well.
        if restricted and any(_low(scope or "/") in restricted
                              for pid in (tid, *user.attrs.get("groups", ()))
                              for _, scope, _ in model.dir_assignments.get(pid, ())):
            continue
        domain = _low(user.attrs.get("upn")).partition("@")[2]
        if domains.get(domain) == "federated":
            continue
        if not domain or domain not in domains:
            reasons.append("target_domain_authentication_not_collected")
        if user.attrs.get("on_prem_sync") is True:
            reasons.append("password_writeback_required")
        if source.attrs.get("account_enabled") is not True:
            reasons.append("source_enabled_state_not_collected")
        if user.attrs.get("account_enabled") is False:
            can_enable = any("microsoft.directory/users/enable" in {_low(action) for action in info["actions"]}
                             and model._dir_scope(scope, "dir:" + tid)[0] == "derived"
                             for scope, info in roles)
            if not can_enable:
                continue
            reasons.append("target_enable_required")
        elif user.attrs.get("account_enabled") is not True:
            reasons.append("target_enabled_state_not_collected")
        out[tid] = (("conditional", ",".join(reasons)) if reasons else None)
    return out
