"""Bound limited directory password-reset roles to eligible Entra users."""
from __future__ import annotations

from . import ANY, inventory_status, items, unavailable
from .azure_graph_tap import _external_user


def _low(value):
    return str(value or "").casefold()


def select(model, candidates, source, *, role_name="helpdesk administrator", allow_app=False,
           allow_target_enable=False):
    # App-only passwordProfile updates require at least User Administrator as
    # well as a Graph application permission; these roles alone are insufficient.
    if source is None or source.kind not in (("azure_user", "azure_service_principal", "azure_managed_identity")
                                                    if allow_app else ("azure_user",)):
        return {}
    if source.attrs.get("account_enabled") is False:
        return {}
    role_scopes = []
    source_roles = []
    for pid in (source.id, *source.attrs.get("groups", ())):
        for role, scope, _ in model.dir_assignments.get(pid, ()):
            info = model.dir_roles.get(role)
            if info and _low(info.get("name")) == role_name:
                role_scopes.append(_low(scope or "/"))
                source_roles.append((_low(scope or "/"), info))
    if not role_scopes:
        return {}
    app = source.kind != "azure_user"
    app_permission = False
    app_grants_missing = False
    if app:
        grant = model.check(source, {"graph_app_permission": "User-PasswordProfile.ReadWrite.All"}, ANY)
        app_permission = grant is not None and grant.confidence == "derived"
        app_status = inventory_status(model.snapshot, "directory_app_role_assignment")
        app_grants_missing = not app_status or bool(unavailable(app_status))
        if not app_permission and not app_grants_missing:
            return {}
    au_source_read_unverified = False
    if (app or _external_user(source)) and all(scope.startswith("/administrativeunits/") for scope in role_scopes):
        au_source_read_unverified = not any(
            info and _low(info.get("name")) == "directory readers" and _low(scope or "/") == "/"
            for pid in (source.id, *source.attrs.get("groups", ()))
            for role, scope, _ in model.dir_assignments.get(pid, ())
            if (info := model.dir_roles.get(role)) is not None)

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
        if app_grants_missing and not app_permission:
            reasons.append("graph_password_application_grant_not_collected")
        if au_source_read_unverified:
            reasons.append("au_scoped_source_directory_read_not_verified")
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
        if not any(scope in ("/", "/" + _low(tid)) or scope in member_units for scope in role_scopes):
            if not au_incomplete:
                continue
            reasons.append("source_au_scope_membership_not_collected")
        if restricted and not any(scope in restricted for scope in role_scopes):
            continue
        if au_incomplete:
            reasons.append("administrative_unit_membership_not_collected")

        target_assignments = [(model.dir_roles.get(role), _low(scope or "/"))
                              for pid in (tid, *user.attrs.get("groups", ()))
                              for role, scope, _ in model.dir_assignments.get(pid, ())]
        if target_assignments and all(scope.startswith("/administrativeunits/") for scope in role_scopes):
            continue  # AU-scoped password reset roles can reach non-admin users only.
        if restricted and any(scope in restricted for _, scope in target_assignments):
            continue  # A role scoped to a restricted AU protects its holder.

        domain = _low(user.attrs.get("upn")).partition("@")[2]
        if domains.get(domain) == "federated":
            continue
        if not domain or domain not in domains:
            reasons.append("target_domain_authentication_not_collected")
        if user.attrs.get("on_prem_sync") is True:
            reasons.append("password_writeback_required")
        if user.attrs.get("account_enabled") is False:
            can_enable = allow_target_enable and any(
                "microsoft.directory/users/enable" in {_low(action) for action in info["actions"]}
                and model._dir_scope(scope, "dir:" + tid)[0] == "derived"
                for scope, info in source_roles)
            if can_enable and app:
                can_enable = all(
                    (grant := model.check(source, {"graph_app_permission": permission}, ANY)) is not None
                    and grant.confidence == "derived"
                    for permission in ("User.EnableDisableAccount.All", "User.Read.All"))
            if not can_enable:
                continue
            reasons.append("target_enable_required")
        elif user.attrs.get("account_enabled") is not True:
            reasons.append("target_enabled_state_not_collected")
        if source.attrs.get("account_enabled") is not True:
            reasons.append("source_or_target_enabled_state_not_collected")
        out[tid] = (("conditional", ",".join(reasons)) if reasons else None)
    return out
