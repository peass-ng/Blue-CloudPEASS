"""Scope and protected-account checks for Authentication Administrator takeover."""
from __future__ import annotations

from . import inventory_status, items, unavailable
from .azure_graph_tap import _external_user, _targets


def _low(value):
    return str(value or "").casefold()


def select(model, candidates, source):
    if source is None or source.kind != "azure_user" or source.attrs.get("account_enabled") is False:
        return {}
    role_scopes = []
    for pid in (source.id, *source.attrs.get("groups", ())):
        for role, scope, _ in model.dir_assignments.get(pid, ()):
            info = model.dir_roles.get(role)
            if info and _low(info.get("name")) == "authentication administrator":
                role_scopes.append(scope or "/")
    if not role_scopes:
        return {}
    aus = list(items(model.snapshot, "directory_administrative_unit"))
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
    tap_policies = [row for _, row in items(model.snapshot, "temporary_access_pass_policy")]
    tap_status = inventory_status(model.snapshot, "temporary_access_pass_policy")
    tap = tap_policies[0] if len(tap_policies) == 1 and tap_status and not unavailable(tap_status) else None
    out = {}
    for tid, user in candidates.items():
        if user.kind != "azure_user" or _external_user(user):
            continue
        if _low(tid) in protected_owners or protected_groups & {_low(g) for g in model._groups(tid)}:
            continue
        reasons = []
        if not owner_status or unavailable(owner_status):
            reasons.append("role_assignable_group_ownership_not_collected")
        if not group_status or unavailable(group_status):
            reasons.append("role_assignable_group_inventory_not_collected")
        groups = {_low(g) for g in model._groups(tid)}
        if any(group.attrs.get("assignable_to_role") is None for gid in groups
               if (group := model.principals.get(gid)) is not None):
            reasons.append("role_assignable_group_status_not_collected")
        if any(status not in ("collected", "empty") for status in model.membership_status.values()):
            reasons.append("group_membership_incomplete")
        member_of = []
        incomplete_au = not au_status or bool(unavailable(au_status))
        for _, row in aus:
            members = row.get("memberIds")
            if not isinstance(members, list):
                incomplete_au = True
                continue
            if _low(tid) in {_low(member) for member in members}:
                member_of.append((_low(row.get("id")), row.get("isMemberManagementRestricted")))
        member_units = {f"/administrativeunits/{aid}" for aid, _ in member_of}
        if not any(_low(scope) in ("/", "/" + _low(tid)) or _low(scope) in member_units
                   for scope in role_scopes):
            if not incomplete_au:
                continue
            reasons.append("source_au_scope_membership_not_collected")
        restricted = {f"/administrativeunits/{aid}" for aid, flag in member_of if flag is True}
        if restricted and not any(_low(scope) in restricted for scope in role_scopes):
            continue
        if incomplete_au:
            reasons.append("administrative_unit_membership_not_collected")
        if any(_low(scope).startswith("/administrativeunits/") for scope in role_scopes):
            roles = [role for pid in (tid, *user.attrs.get("groups", ()))
                     for role, _, _ in model.dir_assignments.get(pid, ())]
            if roles and not any(_low(scope) == "/" for scope in role_scopes):
                continue  # AU-scoped Authentication Administrators can manage non-admin users only.
        if source.attrs.get("account_enabled") is not True or user.attrs.get("account_enabled") is not True:
            reasons.append("source_or_target_enabled_state_unavailable")
        domain = _low(user.attrs.get("upn")).partition("@")[2]
        if domains.get(domain) == "federated":
            if tap and _low(tap.get("state")) == "disabled":
                continue
            if tap is None:
                reasons.append("federated_user_tap_policy_not_collected")
            elif _low(tap.get("state")) != "enabled":
                reasons.append("federated_user_tap_policy_state_unknown")
            else:
                included, excluded = _targets(tap, "includeTargets"), _targets(tap, "excludeTargets")
                if included is None or excluded is None:
                    reasons.append("tap_policy_targets_not_collected")
                else:
                    referenced = (included | excluded) - {"all_users"}
                    membership_incomplete = any(model.membership_status.get(group) not in ("collected", "empty")
                                                for group in referenced)
                    if groups & excluded or "all_users" in excluded:
                        continue
                    if "all_users" not in included and not groups & included:
                        if membership_incomplete:
                            reasons.append("tap_group_membership_incomplete")
                        else:
                            continue
                    elif membership_incomplete:
                        reasons.append("tap_group_membership_incomplete")
                    reasons.append("federated_user_tap_required")
        elif not domains or domain not in domains:
            reasons.append("target_domain_authentication_not_collected")
        if user.attrs.get("on_prem_sync") is True:
            reasons.append("password_writeback_or_tap_required")
        out[tid] = (("conditional", ",".join(reasons)) if reasons else None)
    return out
