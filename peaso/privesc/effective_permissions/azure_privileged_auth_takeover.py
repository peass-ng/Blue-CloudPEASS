"""Check the usable credential reset routes of privileged Entra roles."""
from __future__ import annotations

from . import ANY, inventory_status, items, unavailable
from .azure_graph_tap import _external_user, _targets


ROLES = {"privileged authentication administrator", "global administrator", "partner tier2 support"}
APP_PASSWORD = "User-PasswordProfile.ReadWrite.All"
APP_TAP = ("UserAuthMethod-TAP.ReadWrite.All", "UserAuthenticationMethod.ReadWrite.All")


def _low(value):
    return str(value or "").casefold()


def _app_grant(model, source, permission):
    grant = model.check(source, {"graph_app_permission": permission}, ANY)
    return grant is not None and grant.confidence == "derived"


def select(model, candidates, source):
    if source is None or source.kind not in ("azure_user", "azure_service_principal", "azure_managed_identity"):
        return {}
    if source.attrs.get("account_enabled") is False:
        return {}
    app = source.kind != "azure_user"
    password_app = not app or _app_grant(model, source, APP_PASSWORD)
    tap_app = not app or any(_app_grant(model, source, permission) for permission in APP_TAP)
    app_status = inventory_status(model.snapshot, "directory_app_role_assignment")
    app_grants_missing = app and (not app_status or bool(unavailable(app_status)))
    if app and not (password_app or tap_app or app_grants_missing):
        return {}

    role_scopes = []
    for pid in (source.id, *source.attrs.get("groups", ())):
        for role, scope, _ in model.dir_assignments.get(pid, ()):
            info = model.dir_roles.get(role)
            if info and _low(info.get("name")) in ROLES:
                role_scopes.append(_low(scope or "/"))
    if not role_scopes:
        return {}
    au_app_read_unverified = False
    if app and all(scope.startswith("/administrativeunits/") for scope in role_scopes):
        au_app_read_unverified = not any(
            info and _low(info.get("name")) == "directory readers" and _low(scope or "/") == "/"
            for pid in (source.id, *source.attrs.get("groups", ()))
            for role, scope, _ in model.dir_assignments.get(pid, ())
            if (info := model.dir_roles.get(role)) is not None)

    au_status = inventory_status(model.snapshot, "directory_administrative_unit")
    units = [row for _, row in items(model.snapshot, "directory_administrative_unit")]
    domains = {_low(row.get("id")): _low(row.get("authenticationType"))
               for _, row in items(model.snapshot, "directory_domain") if row.get("id")}
    policy_status = inventory_status(model.snapshot, "temporary_access_pass_policy")
    policies = [row for _, row in items(model.snapshot, "temporary_access_pass_policy")]
    policy = policies[0] if len(policies) == 1 and policy_status and not unavailable(policy_status) else None
    out = {}
    for tid, user in candidates.items():
        if user.kind != "azure_user" or user.attrs.get("account_enabled") is False or _external_user(user):
            continue
        reasons = []
        if source.attrs.get("account_enabled") is not True or user.attrs.get("account_enabled") is not True:
            reasons.append("source_or_target_enabled_state_unavailable")
        restricted = set()
        member_units = set()
        au_incomplete = not au_status or bool(unavailable(au_status))
        for unit in units:
            members = unit.get("memberIds")
            if not isinstance(members, list):
                au_incomplete = True
                continue
            if _low(tid) in {_low(member) for member in members}:
                unit_scope = "/administrativeunits/" + _low(unit.get("id"))
                member_units.add(unit_scope)
                if unit.get("isMemberManagementRestricted") is True:
                    restricted.add(unit_scope)
        if not any(scope in ("/", "/" + _low(tid)) or scope in member_units for scope in role_scopes):
            if not au_incomplete:
                continue
            reasons.append("source_au_scope_membership_not_collected")
        target_roles = [model.dir_roles.get(role) for pid in (tid, *user.attrs.get("groups", ()))
                        for role, _, _ in model.dir_assignments.get(pid, ())]
        if all(scope.startswith("/administrativeunits/") for scope in role_scopes) and target_roles:
            if any(info is not None for info in target_roles):
                reasons.append("au_scoped_admin_credential_management_requires_validation")
            else:
                reasons.append("target_directory_role_definition_not_collected")
        restricted_ga = False
        if restricted:
            if not any(scope in restricted for scope in role_scopes):
                continue
            restricted_ga = any(info and _low(info.get("name")) == "global administrator"
                                for info in target_roles)
        if au_incomplete:
            reasons.append("administrative_unit_membership_not_collected")
        if app_grants_missing:
            reasons.append("graph_application_grants_not_collected")
        if au_app_read_unverified:
            reasons.append("au_scoped_application_directory_read_not_verified")

        domain = _low(user.attrs.get("upn")).partition("@")[2]
        auth_type = domains.get(domain)
        password_possible = password_app and auth_type != "federated" and not restricted_ga
        if password_possible:
            if not auth_type:
                reasons.append("target_domain_authentication_not_collected")
            if user.attrs.get("on_prem_sync") is True:
                reasons.append("password_writeback_required")

        tap_possible = False
        tap_incomplete = False
        if tap_app:
            if policy is None:
                tap_incomplete = True
            elif _low(policy.get("state")) == "enabled":
                included, excluded = _targets(policy, "includeTargets"), _targets(policy, "excludeTargets")
                if included is None or excluded is None:
                    tap_incomplete = True
                else:
                    groups = {_low(group) for group in model._groups(tid)}
                    refs = (included | excluded) - {"all_users"}
                    member_incomplete = any(model.membership_status.get(group) not in ("collected", "empty")
                                            for group in refs)
                    if "all_users" not in excluded and not groups & excluded:
                        tap_possible = "all_users" in included or bool(groups & included)
                        tap_incomplete = member_incomplete
            elif _low(policy.get("state")) != "disabled":
                tap_incomplete = True

        if not password_possible and not tap_possible and not tap_incomplete and not app_grants_missing:
            continue
        if not password_possible and not tap_possible:
            reasons.append("tap_policy_or_grant_not_collected")
        if restricted_ga:
            reasons.append("restricted_au_global_admin_tap_requires_validation")
        if tap_possible and tap_incomplete and not password_possible:
            reasons.append("tap_group_membership_incomplete")
        out[tid] = (("conditional", ",".join(dict.fromkeys(reasons))) if reasons else None)
    return out
