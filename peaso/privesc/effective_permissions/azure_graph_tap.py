"""Bind Graph Temporary Access Pass issuance to eligible internal users."""
from __future__ import annotations

from . import ANY, inventory_status, items, unavailable


def _low(value):
    return str(value or "").casefold()


def _external_user(user):
    if _low(user.attrs.get("creation_type")) == "invitation":
        return True
    if "#ext#" in _low(user.attrs.get("upn")):
        return True
    for identity in user.attrs.get("identities") or ():
        if not isinstance(identity, dict):
            continue
        issuer = _low(identity.get("issuer"))
        if issuer in ("externalazuread", "microsoftaccount", "google.com", "facebook.com"):
            return True
    return False


def _targets(policy, key):
    rows = policy.get(key)
    if not isinstance(rows, list):
        return None
    return {_low(row.get("id")) for row in rows if isinstance(row, dict)
            and _low(row.get("targetType")) == "group" and row.get("id")}


def select(model, candidates, source):
    if source is None or source.kind not in ("azure_service_principal", "azure_managed_identity"):
        return {}
    if source.attrs.get("account_enabled") is False:
        return {}
    policy_status = inventory_status(model.snapshot, "temporary_access_pass_policy")
    policies = [policy for _, policy in items(model.snapshot, "temporary_access_pass_policy")]
    policy = policies[0] if len(policies) == 1 and policy_status and not unavailable(policy_status) else None
    can_change_policy = model.cached_check(source,
        {"graph_app_permission": "Policy.ReadWrite.AuthenticationMethod"}, ANY)
    can_change_policy = can_change_policy is not None and can_change_policy.confidence == "derived"
    out = {}
    for tid, user in candidates.items():
        if user.kind != "azure_user" or user.attrs.get("account_enabled") is False or _external_user(user):
            continue
        if source.attrs.get("account_enabled") is not True or user.attrs.get("account_enabled") is not True:
            out[tid] = ("conditional", "tap_source_or_user_enabled_state_unavailable")
            continue
        if not user.attrs.get("creation_type_recorded"):
            out[tid] = ("conditional", "tap_user_origin_not_collected")
            continue
        if policy is None:
            out[tid] = ("conditional", "tap_policy_not_collected")
            continue
        state = _low(policy.get("state"))
        if state != "enabled":
            if state == "disabled" and can_change_policy:
                out[tid] = ("conditional", "tap_policy_change_required")
            elif state not in ("enabled", "disabled"):
                out[tid] = ("conditional", "tap_policy_state_unavailable")
            continue
        included, excluded = _targets(policy, "includeTargets"), _targets(policy, "excludeTargets")
        if included is None or excluded is None:
            out[tid] = ("conditional", "tap_policy_targets_not_collected")
            continue
        groups = {_low(group) for group in model._groups(tid)}
        referenced = (included | excluded) - {"all_users"}
        incomplete = any(model.membership_status.get(group) not in ("collected", "empty") for group in referenced)
        if groups & excluded:
            if can_change_policy:
                out[tid] = ("conditional", "tap_policy_exclusion_change_required")
            continue
        if "all_users" not in included and not groups & included:
            if can_change_policy:
                out[tid] = ("conditional", "tap_policy_inclusion_change_required")
            elif incomplete:
                out[tid] = ("conditional", "tap_group_membership_incomplete")
            continue
        out[tid] = (("conditional", "tap_group_membership_incomplete") if incomplete else None)
    return out
