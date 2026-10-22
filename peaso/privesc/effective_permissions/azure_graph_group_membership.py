"""Verify Graph can add the calling service principal to a new group."""
from __future__ import annotations

from . import ANY, inventory_status, items, unavailable


def select_controlled_user(model, candidates, source):
    if (source is None or source.kind not in ("azure_service_principal", "azure_managed_identity")
            or source.attrs.get("account_enabled") is not True):
        return {}
    membership = inventory_status(model.snapshot, "directory_membership")
    if not membership:
        return None
    incomplete = bool(unavailable(membership))
    statuses = {str(scope).casefold(): status for scope, status in membership.items()}
    out = {}
    for tid, target in candidates.items():
        if target.kind != "entra_group":
            continue
        group_types = target.attrs.get("group_types")
        mail_enabled = target.attrs.get("mail_enabled")
        security_enabled = target.attrs.get("security_enabled")
        if not isinstance(group_types, list) or mail_enabled is None or security_enabled is None:
            out[tid] = ("unknown", "graph_group_type_unavailable")
            continue
        unified = "Unified" in group_types
        if not unified and (mail_enabled is not False or security_enabled is not True):
            continue
        scope = f"/tenants/{model.tenant}/groups/{target.id}".casefold()
        if statuses.get(scope) not in ("collected", "empty") or incomplete:
            out[tid] = ("unknown", "group_membership_inventory_incomplete")
        else:
            out[tid] = ("conditional", "controlled_user_must_not_already_be_member")
    return out


def select_service_principal(model, candidates, source):
    if (source is None or source.kind not in ("azure_service_principal", "azure_managed_identity")
            or source.attrs.get("account_enabled") is not True):
        return {}
    if not any((grant := model.cached_check(source, {"graph_app_permission": permission}, ANY))
               is not None and grant.confidence != "unknown"
               for permission in ("Application.ReadWrite.All", "Directory.ReadWrite.All")):
        return {}
    membership = inventory_status(model.snapshot, "directory_membership")
    if not membership:
        return None
    incomplete = bool(unavailable(membership))
    statuses = {str(scope).casefold(): status for scope, status in membership.items()}
    out = {}
    for tid, target in candidates.items():
        if target.kind != "entra_group":
            continue
        group_types = target.attrs.get("group_types")
        mail_enabled = target.attrs.get("mail_enabled")
        security_enabled = target.attrs.get("security_enabled")
        if not isinstance(group_types, list) or mail_enabled is None or security_enabled is None:
            out[tid] = ("unknown", "graph_group_type_unavailable")
            continue
        if "Unified" in group_types or mail_enabled is not False or security_enabled is not True:
            continue
        scope = f"/tenants/{model.tenant}/groups/{target.id}".casefold()
        if statuses.get(scope) not in ("collected", "empty") or incomplete:
            out[tid] = ("unknown", "group_membership_inventory_incomplete")
            continue
        if target.id.casefold() not in {str(g).casefold() for g in source.attrs.get("groups", ())}:
            out[tid] = None
    return out


def select_pim_active_service_principal(model, candidates, source):
    """A time-limited active PIM request can add the calling app to a security group."""
    if (source is None or source.kind not in ("azure_service_principal", "azure_managed_identity")
            or source.attrs.get("account_enabled") is not True):
        return {}
    membership = inventory_status(model.snapshot, "directory_membership")
    if not membership:
        return None
    incomplete = bool(unavailable(membership))
    statuses = {str(scope).casefold(): status for scope, status in membership.items()}
    out = {}
    for tid, target in candidates.items():
        if target.kind != "entra_group":
            continue
        group_types = target.attrs.get("group_types")
        mail_enabled = target.attrs.get("mail_enabled")
        security_enabled = target.attrs.get("security_enabled")
        if not isinstance(group_types, list) or mail_enabled is None or security_enabled is None:
            out[tid] = ("unknown", "pim_group_type_unavailable")
            continue
        if "Unified" in group_types or mail_enabled is not False or security_enabled is not True:
            continue
        scope = f"/tenants/{model.tenant}/groups/{target.id}".casefold()
        if statuses.get(scope) not in ("collected", "empty") or incomplete:
            out[tid] = ("unknown", "pim_group_membership_inventory_incomplete")
            continue
        if target.id.casefold() not in {str(g).casefold() for g in source.attrs.get("groups", ())}:
            out[tid] = None
    return out


def select_pim_controlled_user_eligibility(model, candidates, source):
    """Keep an eligibility route only if a controlled user can activate it."""
    supported = select_controlled_user(model, candidates, source)
    if not supported:
        return supported
    policy_status = {str(scope).casefold(): status for scope, status in
                     inventory_status(model.snapshot, "directory_group_pim_policy").items()}
    by_group = {}
    for _, item in items(model.snapshot, "directory_group_pim_policy"):
        by_group.setdefault(str(item.get("scopeId", "")).casefold(), []).append(item)
    policy_write = model.cached_check(source,
        {"graph_app_permission": "RoleManagementPolicy.ReadWrite.AzureADGroup"}, ANY)
    out = {}
    for tid, result in supported.items():
        if result is not None and result[0] == "unknown":
            out[tid] = result
            continue
        scope = f"/tenants/{model.tenant}/groups/{tid}".casefold()
        status = policy_status.get(scope)
        if status not in ("collected", "empty"):
            out[tid] = ("conditional", "pim_group_activation_policy_not_collected")
            continue
        policies = by_group.get(tid.casefold(), [])
        if len(policies) != 1:
            out[tid] = ("conditional", "pim_group_activation_policy_not_established")
            continue
        rules = policies[0].get("policy", {}).get("rules")
        if not isinstance(rules, list):
            out[tid] = ("conditional", "pim_group_activation_rules_not_collected")
            continue
        approval = [rule for rule in rules if isinstance(rule, dict)
                    and str(rule.get("id", "")).casefold() == "approval_enduser_assignment"]
        if len(approval) != 1 or not isinstance(approval[0].get("setting"), dict) or \
                not isinstance(approval[0]["setting"].get("isApprovalRequired"), bool):
            out[tid] = ("conditional", "pim_group_approval_rule_not_collected")
        elif approval[0]["setting"]["isApprovalRequired"] is True:
            if policy_write is not None and policy_write.confidence == "derived":
                out[tid] = ("conditional", "pim_approval_policy_change_required")
        else:
            out[tid] = ("conditional", "pim_user_activation_required")
    return out
