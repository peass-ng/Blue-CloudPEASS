"""Join current Entra role eligibility to self-activation policy and source identity."""
from __future__ import annotations

from datetime import datetime, timezone

from . import inventory_status, items, unavailable


def _low(value):
    return str(value or "").casefold()


def _live(item, now):
    try:
        start = item.get("startDateTime")
        end = item.get("endDateTime")
        return ((not start or datetime.fromisoformat(str(start).replace("Z", "+00:00")) <= now)
                and (not end or datetime.fromisoformat(str(end).replace("Z", "+00:00")) > now))
    except (TypeError, ValueError):
        return False


def select(model, candidates, source):
    if source is None or source.kind != "azure_user" or source.attrs.get("account_enabled") is False:
        return {}
    principals = {source.id, *source.attrs.get("groups", ())}
    policies = {}
    for _, item in items(model.snapshot, "directory_role_pim_policy"):
        if item.get("scopeId") == "/" and _low(item.get("scopeType")) in ("directory", "directoryrole"):
            policies.setdefault(_low(item.get("roleDefinitionId")), []).append(item)
    policy_status = inventory_status(model.snapshot, "directory_role_pim_policy")
    policy_complete = bool(policy_status) and not unavailable(policy_status)
    active_instances = list(items(model.snapshot, "directory_role_assignment_instance"))
    now = datetime.now(timezone.utc)
    out = {}
    for tid, target in candidates.items():
        info = model.dir_roles.get(_low(target.attrs.get("template_id")))
        if info is None or info.get("enabled") is False:
            continue
        role_ids = {_low(info.get("id")), _low(info.get("def_id"))}
        eligibilities = [item for item in model._eligibilities()
                         if item.get("principalId") in principals
                         and _low(item.get("roleDefinitionId")) in role_ids]
        if not eligibilities:
            continue
        possible = []
        for eligibility in eligibilities:
            pid = eligibility.get("principalId")
            if pid != source.id:
                group = model.principals.get(pid)
                if group is None or group.kind != "entra_group" or group.attrs.get("assignable_to_role") is False:
                    continue
            scope = eligibility.get("directoryScopeId") or "/"
            active = any(p in principals and _low(r) in role_ids and
                         ((s or "/") == "/" or (s or "/") == scope)
                         for p in principals for r, s, _ in model.dir_assignments.get(p, ()))
            active = active or any(item.get("principalId") in principals
                                   and _low(item.get("roleDefinitionId")) in role_ids
                                   and ((item.get("directoryScopeId") or "/") == "/"
                                        or (item.get("directoryScopeId") or "/") == scope)
                                   and _live(item, now) for _, item in active_instances)
            if not active:
                possible.append(eligibility)
        if not possible:
            continue
        assigned_policies = [row for role in role_ids for row in policies.get(role, ())]
        if policy_complete and len(assigned_policies) == 1:
            rules = (assigned_policies[0].get("policy") or {}).get("rules")
            approvals = [r for r in rules if isinstance(r, dict)
                         and _low(r.get("id")) == "approval_enduser_assignment"] if isinstance(rules, list) else []
            if len(approvals) == 1 and isinstance(approvals[0].get("setting"), dict):
                required = approvals[0]["setting"].get("isApprovalRequired")
                if required is True:
                    continue  # Another principal must approve; this is not self-activation.
        reasons = []
        if not policy_complete or len(assigned_policies) != 1:
            reasons.append("pim_role_policy_not_collected")
        elif not isinstance((assigned_policies[0].get("policy") or {}).get("rules"), list):
            reasons.append("pim_role_approval_rule_not_collected")
        if any((item.get("directoryScopeId") or "/") != "/" for item in possible):
            reasons.append("pim_eligibility_scope_restricted")
        if source.attrs.get("account_enabled") is not True:
            reasons.append("source_enabled_state_not_collected")
        out[tid] = ("conditional", ",".join(reasons or ["pim_role_activation_requirements"]))
    return out
