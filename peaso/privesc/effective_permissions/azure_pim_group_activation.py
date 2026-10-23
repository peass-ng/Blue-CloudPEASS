"""Validate user self-activation of PIM for Groups membership or ownership."""
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


def _policy(model, group_id, access_id):
    kind = "directory_group_pim_policy" if access_id == "member" else "directory_group_pim_owner_policy"
    status = {_low(scope): value for scope, value in inventory_status(model.snapshot, kind).items()}
    scope = f"/tenants/{model.tenant}/groups/{group_id}".casefold()
    if status.get(scope) not in ("collected", "empty") or unavailable(status):
        return "unknown"
    matching = [item for _, item in items(model.snapshot, kind)
                if _low(item.get("scopeId")) == _low(group_id)
                and _low(item.get("roleDefinitionId")) == access_id]
    if len(matching) != 1:
        return "unknown"
    rules = (matching[0].get("policy") or {}).get("rules")
    approval = [rule for rule in rules if isinstance(rule, dict)
                and _low(rule.get("id")) == "approval_enduser_assignment"] if isinstance(rules, list) else []
    if len(approval) != 1 or not isinstance(approval[0].get("setting"), dict):
        return "unknown"
    required = approval[0]["setting"].get("isApprovalRequired")
    return "required" if required is True else "open" if required is False else "unknown"


def select(model, candidates, source):
    if source is None or source.kind != "azure_user" or source.attrs.get("account_enabled") is False:
        return {}
    schedules = list(items(model.snapshot, "directory_group_eligibility_schedule"))
    instances = list(items(model.snapshot, "directory_group_eligibility_instance"))
    schedule_status = {_low(scope): value for scope, value in
                       inventory_status(model.snapshot, "directory_group_eligibility_schedule").items()}
    instance_status = {_low(scope): value for scope, value in
                       inventory_status(model.snapshot, "directory_group_eligibility_instance").items()}
    membership_status = {_low(scope): value for scope, value in
                         inventory_status(model.snapshot, "directory_membership").items()}
    owner_status = {_low(scope): value for scope, value in
                    inventory_status(model.snapshot, "directory_owner").items()}
    current_groups = {_low(group) for group in model._groups(source.id)}
    known_owned = {_low(item.get("objectId")) for _, item in items(model.snapshot, "directory_owner")
                   if _low(item.get("objectType")) == "group"
                   and source.id in (item.get("ownerIds") or [])}
    now = datetime.now(timezone.utc)
    out = {}
    for tid, group in candidates.items():
        scope = f"/tenants/{model.tenant}/groups/{tid}".casefold()
        types = group.attrs.get("group_types")
        mail = group.attrs.get("mail_enabled")
        security = group.attrs.get("security_enabled")
        if not isinstance(types, list) or mail is None or security is None:
            out[tid] = ("unknown", "pim_group_type_not_collected")
            continue
        if "DynamicMembership" in types or ("Unified" not in types and (security is not True or mail is not False)):
            continue
        if group.attrs.get("on_prem_sync") is True:
            continue
        viable = []
        for access in ("member", "owner"):
            if access == "member" and _low(tid) in current_groups:
                continue
            if access == "owner" and (_low(tid) in known_owned or _low(tid) in current_groups):
                continue
            live = [item for _, item in instances
                    if item.get("principalId") == source.id and _low(item.get("groupId")) == _low(tid)
                    and _low(item.get("accessId")) == access and _live(item, now)]
            if instance_status.get(scope) in ("collected", "empty") and not live:
                continue
            recorded = [item for _, item in schedules
                        if item.get("principalId") == source.id and _low(item.get("groupId")) == _low(tid)
                        and _low(item.get("accessId")) == access
                        and _low(item.get("status") or "provisioned") in ("provisioned", "granted", "scheduled")]
            if not live and not recorded:
                continue
            policy = _policy(model, tid, access)
            if policy == "required":
                continue
            reasons = ["pim_group_activation_required"]
            if policy == "unknown":
                reasons.append("pim_group_activation_policy_not_collected")
            if not live:
                reasons.append("pim_group_eligibility_instance_not_collected")
            if access == "member" and membership_status.get(scope) not in ("collected", "empty"):
                reasons.append("group_membership_inventory_incomplete")
            if access == "owner" and owner_status.get(scope) not in ("collected", "empty"):
                reasons.append("group_owner_inventory_incomplete")
            if group.attrs.get("on_prem_sync_recorded") is not True:
                reasons.append("group_source_of_authority_not_collected")
            if source.attrs.get("account_enabled") is not True:
                reasons.append("source_enabled_state_not_collected")
            viable.append((access, reasons))
        if viable:
            access, reasons = min(viable, key=lambda pair: len(pair[1]))
            out[tid] = ("conditional", ",".join([f"pim_{access}_eligibility", *reasons]))
        elif (schedule_status.get(scope) not in ("collected", "empty")
              and instance_status.get(scope) not in ("collected", "empty")):
            out[tid] = ("unknown", "pim_group_eligibility_not_collected")
    return out
