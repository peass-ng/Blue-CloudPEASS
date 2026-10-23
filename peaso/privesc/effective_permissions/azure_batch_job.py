"""Join Batch data actions to a runnable pool and its exact identity."""
from __future__ import annotations

import re

from . import inventory_status, items


POOL = re.compile(r"(/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.batch/batchaccounts/[^/]+)/pools/[^/]+")
ACTIONS = ("Microsoft.Batch/batchAccounts/jobs/write",
           "Microsoft.Batch/batchAccounts/jobSchedules/write")


def _nodes(props):
    values = [props.get(key) for key in ("currentDedicatedNodes", "currentLowPriorityNodes",
                                            "targetDedicatedNodes", "targetLowPriorityNodes")]
    if any(isinstance(value, int) and not isinstance(value, bool) and value > 0 for value in values):
        return "possible"
    if props.get("enableAutoScale") is True:
        return "possible"
    if all(isinstance(value, int) and not isinstance(value, bool) and value == 0 for value in values):
        return "none"
    return "unknown"


def select(model, candidates, source):
    if source is None:
        return {}
    accounts = {str(row.get("id") or "").lower(): row for _, row in items(model.snapshot, "batch_account")}
    pools = {str(row.get("id") or "").lower(): row for _, row in items(model.snapshot, "batch_pool")}
    pool_status = inventory_status(model.snapshot, "batch_pool")
    account_status = inventory_status(model.snapshot, "batch_account")
    out = {}
    for tid, target in candidates.items():
        uai = str(target.attrs.get("uai_resource") or "").lower()
        if target.attrs.get("mi_type") != "user_assigned" or not uai:
            continue
        for host in target.attrs.get("hosts", ()):
            pool_id = str(host).lower()
            match = POOL.fullmatch(pool_id)
            if not match:
                continue
            account = match.group(1)
            subscription = account.split("/resourcegroups/", 1)[0]
            pool = pools.get(pool_id)
            if pool is None:
                if pool_status.get(subscription) not in ("collected", "empty"):
                    out[tid] = ("unknown", "batch_pool_inventory_incomplete")
                continue
            identity = pool.get("identity") or {}
            assigned = {str(key).lower(): value for key, value in
                        (identity.get("userAssignedIdentities") or {}).items()}.get(uai)
            if (str(identity.get("type") or "").lower() != "userassigned"
                    or not isinstance(assigned, dict)
                    or assigned.get("principalId") and str(assigned["principalId"]).lower() != tid.lower()):
                continue
            account_row = accounts.get(account)
            if account_row is None:
                if account_status.get(subscription) not in ("collected", "empty"):
                    out[tid] = ("unknown", "batch_account_inventory_incomplete")
                continue
            modes = (account_row.get("properties") or {}).get("allowedAuthenticationModes")
            if isinstance(modes, list) and not any(str(mode).lower() == "aad" for mode in modes):
                continue
            grants = [model.cached_check(source, {"action": action, "data_action": True}, account)
                      for action in ACTIONS]
            available = [grant for grant in grants if grant is not None]
            if not available:
                continue
            props = pool.get("properties") or {}
            if str(props.get("provisioningState") or "").lower() in ("failed", "deleting"):
                continue
            node_state = _nodes(props)
            if node_state == "none":
                continue
            state = ("unknown" if node_state == "unknown" or not isinstance(modes, list)
                     or all(grant.confidence == "unknown" for grant in available) else "conditional")
            previous = out.get(tid)
            if previous is None or previous[0] == "unknown" and state == "conditional":
                out[tid] = (state, "batch_job_pool_identity_execution")
    return out
