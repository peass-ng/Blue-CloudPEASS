"""Join Batch account key access to a pool with an executable identity."""
from __future__ import annotations

from . import inventory_status, items
from .azure_batch_pool_assign import ACCOUNT, POOL


KEY_ACTIONS = ("Microsoft.Batch/batchAccounts/listkeys/action",
               "Microsoft.Batch/batchAccounts/regeneratekeys/action")
ACCOUNT_WRITE = {"action": "Microsoft.Batch/batchAccounts/write"}


def select(model, candidates, source):
    if source is None:
        return {}
    accounts = {str(row.get("id") or "").lower(): row
                for _, row in items(model.snapshot, "batch_account")
                if str(row.get("type") or "").lower() == "microsoft.batch/batchaccounts"
                and ACCOUNT.fullmatch(str(row.get("id") or "").lower())}
    pools = {str(row.get("id") or "").lower(): row
             for _, row in items(model.snapshot, "batch_pool")
             if str(row.get("type") or "").lower() == "microsoft.batch/batchaccounts/pools"
             and POOL.fullmatch(str(row.get("id") or "").lower())}
    account_status = inventory_status(model.snapshot, "batch_account")
    pool_status = inventory_status(model.snapshot, "batch_pool")
    identity_status = inventory_status(model.snapshot, "managed_identity")
    out = {}
    for tid, target in candidates.items():
        uai = str(target.attrs.get("uai_resource") or "").lower()
        if target.attrs.get("mi_type") != "user_assigned" or not uai:
            continue
        unresolved = False
        for host in target.attrs.get("hosts", ()):
            pool_id = str(host).lower()
            if not POOL.fullmatch(pool_id):
                continue
            account_id = pool_id.rsplit("/pools/", 1)[0]
            subscription = account_id.split("/resourcegroups/", 1)[0]
            pool = pools.get(pool_id)
            if pool is None:
                unresolved |= pool_status.get(subscription) not in ("collected", "empty")
                continue
            account = accounts.get(account_id)
            if account is None:
                unresolved |= account_status.get(subscription) not in ("collected", "empty")
                continue
            account_props = account.get("properties") or {}
            pool_props = pool.get("properties") or {}
            if str(account_props.get("provisioningState") or "").lower() in ("failed", "deleting"):
                continue
            if str(pool_props.get("provisioningState") or "").lower() in ("failed", "deleting"):
                continue
            identity = pool.get("identity") or {}
            assigned = {str(key).lower(): value for key, value in
                        (identity.get("userAssignedIdentities") or {}).items()}.get(uai)
            if (str(identity.get("type") or "").lower() != "userassigned"
                    or not isinstance(assigned, dict)
                    or assigned.get("principalId") and str(assigned["principalId"]).lower() != tid.lower()):
                continue
            if target.attrs.get("uai_resource_verified") is not True:
                unresolved |= identity_status.get(target.scope) not in ("collected", "empty")
                continue
            keys = [model.cached_check(source, {"action": action}, account_id) for action in KEY_ACTIONS]
            grants = [grant for grant in keys if grant is not None]
            if not grants:
                continue
            modes = account_props.get("allowedAuthenticationModes")
            if isinstance(modes, list):
                if not any(str(mode).lower() == "sharedkey" for mode in modes):
                    write = model.cached_check(source, ACCOUNT_WRITE, account_id)
                    if write is None:
                        continue
                    if write.confidence == "unknown":
                        unresolved = True
                        continue
            else:
                write = model.cached_check(source, ACCOUNT_WRITE, account_id)
                if write is None or write.confidence == "unknown":
                    unresolved = True
                    continue
            if all(grant.confidence == "unknown" for grant in grants):
                unresolved = True
                continue
            out[tid] = ("conditional", "batch_shared_key_task_or_pool_allocation")
            break
        else:
            if unresolved:
                out[tid] = ("unknown", "batch_account_key_or_pool_unverified")
    return out
