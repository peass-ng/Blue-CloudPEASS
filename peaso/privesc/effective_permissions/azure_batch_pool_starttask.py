"""Confirm a writable Batch start task reaches the pool's current identity."""
from __future__ import annotations

from . import inventory_status, items
from .azure_batch_pool_assign import ACCOUNT, POOL


WRITE = {"action": "Microsoft.Batch/batchAccounts/pools/write"}


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
    pool_status = inventory_status(model.snapshot, "batch_pool")
    account_status = inventory_status(model.snapshot, "batch_account")
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
            if str((pool.get("properties") or {}).get("provisioningState") or "").lower() in ("failed", "deleting"):
                continue
            if str((account.get("properties") or {}).get("provisioningState") or "").lower() in ("failed", "deleting"):
                continue
            identity = pool.get("identity") or {}
            if str(identity.get("type") or "").lower() != "userassigned":
                continue
            assigned = {str(resource).lower(): detail for resource, detail in
                        (identity.get("userAssignedIdentities") or {}).items()}.get(uai)
            if not isinstance(assigned, dict) or assigned.get("principalId") and str(
                    assigned["principalId"]).lower() != tid.lower():
                continue
            if target.attrs.get("uai_resource_verified") is not True:
                unresolved |= identity_status.get(target.scope) not in ("collected", "empty")
                continue
            grant = model.cached_check(source, WRITE, pool_id)
            if grant is None:
                continue
            if grant.confidence == "unknown":
                unresolved = True
                continue
            out[tid] = ("conditional", "batch_starttask_awaits_node_join_or_restart")
            break
        else:
            if unresolved:
                out[tid] = ("unknown", "batch_pool_identity_or_write_unverified")
    return out
