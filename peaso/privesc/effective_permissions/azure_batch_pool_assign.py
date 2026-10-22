"""Bind Batch pool identity attachment to an exact writable pool path."""
from __future__ import annotations

import re

from . import inventory_status, items


ACCOUNT = re.compile(
    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.batch/batchaccounts/[^/]+")
POOL = re.compile(ACCOUNT.pattern + r"/pools/[^/]+")
UAI = re.compile(
    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.managedidentity/userassignedidentities/[^/]+")
WRITE = {"action": "Microsoft.Batch/batchAccounts/pools/write"}


def _subscription(resource):
    match = re.match(r"/subscriptions/[^/]+", resource)
    return match.group(0) if match else ""


def _valid(row, kind, pattern):
    rid = str(row.get("id") or "").lower()
    return rid if row.get("type", "").lower() == kind and pattern.fullmatch(rid) else ""


def select(model, candidates, source):
    if source is None:
        return {}
    account_type = "microsoft.batch/batchaccounts"
    accounts = {}
    for _, row in items(model.snapshot, "batch_account"):
        rid = _valid(row, account_type, ACCOUNT)
        if rid and str((row.get("properties") or {}).get("provisioningState") or "").lower() not in ("failed", "deleting"):
            accounts[rid] = row
    pools = {}
    for _, row in items(model.snapshot, "batch_pool"):
        rid = _valid(row, account_type + "/pools", POOL)
        if rid and rid.rsplit("/pools/", 1)[0] in accounts and str(
                (row.get("properties") or {}).get("provisioningState") or "").lower() not in ("failed", "deleting"):
            pools[rid] = row
    paths = set(pools)
    for account in accounts:
        name = "peassprobe"
        suffix = 0
        while account + "/pools/" + name in pools:
            suffix += 1
            name = "peassprobe" + str(suffix)
        paths.add(account + "/pools/" + name)
    grants = [model.cached_check(source, WRITE, path) for path in sorted(paths)]
    known = [grant for grant in grants if grant is not None]
    accounts_status = inventory_status(model.snapshot, "batch_account")
    pools_status = inventory_status(model.snapshot, "batch_pool")
    identity_status = inventory_status(model.snapshot, "managed_identity")
    unresolved_accounts = not model.exact_scopes or any(
        accounts_status.get(scope) not in ("collected", "empty") for scope in model.exact_scopes)
    unresolved_pools = not model.exact_scopes or any(
        pools_status.get(scope) not in ("collected", "empty") for scope in model.exact_scopes)
    out = {}
    for tid, target in candidates.items():
        uai = str(target.attrs.get("uai_resource") or "").lower()
        if target.attrs.get("mi_type") != "user_assigned" or not UAI.fullmatch(uai):
            continue
        if target.attrs.get("uai_resource_verified") is not True:
            if identity_status.get(_subscription(uai)) not in ("collected", "empty"):
                out[tid] = ("unknown", "batch_identity_inventory_incomplete")
            continue
        if any(grant.confidence != "unknown" for grant in known):
            out[tid] = ("conditional", "batch_pool_node_allocation_or_recreation")
        elif known or unresolved_accounts or unresolved_pools:
            out[tid] = ("unknown", "batch_pool_write_or_account_unverified")
    return out
