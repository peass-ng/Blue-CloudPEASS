"""Batch pool identity attachment needs an exact writable pool path and verified UAMI."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-batch-pool-write-assign-user-assigned-identity"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)
ACCOUNT = RG + "/providers/Microsoft.Batch/batchAccounts/main"
OTHER = RG + "/providers/Microsoft.Batch/batchAccounts/other"
POOL = ACCOUNT + "/pools/work"
UAI = RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/worker"
WRITE_ROLE = "22222222-2222-2222-2222-222222222222"
WRITE = "Microsoft.Batch/batchAccounts/pools/write"
ASSIGN = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"


def _run(*, write_scope=ACCOUNT, assign=True, account_status="collected", pool_status="empty",
         identity_status="collected", account_state="Succeeded", pool_state="Succeeded"):
    assignments = [("u-alice", "User", write_scope, WRITE_ROLE)]
    if assign:
        assignments.append(("u-alice", "User", UAI, ROLE_ID))
    accounts = [{"id": ACCOUNT, "type": "Microsoft.Batch/batchAccounts",
                 "properties": {"provisioningState": account_state}}] if account_status == "collected" else []
    pools = [{"id": POOL, "type": "Microsoft.Batch/batchAccounts/pools",
              "properties": {"provisioningState": pool_state}}] if pool_status == "collected" else []
    identities = [{"id": UAI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                   "properties": {"principalId": "mi-worker", "clientId": "worker-client"}}]
    snap = az(assignments, roles={ROLE_ID: ([ASSIGN], []), WRITE_ROLE: ([WRITE], [])},
              extra=[("batch_account", SUB, accounts, account_status),
                     ("batch_pool", SUB, pools, pool_status),
                     ("managed_identity", SUB, identities if identity_status == "collected" else [], identity_status)])
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True)


def test_batch_pool_create_path_and_existing_pool_path():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-worker": "conditional"}
    assert reached(_run(write_scope=POOL, pool_status="collected"), "u-alice", TID) == {
        "mi-worker": "conditional"}


def test_pool_write_and_assign_must_both_apply_to_exact_resources():
    assert reached(_run(write_scope=OTHER), "u-alice", TID) == {}
    assert reached(_run(assign=False), "u-alice", TID) == {}
    assert reached(_run(account_state="Failed"), "u-alice", TID) == {}
    assert reached(_run(account_status="empty"), "u-alice", TID) == {}
    assert reached(_run(write_scope=POOL, pool_status="collected", pool_state="Failed"), "u-alice", TID) == {}


def test_missing_account_or_identity_inventory_stays_unresolved():
    assert set(reached(_run(account_status="not_collected"), "u-alice", TID).values()) == {"unknown"}
    assert set(reached(_run(identity_status="not_collected"), "u-alice", TID).values()) == {"unknown"}
    assert set(reached(_run(write_scope=POOL, pool_status="not_collected"), "u-alice", TID).values()) == {"unknown"}
