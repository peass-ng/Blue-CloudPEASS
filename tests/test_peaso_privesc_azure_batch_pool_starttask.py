"""A pool start task can use only the identity on the exact writable native pool."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-batch-pool-write-starttask"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)
ACCOUNT = RG + "/providers/Microsoft.Batch/batchAccounts/main"
POOL = ACCOUNT + "/pools/work"
OTHER = ACCOUNT + "/pools/other"
UAI = RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/worker"
WRITE = "Microsoft.Batch/batchAccounts/pools/write"


def _run(*, write_scope=POOL, pool_status="collected", account_status="collected",
         identity_status="collected", attached=True, principal="mi-worker",
         pool_state="Succeeded", account_state="Succeeded", nodes=0):
    account = {"id": ACCOUNT, "type": "Microsoft.Batch/batchAccounts",
               "properties": {"provisioningState": account_state}}
    pool = {"id": POOL, "type": "Microsoft.Batch/batchAccounts/pools",
            "identity": {"type": "UserAssigned", "userAssignedIdentities": {
                UAI: {"principalId": principal}}} if attached else {"type": "None"},
            "properties": {"provisioningState": pool_state, "currentDedicatedNodes": nodes,
                           "targetDedicatedNodes": nodes}}
    identity = {"id": UAI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                "properties": {"principalId": "mi-worker", "clientId": "worker-client"}}
    snap = az([("u-alice", "User", write_scope, ROLE_ID)], roles={ROLE_ID: ([WRITE], [])},
              extra=[("batch_account", SUB, [account] if account_status == "collected" else [], account_status),
                     ("batch_pool", SUB, [pool] if pool_status == "collected" else [], pool_status),
                     ("managed_identity", SUB, [identity] if identity_status == "collected" else [], identity_status)])
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True)


def test_exact_pool_identity_and_write_with_zero_current_nodes():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-worker": "conditional"}
    assert reached(_run(nodes=2), "u-alice", TID) == {"mi-worker": "conditional"}


def test_unrelated_write_or_inactive_pool_or_absent_identity_does_not_reach_target():
    assert reached(_run(write_scope=OTHER), "u-alice", TID) == {}
    assert reached(_run(attached=False), "u-alice", TID) == {}
    assert reached(_run(principal="mi-other"), "u-alice", TID) == {}
    assert reached(_run(pool_state="Failed"), "u-alice", TID) == {}
    assert reached(_run(account_state="Deleting"), "u-alice", TID) == {}


def test_missing_native_inventory_is_unresolved():
    for kind in ("pool_status", "account_status", "identity_status"):
        result = reached(_run(**{kind: "not_collected"}), "u-alice", TID)
        assert result and set(result.values()) == {"unknown"}
