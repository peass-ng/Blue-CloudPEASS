"""Batch account keys reach only pools on an account that permits Shared Key."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-batch-shared-key-task-submission"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)
ACCOUNT = RG + "/providers/Microsoft.Batch/batchAccounts/main"
OTHER = RG + "/providers/Microsoft.Batch/batchAccounts/other"
POOL = ACCOUNT + "/pools/work"
UAI = RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/worker"
LIST = "Microsoft.Batch/batchAccounts/listkeys/action"
REGENERATE = "Microsoft.Batch/batchAccounts/regeneratekeys/action"
WRITE = "Microsoft.Batch/batchAccounts/write"


def _run(*, action=LIST, assignment=ACCOUNT, modes=("SharedKey",), account_write=False,
         nodes=2, target_nodes=2, account_status="collected", pool_status="collected",
         identity_status="collected", attached=True, account_state="Succeeded", pool_state="Succeeded"):
    account = {"id": ACCOUNT, "type": "Microsoft.Batch/batchAccounts",
               "properties": {"provisioningState": account_state}}
    if modes is not None:
        account["properties"]["allowedAuthenticationModes"] = list(modes)
    pool = {"id": POOL, "type": "Microsoft.Batch/batchAccounts/pools",
            "identity": {"type": "UserAssigned", "userAssignedIdentities": {
                UAI: {"principalId": "mi-worker"}}} if attached else {"type": "None"},
            "properties": {"provisioningState": pool_state, "currentDedicatedNodes": nodes,
                           "currentLowPriorityNodes": 0, "targetDedicatedNodes": target_nodes,
                           "targetLowPriorityNodes": 0, "enableAutoScale": False}}
    identity = {"id": UAI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                "properties": {"principalId": "mi-worker", "clientId": "worker-client"}}
    snap = az([("u-alice", "User", assignment, ROLE_ID)],
              roles={ROLE_ID: ([action] + ([WRITE] if account_write else []), [])},
              extra=[("batch_account", SUB, [account] if account_status == "collected" else [], account_status),
                     ("batch_pool", SUB, [pool] if pool_status == "collected" else [], pool_status),
                     ("managed_identity", SUB, [identity] if identity_status == "collected" else [], identity_status)])
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True)


def test_list_or_regenerate_keys_on_exact_account_reaches_pool_identity():
    assert validate_entry(ENTRY)[0] == []
    for action in (LIST, REGENERATE):
        assert reached(_run(action=action), "u-alice", TID) == {"mi-worker": "conditional"}
    assert reached(_run(nodes=0, target_nodes=0), "u-alice", TID) == {"mi-worker": "conditional"}
    assert reached(_run(nodes=None, target_nodes=None), "u-alice", TID) == {"mi-worker": "conditional"}


def test_account_write_can_reenable_shared_key_but_an_unrelated_grant_cannot():
    assert reached(_run(modes=("AAD",)), "u-alice", TID) == {}
    assert reached(_run(modes=("AAD",), account_write=True), "u-alice", TID) == {
        "mi-worker": "conditional"}
    assert reached(_run(assignment=OTHER), "u-alice", TID) == {}
    assert reached(_run(attached=False), "u-alice", TID) == {}
    assert reached(_run(account_state="Failed"), "u-alice", TID) == {}
    assert reached(_run(pool_state="Deleting"), "u-alice", TID) == {}


def test_missing_mode_or_native_inventory_is_unresolved():
    assert set(reached(_run(modes=None), "u-alice", TID).values()) == {"unknown"}
    assert reached(_run(modes=None, account_write=True), "u-alice", TID) == {
        "mi-worker": "conditional"}
    for kind in ("account_status", "pool_status", "identity_status"):
        result = reached(_run(**{kind: "not_collected"}), "u-alice", TID)
        assert result and set(result.values()) == {"unknown"}
