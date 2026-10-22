"""Batch job data actions must reach a runnable pool on the same account."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-batch-job-task-submission"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)
ACCOUNT = RG + "/providers/Microsoft.Batch/batchAccounts/main"
OTHER = RG + "/providers/Microsoft.Batch/batchAccounts/other"
POOL = ACCOUNT + "/pools/work"
UAI = RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/worker"
JOB = "Microsoft.Batch/batchAccounts/jobs/write"
SCHEDULE = "Microsoft.Batch/batchAccounts/jobSchedules/write"


def _run(*, action=JOB, assignment=ACCOUNT, modes=("AAD",), nodes=2, target_nodes=2,
         account=ACCOUNT, pool_status="collected", principal="mi-worker", identity_type="UserAssigned"):
    account_row = {"id": account, "type": "Microsoft.Batch/batchAccounts",
                   "properties": {"allowedAuthenticationModes": list(modes)}}
    pool_row = {"id": account + "/pools/work", "type": "Microsoft.Batch/batchAccounts/pools",
                "identity": {"type": identity_type,
                             "userAssignedIdentities": {UAI: {"principalId": principal}}},
                "properties": {"provisioningState": "Succeeded", "currentDedicatedNodes": nodes,
                               "currentLowPriorityNodes": 0, "targetDedicatedNodes": target_nodes,
                               "targetLowPriorityNodes": 0, "enableAutoScale": False}}
    snap = az([("u-alice", "User", assignment, ROLE_ID)], roles={ROLE_ID: ([], [action])},
              extra=[("batch_account", SUB, [account_row], "collected"),
                     ("batch_pool", SUB, [pool_row] if pool_status == "collected" else [], pool_status)])
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True)


def test_batch_job_and_schedule_write_reach_exact_pool_identity():
    assert validate_entry(ENTRY)[0] == []
    for action in (JOB, SCHEDULE):
        assert reached(_run(action=action), "u-alice", TID) == {"mi-worker": "conditional"}


def test_batch_job_requires_same_account_aad_and_allocatable_nodes():
    assert reached(_run(assignment=OTHER), "u-alice", TID) == {}
    assert reached(_run(modes=("SharedKey",)), "u-alice", TID) == {}
    assert reached(_run(nodes=0, target_nodes=0), "u-alice", TID) == {}
    assert reached(_run(identity_type="None"), "u-alice", TID) == {}
    assert reached(_run(principal="mi-other"), "u-alice", TID) == {"mi-other": "conditional"}


def test_batch_pool_inventory_gap_is_unresolved():
    result = reached(_run(pool_status="not_collected"), "u-alice", TID)
    assert result and set(result.values()) == {"unknown"}
