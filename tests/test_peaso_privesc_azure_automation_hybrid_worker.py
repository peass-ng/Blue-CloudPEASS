"""Hybrid Worker escalation joins worker, account, and runnable code path."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, az, _vm


TID = "azure-automation-runbook-hybrid-worker"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)
MAIN = RG + "/providers/Microsoft.Automation/automationAccounts/main"
OTHER = RG + "/providers/Microsoft.Automation/automationAccounts/other"
RUNBOOK = MAIN + "/runbooks/known"
CREATE = ["Microsoft.Automation/automationAccounts/runbooks/write",
          "Microsoft.Automation/automationAccounts/runbooks/draft/content/write",
          "Microsoft.Automation/automationAccounts/runbooks/publish/action",
          "Microsoft.Automation/automationAccounts/jobs/write"]


def _run(*, scope=MAIN, actions=CREATE, runbook=False, link_account=MAIN,
         link_collected=True, named=False):
    worker = {"id": f"{link_account}/hybridRunbookWorkerGroups/g/hybridRunbookWorkers/w",
              "properties": {"vmResourceId": f"{RG}/providers/Microsoft.Compute/virtualMachines/host"}}
    graph = [{"id": account, "type": "Microsoft.Automation/automationAccounts"}
             for account in (MAIN, OTHER)]
    if runbook:
        graph.append({"id": RUNBOOK, "type": "Microsoft.Automation/automationAccounts/runbooks"})
    assignments = [("u-alice", "User", scope, ROLE_ID)]
    roles = {ROLE_ID: (list(actions), [])}
    if named:
        assignments.append(("u-alice", "User", MAIN, ROLE_ID + "-job"))
        roles[ROLE_ID + "-job"] = ([CREATE[-1]], [])
    snap = az(assignments, roles=roles, vms=[_vm("host", "mi-host")], graph=graph,
              extra=[("automation_hybrid_worker", MAIN, [worker] if link_collected else [],
                      "collected" if link_collected else "not_collected"),
                     ("automation_hybrid_worker", OTHER, [], "empty")])
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True)


def test_hybrid_worker_full_create_route_is_conditional():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-host": "conditional"}


def test_hybrid_worker_requires_complete_same_account_path():
    assert reached(_run(actions=CREATE[:-1]), "u-alice", TID) == {}
    assert reached(_run(scope=OTHER), "u-alice", TID) == {}
    assert reached(_run(link_account=OTHER), "u-alice", TID) == {}


def test_hybrid_worker_named_runbook_and_test_job_routes():
    assert reached(_run(scope=RUNBOOK, actions=CREATE[:-1], named=True),
                   "u-alice", TID) == {"mi-host": "conditional"}
    test_job = ["Microsoft.Automation/automationAccounts/runbooks/draft/write",
                "Microsoft.Automation/automationAccounts/runbooks/draft/content/write",
                "Microsoft.Automation/automationAccounts/runbooks/draft/testJob/write"]
    assert reached(_run(scope=RUNBOOK, actions=test_job, runbook=True),
                   "u-alice", TID) == {"mi-host": "conditional"}


def test_hybrid_worker_incomplete_worker_inventory_is_unresolved():
    result = reached(_run(link_collected=False), "u-alice", TID)
    assert result and set(result.values()) == {"unknown"}


def test_arc_worker_identity_requires_account_without_managed_identity():
    host = f"{RG}/providers/Microsoft.HybridCompute/machines/arc"
    worker = {"id": f"{MAIN}/hybridRunbookWorkerGroups/g/hybridRunbookWorkers/w",
              "properties": {"vmResourceId": host}}
    account = {"id": MAIN, "type": "Microsoft.Automation/automationAccounts"}
    arc = {"id": host, "type": "Microsoft.HybridCompute/machines",
           "identity": {"type": "SystemAssigned", "principalId": "mi-arc"}}

    def run(with_account_identity):
        resource = copy.deepcopy(account)
        if with_account_identity:
            resource["identity"] = {"type": "SystemAssigned", "principalId": "mi-account"}
        snap = az([("u-alice", "User", MAIN, ROLE_ID)], roles={ROLE_ID: (CREATE, [])},
                  graph=[resource, arc],
                  extra=[("automation_hybrid_worker", MAIN, [worker], "collected")])
        return reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)]), "u-alice", TID)

    assert run(False) == {"mi-arc": "conditional"}
    assert run(True) == {}
