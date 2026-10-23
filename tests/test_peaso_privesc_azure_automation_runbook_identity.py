"""Runbook execution must be on the account carrying the target identity."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, az


TID = "azure-automation-runbook-author-and-run"
ENTRY = next({key: value for key, value in item.items() if not key.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)
MAIN = RG + "/providers/Microsoft.Automation/automationAccounts/main"
OTHER = RG + "/providers/Microsoft.Automation/automationAccounts/other"
RUNBOOK = MAIN + "/runbooks/known"
CREATE = ["Microsoft.Automation/automationAccounts/runbooks/write",
          "Microsoft.Automation/automationAccounts/runbooks/draft/content/write",
          "Microsoft.Automation/automationAccounts/runbooks/publish/action",
          "Microsoft.Automation/automationAccounts/jobs/write"]
DRAFT = ["Microsoft.Automation/automationAccounts/runbooks/draft/write", *CREATE[1:]]


def _run(*, scope=MAIN, actions=CREATE, runbook=False, separate_job=False):
    assignments = [("u-alice", "User", scope, ROLE_ID)]
    roles = {ROLE_ID: (list(actions), [])}
    if separate_job:
        assignments.append(("u-alice", "User", MAIN, ROLE_ID + "-job"))
        roles[ROLE_ID + "-job"] = (["Microsoft.Automation/automationAccounts/jobs/write"], [])
    graph = [{"id": MAIN, "type": "Microsoft.Automation/automationAccounts",
              "identity": {"type": "SystemAssigned", "principalId": "mi-main"}},
             {"id": OTHER, "type": "Microsoft.Automation/automationAccounts",
              "identity": {"type": "SystemAssigned", "principalId": "mi-other"}}]
    if runbook:
        graph.append({"id": RUNBOOK, "type": "Microsoft.Automation/automationAccounts/runbooks"})
    return privesc.analyze(az(assignments, roles=roles, graph=graph), entries=[copy.deepcopy(ENTRY)])


def test_runbook_create_path_reaches_only_the_attached_identity():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-main": "derived"}


def test_unrelated_account_rights_do_not_cross_to_another_identity():
    assert reached(_run(scope=OTHER), "u-alice", TID) == {"mi-other": "derived"}
    assert reached(_run(actions=CREATE[:-1]), "u-alice", TID) == {}


def test_draft_route_needs_an_existing_runbook_on_the_attached_account():
    assert reached(_run(actions=DRAFT), "u-alice", TID) == {}
    assert reached(_run(actions=DRAFT, runbook=True), "u-alice", TID) == {"mi-main": "derived"}


def test_named_runbook_grant_can_run_only_with_its_account_job_grant():
    assert reached(_run(scope=RUNBOOK, actions=CREATE[:-1], separate_job=True),
                   "u-alice", TID) == {"mi-main": "derived"}
    test_job = ["Microsoft.Automation/automationAccounts/runbooks/draft/write",
                "Microsoft.Automation/automationAccounts/runbooks/draft/content/write",
                "Microsoft.Automation/automationAccounts/runbooks/draft/testJob/write"]
    assert reached(_run(scope=RUNBOOK, actions=test_job, runbook=True),
                   "u-alice", TID) == {"mi-main": "derived"}
