"""Automation UAMI assignment needs one executable account and exact identity."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-automation-assign-user-assigned-identity"
ENTRY = next({key: value for key, value in item.items() if not key.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)
ACCOUNT = RG + "/providers/Microsoft.Automation/automationAccounts/live"
OTHER = RG + "/providers/Microsoft.Automation/automationAccounts/other"
RUNBOOK = ACCOUNT + "/runbooks/live"
UAMI = RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/worker"
ASSIGN = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
WRITE = "Microsoft.Automation/automationAccounts/write"
CREATE = ["Microsoft.Automation/automationAccounts/runbooks/write",
          "Microsoft.Automation/automationAccounts/runbooks/draft/content/write",
          "Microsoft.Automation/automationAccounts/runbooks/publish/action",
          "Microsoft.Automation/automationAccounts/jobs/write"]
DRAFT = ["Microsoft.Automation/automationAccounts/runbooks/draft/write", *CREATE[1:]]


def _run(*, account=True, account_scope=ACCOUNT, code_scope=ACCOUNT,
         code_actions=CREATE, identity_scope=UAMI, runbook=False, job_scope=None):
    assignments = [("u-alice", "User", account_scope, ROLE_ID),
                   ("u-alice", "User", code_scope, ROLE_ID + "-code"),
                   ("u-alice", "User", identity_scope, ROLE_ID + "-assign")]
    roles = {ROLE_ID: ([WRITE], []), ROLE_ID + "-code": (list(code_actions), []),
             ROLE_ID + "-assign": ([ASSIGN], [])}
    if job_scope:
        assignments.append(("u-alice", "User", job_scope, ROLE_ID + "-job"))
        roles[ROLE_ID + "-job"] = (["Microsoft.Automation/automationAccounts/jobs/write"], [])
    graph = ([{"id": ACCOUNT, "type": "Microsoft.Automation/automationAccounts", "name": "live"}]
             if account else [])
    if runbook:
        graph.append({"id": RUNBOOK, "type": "Microsoft.Automation/automationAccounts/runbooks",
                      "name": "live"})
    snap = az(assignments, roles=roles, graph=graph,
              extra=[("resource_group", SUB, [{"id": RG, "type": "Microsoft.Resources/resourceGroups"}]),
                     ("managed_identity", SUB, [{"id": UAMI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                                                "name": "worker", "properties": {"principalId": "mi-worker", "clientId": "worker"}}])])
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)])


def test_existing_account_and_exact_assignable_uami_with_create_runbook_path():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-worker": "conditional"}


def test_new_account_in_inventoried_resource_group_is_conditional():
    assert reached(_run(account=False, account_scope=RG, code_scope=RG), "u-alice", TID) == {
        "mi-worker": "conditional"}


def test_unrelated_account_or_identity_scope_does_not_join():
    assert "mi-worker" not in reached(_run(account_scope=OTHER), "u-alice", TID)
    assert "mi-worker" not in reached(_run(identity_scope=OTHER), "u-alice", TID)


def test_existing_draft_route_requires_an_inventoried_runbook():
    assert "mi-worker" not in reached(_run(code_actions=DRAFT), "u-alice", TID)
    assert reached(_run(code_actions=DRAFT, runbook=True), "u-alice", TID) == {
        "mi-worker": "conditional"}


def test_exact_existing_runbook_test_job_route_and_unrelated_code_scope():
    test_job = ["Microsoft.Automation/automationAccounts/runbooks/draft/write",
                "Microsoft.Automation/automationAccounts/runbooks/draft/content/write",
                "Microsoft.Automation/automationAccounts/runbooks/draft/testJob/write"]
    assert reached(_run(code_scope=RUNBOOK, code_actions=test_job, runbook=True),
                   "u-alice", TID) == {"mi-worker": "conditional"}
    assert "mi-worker" not in reached(_run(code_scope=OTHER), "u-alice", TID)


def test_named_child_create_rights_and_account_job_rights_are_joined():
    assert reached(_run(code_scope=RUNBOOK, code_actions=CREATE[:-1], job_scope=ACCOUNT),
                   "u-alice", TID) == {"mi-worker": "conditional"}


def test_native_automation_account_inventory_can_supply_the_exact_pivot():
    snap = az([("u-alice", "User", ACCOUNT, ROLE_ID),
               ("u-alice", "User", ACCOUNT, ROLE_ID + "-code"),
               ("u-alice", "User", UAMI, ROLE_ID + "-assign")],
              roles={ROLE_ID: ([WRITE], []), ROLE_ID + "-code": (CREATE, []),
                     ROLE_ID + "-assign": ([ASSIGN], [])},
              extra=[("automation_account", SUB, [{"id": ACCOUNT,
                       "type": "Microsoft.Automation/automationAccounts", "name": "live"}]),
                     ("managed_identity", SUB, [{"id": UAMI,
                       "type": "Microsoft.ManagedIdentity/userAssignedIdentities", "name": "worker",
                       "properties": {"principalId": "mi-worker", "clientId": "worker"}}])])
    assert reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)]), "u-alice", TID) == {
        "mi-worker": "conditional"}
