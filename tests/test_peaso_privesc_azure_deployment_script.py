"""Deployment scripts must bind one writable script, support group, and UAMI."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-arm-deploymentscript-with-user-assigned-identity"
OTHER_RG = f"{SUB}/resourceGroups/other"
SCRIPT = RG + "/providers/Microsoft.Resources/deploymentScripts/script"
ACI = RG + "/providers/Microsoft.ContainerInstance/containerGroups/support"
STORAGE = RG + "/providers/Microsoft.Storage/storageAccounts/support"
UAMI = RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/worker"
OTHER_UAMI = OTHER_RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/other"
SCRIPT_WRITE = "Microsoft.Resources/deploymentScripts/write"
ASSIGN = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
SUPPORT = ["Microsoft.ContainerInstance/containerGroups/read",
           "Microsoft.ContainerInstance/containerGroups/write",
           "Microsoft.Storage/storageAccounts/read",
           "Microsoft.Storage/storageAccounts/write",
           "Microsoft.Storage/storageAccounts/listKeys/action"]
DELETE = "Microsoft.ContainerInstance/containerGroups/delete"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _run(*, script_scope=RG, support_scope=RG, identity_scope=UAMI,
         support=SUPPORT, existing=False, retained=False, can_delete=False,
         include_unknown=False):
    uami = {"id": UAMI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
            "name": "worker", "properties": {"principalId": "mi-worker", "clientId": "worker"}}
    other = {"id": OTHER_UAMI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
             "name": "other", "properties": {"principalId": "mi-other", "clientId": "other"}}
    graph = []
    if existing:
        graph.append({"id": SCRIPT, "type": "Microsoft.Resources/deploymentScripts",
                      "name": "script", "properties": {"cleanupPreference": "OnExpiration" if retained else "OnSuccess",
                      "containerInstanceId": ACI, "storageAccountId": STORAGE}})
    if retained:
        graph.append({"id": ACI, "type": "Microsoft.ContainerInstance/containerGroups", "name": "support"})
    assignments = [("u-alice", "User", script_scope, ROLE_ID),
                   ("u-alice", "User", support_scope, ROLE_ID + "-support"),
                   ("u-alice", "User", identity_scope, ROLE_ID + "-assign")]
    roles = {ROLE_ID: ([SCRIPT_WRITE], []),
             ROLE_ID + "-support": (list(support) + ([DELETE] if can_delete else []), []),
             ROLE_ID + "-assign": ([ASSIGN], [])}
    snap = az(assignments, roles=roles, graph=graph,
              extra=[("resource_group", SUB, [{"id": RG, "type": "Microsoft.Resources/resourceGroups"},
                                               {"id": OTHER_RG, "type": "Microsoft.Resources/resourceGroups"}]),
                     ("managed_identity", SUB, [uami, other])])
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=include_unknown)


def test_create_and_existing_script_with_exact_assignable_uami():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-worker": "conditional"}
    assert reached(_run(existing=True, script_scope=SCRIPT), "u-alice", TID) == {
        "mi-worker": "conditional"}


def test_other_uami_and_wrong_support_group_do_not_join():
    assert "mi-worker" not in reached(_run(identity_scope=OTHER_UAMI), "u-alice", TID)
    assert "mi-worker" not in reached(_run(support_scope=OTHER_RG), "u-alice", TID)
    assert "mi-worker" not in reached(_run(support=SUPPORT[:-1]), "u-alice", TID)


def test_retained_container_requires_delete_permission():
    assert "mi-worker" not in reached(_run(existing=True, retained=True, script_scope=SCRIPT), "u-alice", TID)
    assert reached(_run(existing=True, retained=True, script_scope=SCRIPT,
                        can_delete=True), "u-alice", TID) == {
        "mi-worker": "conditional"}


def test_existing_script_child_cannot_create_another_without_group_rights():
    assert "mi-worker" not in reached(_run(script_scope=OTHER_RG), "u-alice", TID)
