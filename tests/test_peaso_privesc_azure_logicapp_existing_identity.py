"""Workflow editing reaches only identities attached to that exact workflow."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TID = "azure-logicapp-workflow-write-existing-identity"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
WORKFLOW = f"{RG}/providers/Microsoft.Logic/workflows/one"
OTHER_WORKFLOW = f"{RG}/providers/Microsoft.Logic/workflows/two"
VM = f"{RG}/providers/Microsoft.Compute/virtualMachines/one"
UAMI = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/shared"
WRITE = "Microsoft.Logic/workflows/write"


def _run(write_scope, *, include_workflow=True):
    graph = [{"id": VM, "type": "Microsoft.Compute/virtualMachines",
              "identity": {"userAssignedIdentities": {UAMI: {"principalId": "mi-shared"}}}},
             {"id": OTHER_WORKFLOW, "type": "Microsoft.Logic/workflows",
              "identity": {"principalId": "mi-other"}}]
    if include_workflow:
        graph.append({"id": WORKFLOW, "type": "Microsoft.Logic/workflows",
                      "identity": {"principalId": "mi-system",
                                   "userAssignedIdentities": {UAMI: {"principalId": "mi-shared"}}}})
    snap = az(assignments=[("u-alice", "User", write_scope, "role-write")],
              roles={"role-write": ([WRITE], [])}, graph=graph,
              extra=[("managed_identity", SUB,
                      [{"id": UAMI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                        "properties": {"principalId": "mi-shared"}}])])
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TID)


def test_exact_consumption_workflow_reaches_both_attached_identities():
    assert validate_entry(ENTRY)[0] == []
    result = _run(WORKFLOW)
    assert result.get("mi-system") == "conditional"
    assert result.get("mi-shared") == "conditional"
    assert result.get("mi-other") != "conditional"


def test_permission_on_other_host_or_workflow_does_not_cross_join():
    assert _run(VM).get("mi-shared") != "conditional"
    assert _run(OTHER_WORKFLOW).get("mi-shared") != "conditional"
    assert _run(WORKFLOW, include_workflow=False).get("mi-shared") != "conditional"
