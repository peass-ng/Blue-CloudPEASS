"""Logic App UAMI gain requires one writable Consumption workflow."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TID = "azure-logicapp-assign-user-assigned-identity"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
WORKFLOW = f"{RG}/providers/Microsoft.Logic/workflows/one"
OTHER = f"{RG}/providers/Microsoft.Logic/workflows/two"
UAMI = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/target"
WRITE = "Microsoft.Logic/workflows/write"
ASSIGN = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
CREATE_RG = "Microsoft.Resources/subscriptions/resourceGroups/write"


def _run(*, write_scope=WORKFLOW, assign_scope=UAMI, include_workflow=True,
         include_rg=True, create_rg=False):
    assignments = [("u-alice", "User", write_scope, "role-write"),
                   ("u-alice", "User", assign_scope, "role-assign")]
    if create_rg:
        assignments.append(("u-alice", "User", SUB, "role-create-rg"))
    roles = {"role-write": ([WRITE], []), "role-assign": ([ASSIGN], []),
             "role-create-rg": ([CREATE_RG], [])}
    extra = [("managed_identity", SUB,
              [{"id": UAMI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                "properties": {"principalId": "mi-target"}}])]
    if include_rg:
        extra.append(("resource_group", SUB, [{"id": RG}]))
    graph = ([{"id": WORKFLOW, "type": "Microsoft.Logic/workflows"},
              {"id": OTHER, "type": "Microsoft.Logic/workflows"}]
             if include_workflow else [])
    snap = az(assignments=assignments, roles=roles, graph=graph, extra=extra)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TID)


def test_exact_existing_or_creatable_workflow_and_uami():
    assert validate_entry(ENTRY)[0] == []
    assert _run().get("mi-target") == "conditional"
    assert _run(write_scope=RG, include_workflow=False).get("mi-target") == "conditional"
    assert _run(write_scope=SUB, include_workflow=False, include_rg=False,
                create_rg=True).get("mi-target") == "conditional"


def test_unrelated_workflow_or_identity_and_missing_rg_do_not_match():
    assert _run(write_scope=OTHER, include_workflow=False).get("mi-target") != "conditional"
    assert _run(assign_scope=OTHER).get("mi-target") != "conditional"
    assert _run(write_scope=RG, include_workflow=False, include_rg=False).get("mi-target") != "conditional"
