"""New ML compute plus inline script must bind write and UAMI assignment."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TID = "azure-ml-compute-create-with-user-assigned-identity"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
WORKSPACE = f"{RG}/providers/Microsoft.MachineLearningServices/workspaces/ml"
OTHER_WORKSPACE = f"{RG}/providers/Microsoft.MachineLearningServices/workspaces/other"
EXISTING = f"{WORKSPACE}/computes/existing"
UAMI = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/target"
OTHER_UAMI = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/other"
WRITE = "Microsoft.MachineLearningServices/workspaces/computes/write"
ASSIGN = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"


def _run(*, write_scope=WORKSPACE, assign_scope=UAMI, include_workspace=True):
    graph = ([{"id": WORKSPACE, "type": "Microsoft.MachineLearningServices/workspaces"}]
             if include_workspace else [])
    identities = [{"id": UAMI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                   "properties": {"principalId": "mi-target"}},
                  {"id": OTHER_UAMI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                   "properties": {"principalId": "mi-other"}}]
    snap = az(assignments=[("u-alice", "User", write_scope, "role-write"),
                           ("u-alice", "User", assign_scope, "role-assign")],
              roles={"role-write": ([WRITE], []), "role-assign": ([ASSIGN], [])},
              graph=graph, extra=[("managed_identity", SUB, identities)])
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TID)


def test_existing_workspace_child_write_and_exact_uami_assignment():
    assert validate_entry(ENTRY)[0] == []
    assert _run().get("mi-target") == "conditional"
    assert _run().get("mi-other") != "conditional"
    assert _run(write_scope=RG).get("mi-target") == "conditional"


def test_unrelated_or_existing_child_write_and_missing_workspace_do_not_match():
    assert _run(write_scope=EXISTING).get("mi-target") != "conditional"
    assert _run(write_scope=OTHER_WORKSPACE).get("mi-target") != "conditional"
    assert _run(assign_scope=OTHER_UAMI).get("mi-target") != "conditional"
    assert _run(include_workspace=False).get("mi-target") != "conditional"
