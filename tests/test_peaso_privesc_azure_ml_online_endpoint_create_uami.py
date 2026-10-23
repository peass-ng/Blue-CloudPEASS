"""New ML endpoint and deployment must be writable together for an exact UAMI."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TID = "azure-ml-online-endpoint-create-with-user-assigned-identity"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
WORKSPACE = f"{RG}/providers/Microsoft.MachineLearningServices/workspaces/ml"
OTHER_WORKSPACE = f"{RG}/providers/Microsoft.MachineLearningServices/workspaces/other"
EXISTING = f"{WORKSPACE}/onlineEndpoints/existing"
UAMI = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/target"
OTHER_UAMI = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/other"
READ = "Microsoft.MachineLearningServices/workspaces/read"
WRITE = "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/write"
DEPLOY = "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/write"
ASSIGN = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"


def _run(*, read_scope=WORKSPACE, write_scope=WORKSPACE, deploy_scope=WORKSPACE,
         assign_scope=UAMI, include_workspace=True):
    graph = ([{"id": WORKSPACE, "type": "Microsoft.MachineLearningServices/workspaces"}]
             if include_workspace else [])
    identities = [{"id": UAMI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                   "properties": {"principalId": "mi-target"}},
                  {"id": OTHER_UAMI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                   "properties": {"principalId": "mi-other"}}]
    snap = az(assignments=[("u-alice", "User", read_scope, "role-read"),
                           ("u-alice", "User", write_scope, "role-write"),
                           ("u-alice", "User", deploy_scope, "role-deploy"),
                           ("u-alice", "User", assign_scope, "role-assign")],
              roles={"role-read": ([READ], []), "role-write": ([WRITE], []),
                     "role-deploy": ([DEPLOY], []), "role-assign": ([ASSIGN], [])},
              graph=graph, extra=[("managed_identity", SUB, identities)])
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TID)


def test_same_new_endpoint_deployment_and_exact_identity():
    assert validate_entry(ENTRY)[0] == []
    assert _run().get("mi-target") == "conditional"
    assert _run().get("mi-other") != "conditional"
    assert _run(write_scope=RG, deploy_scope=RG).get("mi-target") == "conditional"


def test_split_or_existing_only_permissions_do_not_form_creation_path():
    assert _run(read_scope=OTHER_WORKSPACE).get("mi-target") != "conditional"
    assert _run(write_scope=EXISTING).get("mi-target") != "conditional"
    assert _run(deploy_scope=EXISTING).get("mi-target") != "conditional"
    assert _run(assign_scope=OTHER_UAMI).get("mi-target") != "conditional"
    assert _run(include_workspace=False).get("mi-target") != "conditional"
