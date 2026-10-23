"""Online deployment code path binds every permission to one identity endpoint."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TID = "azure-ml-online-deployment-existing-endpoint"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
WORKSPACE = f"{RG}/providers/Microsoft.MachineLearningServices/workspaces/ml"
ENDPOINT = f"{WORKSPACE}/onlineEndpoints/one"
OTHER = f"{WORKSPACE}/onlineEndpoints/two"
UAMI = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/shared"
READ = "Microsoft.MachineLearningServices/workspaces/read"
WRITE = "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/write"
DEPLOY = "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/write"
EXISTING_DEPLOYMENT = f"{ENDPOINT}/deployments/blue"


def _run(*, read_scope=WORKSPACE, write_scope=ENDPOINT, deploy_scope=ENDPOINT,
         compute_type="Managed", state="Succeeded", include_deployment=False):
    graph = [{"id": ENDPOINT, "type": "Microsoft.MachineLearningServices/workspaces/onlineEndpoints",
              "identity": {"principalId": "mi-system",
                           "userAssignedIdentities": {UAMI: {"principalId": "mi-shared"}}},
              "properties": {"endpointComputeType": compute_type, "provisioningState": state}},
             {"id": OTHER, "type": "Microsoft.MachineLearningServices/workspaces/onlineEndpoints",
              "identity": {"principalId": "mi-other"},
              "properties": {"endpointComputeType": "Managed", "provisioningState": "Succeeded"}}]
    if include_deployment:
        graph.append({"id": EXISTING_DEPLOYMENT,
                      "type": "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments"})
    snap = az(assignments=[("u-alice", "User", read_scope, "role-read"),
                           ("u-alice", "User", write_scope, "role-write"),
                           ("u-alice", "User", deploy_scope, "role-deploy")],
              roles={"role-read": ([READ], []), "role-write": ([WRITE], []),
                     "role-deploy": ([DEPLOY], [])}, graph=graph,
              extra=[("managed_identity", SUB,
                      [{"id": UAMI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                        "properties": {"principalId": "mi-shared"}}])])
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TID)


def test_exact_endpoint_reaches_attached_system_and_user_identity():
    assert validate_entry(ENTRY)[0] == []
    result = _run()
    assert result.get("mi-system") == "conditional"
    assert result.get("mi-shared") == "conditional"
    assert result.get("mi-other") != "conditional"
    assert _run(deploy_scope=EXISTING_DEPLOYMENT, include_deployment=True).get("mi-system") == "conditional"


def test_split_scopes_and_wrong_compute_or_state_do_not_match():
    assert _run(write_scope=OTHER).get("mi-system") != "conditional"
    assert _run(deploy_scope=OTHER).get("mi-system") != "conditional"
    assert _run(deploy_scope=EXISTING_DEPLOYMENT).get("mi-system") != "conditional"
    assert _run(read_scope=OTHER).get("mi-system") != "conditional"
    assert _run(compute_type="Other").get("mi-system") != "conditional"
    assert _run(state="Failed").get("mi-system") != "conditional"
