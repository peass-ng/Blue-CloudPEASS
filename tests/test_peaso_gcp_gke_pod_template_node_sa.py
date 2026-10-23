"""Workload writes reach only an attached, usable GKE node-pool identity."""
from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

HOST = "projects/demo-project1"
TARGET_PROJECT = "projects/identity-project"
CLUSTER = HOST + "/locations/us-central1/clusters/primary"
SOURCE = "user:operator@example.com"
EMAIL = "node-power@identity-project.iam.gserviceaccount.com"
ROLE = HOST + "/roles/workloadWriter"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-container-pod-template-node-sa")


def row(kind, records, scope=HOST, status=None):
    return {"type": kind, "scope": scope, "status": status or ("collected" if records else "empty"),
            "items": records}


def case(action, *, mode="GCE_METADATA", pool="pool-a", controller=True,
         pod=True, host_network=False, joined=True, get=True, private=False,
         node_ready=True, node_status=None, pod_status=None, controller_status=None):
    permissions = [action] + (["container.clusters.get"] if get else [])
    cluster = {"name": "primary", "location": "us-central1", "status": "RUNNING",
               "endpoint": "203.0.113.10", "privateClusterConfig": {"enablePrivateEndpoint": private},
               "masterAuthorizedNetworksConfig": {"enabled": False},
               "workloadIdentityConfig": {"workloadPool": "demo-project1.svc.id.goog"},
               "nodePools": [{"name": "pool-a", "status": "RUNNING",
                              "config": {"serviceAccount": EMAIL,
                                         "workloadMetadataConfig": {"mode": mode}}}]}
    gcp = {"provider": "gcp", "metadata": {}, "collections": [
        row("project", [{"name": HOST, "projectId": "demo-project1"}]),
        row("project", [{"name": TARGET_PROJECT, "projectId": "identity-project"}], TARGET_PROJECT),
        row("service_account", [{"email": EMAIL, "projectId": "identity-project"}], TARGET_PROJECT),
        row("iam_role", [{"name": ROLE, "includedPermissions": permissions}]),
        row("iam_policy", [{"name": HOST, "bindings": [{"role": ROLE, "members": [SOURCE]}]}]),
        row("iam_deny_policy", []), row("gke_cluster", [cluster]),
    ]}
    node = {"metadata": {"name": "node-a", "labels": {"cloud.google.com/gke-nodepool": pool}},
            "spec": {"providerID": "gce://demo-project1/us-central1-a/node-a"},
            "status": {"conditions": [{"type": "Ready", "status": "True" if node_ready else "False"}]}}
    workload = {"metadata": {"name": "app", "namespace": "work"},
                "spec": {"template": {"spec": {"containers": [{"name": "app"}]}}}}
    running_pod = {"metadata": {"name": "app", "namespace": "work"},
                   "spec": {"nodeName": "node-a", "hostNetwork": host_network,
                            "containers": [{"name": "app"}]},
                   "status": {"phase": "Running", "containerStatuses": [
                       {"name": "app", "state": {"running": {"startedAt": "2026-01-01T00:00:00Z"}}}]}}
    k8s = {"provider": "k8s", "metadata": {"cluster_id": CLUSTER}, "collections": [
        row("node", [node], "*", node_status),
        row("deployment", [workload] if controller else [], "*", controller_status),
        row("pod", [running_pod] if pod else [], "*", pod_status),
    ]}
    model = GcpModel(gcp)
    if joined:
        model.set_related([k8s])
    return [(target, grant.confidence) for reach in
            Evaluator(model, [ENTRY], include_unknown=True, admin_scopes={}).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()]


def test_exact_cross_project_pool_and_workload_paths():
    target = "serviceAccount:" + EMAIL
    assert case("container.pods.create") == [(target, "conditional")]
    assert case("container.deployments.update") == [(target, "conditional")]
    assert case("container.pods.update") == [(target, "conditional")]
    assert case("container.pods.update", mode="GKE_METADATA", host_network=True) == [(target, "conditional")]
    assert case("container.pods.update", mode="GKE_METADATA", host_network=False) == []
    assert case("container.pods.update", mode="SECURE", host_network=False) == [(target, "conditional")]
    assert case("container.pods.update", node_ready=False) == [(target, "conditional")]
    assert case("container.jobs.update") == []


def test_unmatched_or_unresolved_cluster_does_not_claim_node_identity():
    assert case("container.pods.create", pool="other")[0][1] == "unknown"
    assert case("container.pods.create", node_ready=False)[0][1] == "unknown"
    assert case("container.pods.create", joined=False)[0][1] == "unknown"
    assert case("container.pods.create", private=True)[0][1] == "unknown"
    assert case("container.pods.create", node_status="denied")[0][1] == "unknown"
    assert case("container.pods.create", get=False) == []
    assert case("container.deployments.update", controller=False) == []
    assert case("container.deployments.update", controller_status="denied")[0][1] == "unknown"
    assert case("container.pods.update", pod=False) == []
    assert case("container.pods.update", pod_status="denied")[0][1] == "unknown"
