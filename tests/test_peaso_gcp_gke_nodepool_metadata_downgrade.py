"""A metadata downgrade needs an exact pool and a separate workload path."""
from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

HOST = "projects/demo-project1"
TARGET_PROJECT = "projects/identity-project"
CLUSTER = HOST + "/locations/us-central1/clusters/primary"
SOURCE = "user:operator@example.com"
EMAIL = "node-power@identity-project.iam.gserviceaccount.com"
ROLE = HOST + "/roles/nodePoolWriter"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-container-updatenodepool-expose-node-sa")


def row(kind, records, scope=HOST, status=None):
    return {"type": kind, "scope": scope, "status": status or ("collected" if records else "empty"),
            "items": records}


def case(*, workload="container.pods.create", mode="GKE_METADATA", node_pool="pool-a",
         host_network=False, pod=True, controller=True, get=True, update=True,
         joined=True, private=False, autopilot=False, node_status=None, pod_status=None):
    permissions = ((["container.clusters.update"] if update else []) +
                   (["container.clusters.get"] if get else []) +
                   ([workload] if workload else []))
    cluster = {"name": "primary", "location": "us-central1", "status": "RUNNING",
               "endpoint": "203.0.113.10", "privateClusterConfig": {"enablePrivateEndpoint": private},
               "masterAuthorizedNetworksConfig": {"enabled": False},
               "autopilot": {"enabled": autopilot},
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
    node = {"metadata": {"name": "node-a", "labels": {"cloud.google.com/gke-nodepool": node_pool}},
            "spec": {"providerID": "gce://demo-project1/us-central1-a/node-a"},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
    running_pod = {"metadata": {"name": "app", "namespace": "work"},
                   "spec": {"nodeName": "node-a", "hostNetwork": host_network,
                            "containers": [{"name": "app", "image": "app:1"}]},
                   "status": {"phase": "Running", "containerStatuses": [
                       {"name": "app", "state": {"running": {"startedAt": "2026-01-01T00:00:00Z"}}}]}}
    deployment = {"metadata": {"name": "app", "namespace": "work"},
                  "spec": {"template": {"spec": {"containers": [{"name": "app", "image": "app:1"}]}}}}
    k8s = {"provider": "k8s", "metadata": {"cluster_id": CLUSTER}, "collections": [
        row("node", [node], "*", node_status),
        row("pod", [running_pod] if pod else [], "*", pod_status),
        row("deployment", [deployment] if controller else [], "*"),
    ]}
    model = GcpModel(gcp)
    if joined:
        model.set_related([k8s])
    return [(target, grant.confidence) for reach in
            Evaluator(model, [ENTRY], include_unknown=True, admin_scopes={}).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()]


def test_exact_cross_project_pool_downgrade_has_workload_path():
    target = "serviceAccount:" + EMAIL
    assert case() == [(target, "conditional")]
    assert case(workload="container.pods.exec") == [(target, "conditional")]
    assert case(workload="container.pods.update") == [(target, "conditional")]
    assert case(workload="container.nodes.proxy") == [(target, "conditional")]
    assert case(workload="container.deployments.update") == [(target, "conditional")]
    assert case(workload="container.pods.create", pod=False) == [(target, "conditional")]
    assert case(workload="container.pods.exec", host_network=True) == []
    assert case(workload="container.pods.exec", pod=False) == []
    assert case(workload="container.deployments.update", controller=False) == []


def test_update_alone_or_unmatched_pool_does_not_claim_node_sa():
    assert case(workload=None) == []
    assert case(update=False) == []
    assert case(mode="GCE_METADATA") == []
    assert case(autopilot=True) == []
    assert case(node_pool="other")[0][1] == "unknown"
    assert case(get=False)[0][1] == "unknown"
    assert case(joined=False)[0][1] == "unknown"
    assert case(private=True)[0][1] == "unknown"
    assert case(node_status="denied")[0][1] == "unknown"
    assert case(workload="container.pods.exec", pod_status="denied")[0][1] == "unknown"
