"""Pod exec must reach a running container on the target node pool."""
from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

HOST = "projects/demo-project1"
TARGET_PROJECT = "projects/identity-project"
CLUSTER = HOST + "/locations/us-central1/clusters/primary"
SOURCE = "user:operator@example.com"
EMAIL = "node-power@identity-project.iam.gserviceaccount.com"
ROLE = HOST + "/roles/podExec"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-container-pods-exec-node-sa")


def row(kind, records, scope=HOST, status=None):
    return {"type": kind, "scope": scope, "status": status or ("collected" if records else "empty"),
            "items": records}


def case(*, mode="GCE_METADATA", host_network=False, node_pool="pool-a",
         pod_node="node-a", running=True, exec_permission=True, get=True,
         joined=True, private=False, disabled=False, pod_status=None,
         node_status=None, runtime_class=None, autopilot=False):
    permissions = ((["container.pods.exec"] if exec_permission else []) +
                   (["container.clusters.get"] if get else []))
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
        row("service_account", [{"email": EMAIL, "projectId": "identity-project",
                                 "disabled": disabled}], TARGET_PROJECT),
        row("iam_role", [{"name": ROLE, "includedPermissions": permissions}]),
        row("iam_policy", [{"name": HOST, "bindings": [{"role": ROLE, "members": [SOURCE]}]}]),
        row("iam_deny_policy", []), row("gke_cluster", [cluster]),
    ]}
    k8s = {"provider": "k8s", "metadata": {"cluster_id": CLUSTER}, "collections": [
        row("node", [{"metadata": {"name": "node-a",
                                     "labels": {"cloud.google.com/gke-nodepool": node_pool}},
                      "spec": {"providerID": "gce://demo-project1/us-central1-a/node-a"}}],
            "*", node_status),
        row("pod", [{"metadata": {"name": "app", "namespace": "work"},
                     "spec": {"nodeName": pod_node, "hostNetwork": host_network,
                              "runtimeClassName": runtime_class, "containers": [{"name": "app"}]},
                     "status": {"phase": "Running" if running else "Pending",
                                "containerStatuses": [{"name": "app", "state": {
                                    "running": {"startedAt": "2026-01-01T00:00:00Z"}}}]}}],
            "*", pod_status),
    ]}
    model = GcpModel(gcp)
    if joined:
        model.set_related([k8s])
    return [(target, grant.confidence) for reach in
            Evaluator(model, [ENTRY], include_unknown=True, admin_scopes={}).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()]


def test_exact_running_pod_and_metadata_mode_reach_cross_project_sa():
    target = "serviceAccount:" + EMAIL
    assert case() == [(target, "conditional")]
    assert case(mode="SECURE") == [(target, "conditional")]
    assert case(mode="GKE_METADATA", host_network=True) == [(target, "conditional")]
    assert case(mode="GKE_METADATA") == []
    assert case(node_pool="other") == []
    assert case(pod_node="other") == []
    assert case(running=False) == []
    assert case(runtime_class="gvisor") == []


def test_missing_authority_or_inventory_does_not_claim_exec_path():
    assert case(exec_permission=False) == []
    assert case(get=False) == []
    assert case(disabled=True) == []
    assert case(joined=False)[0][1] == "unknown"
    assert case(private=True)[0][1] == "unknown"
    assert case(pod_status="denied")[0][1] == "unknown"
    assert case(node_status="denied")[0][1] == "unknown"
    assert case(autopilot=True)[0][1] == "unknown"
