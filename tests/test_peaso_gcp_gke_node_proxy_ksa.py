"""Node proxy KSA reach requires a running container and matching GKE Node."""
from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

PROJECT = "projects/demo-project1"
CLUSTER = PROJECT + "/locations/us-central1/clusters/primary"
SOURCE = "user:operator@example.com"
ROLE = PROJECT + "/roles/nodeProxy"
TARGET = "k8s:" + CLUSTER + ":sa:work:app"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-container-nodes-proxy-running-ksa")


def row(kind, records, scope=PROJECT, status=None):
    return {"type": kind, "scope": scope, "status": status or ("collected" if records else "empty"),
            "items": records}


def case(*, proxy=True, get=True, joined=True, private=False, autopilot=False,
         pod_node="node-a", running=True, automount=True, projected=False,
         node_status=None, pod_status=None):
    permissions = ((["container.nodes.proxy"] if proxy else []) +
                   (["container.clusters.get"] if get else []))
    gcp = {"provider": "gcp", "metadata": {}, "collections": [
        row("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        row("iam_role", [{"name": ROLE, "includedPermissions": permissions}]),
        row("iam_policy", [{"name": PROJECT, "bindings": [{"role": ROLE,
                                                            "members": [SOURCE]}]}]),
        row("iam_deny_policy", []),
        row("gke_cluster", [{"name": "primary", "location": "us-central1",
                             "status": "RUNNING", "endpoint": "203.0.113.10",
                             "autopilot": {"enabled": autopilot},
                             "privateClusterConfig": {"enablePrivateEndpoint": private},
                             "masterAuthorizedNetworksConfig": {"enabled": False}}]),
    ]}
    spec = {"serviceAccountName": "app", "nodeName": pod_node,
            "automountServiceAccountToken": automount,
            "containers": [{"name": "app", "volumeMounts": [
                {"name": "token", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"}]
                if projected else []}]}
    if projected:
        spec["volumes"] = [{"name": "token", "projected": {"sources": [
            {"serviceAccountToken": {"path": "token"}}]}}]
    pod = {"metadata": {"name": "app-1", "namespace": "work"}, "spec": spec,
           "status": {"phase": "Running" if running else "Pending",
                      "containerStatuses": [{"name": "app", "state": {
                          "running": {"startedAt": "2026-01-01T00:00:00Z"}}}]}}
    k8s = {"provider": "k8s", "metadata": {"cluster_id": CLUSTER}, "collections": [
        row("serviceaccount", [{"metadata": {"name": "app", "namespace": "work"}}], "*"),
        row("node", [{"metadata": {"name": "node-a"},
                      "spec": {"providerID": "gce://demo-project1/us-central1-a/node-a"}}],
            "*", node_status),
        row("pod", [pod], "*", pod_status),
    ]}
    model = GcpModel(gcp)
    if joined:
        model.set_related([k8s])
    return [(target, grant.confidence) for reach in
            Evaluator(model, [ENTRY], include_unknown=True, admin_scopes={}).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()]


def test_running_container_on_joined_node_exposes_mounted_ksa():
    assert case() == [(TARGET, "conditional")]
    assert case(automount=False, projected=True) == [(TARGET, "conditional")]
    assert case(automount=False, projected=False) == []
    assert case(pod_node="node-b")[0][1] == "unknown"
    assert case(running=False) == []


def test_missing_authority_and_inventory_do_not_claim_ksa():
    assert case(proxy=False) == []
    assert case(get=False) == []
    assert case(joined=False)[0][1] == "unknown"
    assert case(private=True)[0][1] == "unknown"
    assert case(autopilot=True)[0][1] == "unknown"
    assert case(node_status="denied")[0][1] == "unknown"
    assert case(pod_status="denied")[0][1] == "unknown"
