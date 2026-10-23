"""GKE Pod-template KSA paths require a same-namespace mutable workload."""
from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

PROJECT = "projects/demo-project1"
CLUSTER = PROJECT + "/locations/us-central1/clusters/primary"
SOURCE = "user:operator@example.com"
ROLE = PROJECT + "/roles/workloadWriter"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-container-pod-template-ksa")


def row(kind, records, scope=PROJECT, status=None):
    return {"type": kind, "scope": scope, "status": status or ("collected" if records else "empty"),
            "items": records}


def case(action, *, controller_kind="deployment", controller_namespace="work",
         controller_status=None, joined=True, get=True, private=False):
    permissions = [action] + (["container.clusters.get"] if get else [])
    gcp = {"provider": "gcp", "metadata": {}, "collections": [
        row("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        row("iam_role", [{"name": ROLE, "includedPermissions": permissions}]),
        row("iam_policy", [{"name": PROJECT, "bindings": [{"role": ROLE, "members": [SOURCE]}]}]),
        row("iam_deny_policy", []),
        row("gke_cluster", [{"name": "primary", "location": "us-central1", "status": "RUNNING",
                             "endpoint": "203.0.113.10",
                             "privateClusterConfig": {"enablePrivateEndpoint": private},
                             "masterAuthorizedNetworksConfig": {"enabled": False}}]),
    ]}
    controller = {"metadata": {"name": "app", "namespace": controller_namespace},
                  "spec": {"template": {"spec": {"containers": [{"name": "app", "image": "app:1"}]}}}}
    if controller_kind == "cronjob":
        controller["spec"] = {"jobTemplate": {"spec": controller["spec"]}}
    k8s = {"provider": "k8s", "metadata": {"cluster_id": CLUSTER}, "collections": [
        row("serviceaccount", [{"metadata": {"name": "app", "namespace": "work"}}], "*"),
        row(controller_kind, [controller] if controller_namespace else [], "*", controller_status),
    ]}
    model = GcpModel(gcp)
    if joined:
        model.set_related([k8s])
    return [(target, grant.confidence) for reach in
            Evaluator(model, [ENTRY], include_unknown=True, admin_scopes={}).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()]


def test_create_can_select_existing_ksa_without_existing_controller():
    target = "k8s:" + CLUSTER + ":sa:work:app"
    assert case("container.pods.create", controller_namespace="") == [(target, "conditional")]
    assert case("container.jobs.create", controller_namespace="") == [(target, "conditional")]
    assert case("container.pods.create", private=True)[0][1] == "unknown"
    assert case("container.pods.create", joined=False)[0][1] == "unknown"
    assert case("container.pods.create", get=False) == []


def test_update_requires_mutable_controller_in_target_namespace():
    target = "k8s:" + CLUSTER + ":sa:work:app"
    assert case("container.deployments.update") == [(target, "conditional")]
    assert case("container.cronJobs.update", controller_kind="cronjob") == [(target, "conditional")]
    assert case("container.deployments.update", controller_namespace="other") == []
    assert case("container.deployments.update", controller_namespace="") == []
    assert case("container.deployments.update", controller_status="denied")[0][1] == "unknown"
    assert case("container.jobs.update", controller_kind="job") == []
