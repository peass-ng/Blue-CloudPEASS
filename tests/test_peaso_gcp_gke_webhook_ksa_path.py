"""GKE webhook grants need an exact cluster and an active KSA target."""
from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

PROJECT = "projects/demo-project1"
CLUSTER = PROJECT + "/locations/us-central1/clusters/primary"
SOURCE = "user:operator@example.com"
ROLE = PROJECT + "/roles/webhookWriter"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-container-mutatingwebhookconfigurations-write")


def row(kind, records, scope=PROJECT, status=None):
    return {"type": kind, "scope": scope, "status": status or ("collected" if records else "empty"),
            "items": records}


def case(*, create=True, update=False, existing=False, get=True, running=True,
         autopilot=False, namespace="work", private=False, joined=True,
         webhook_status=None):
    permissions = []
    if create:
        permissions.append("container.mutatingWebhookConfigurations.create")
    if update:
        permissions.append("container.mutatingWebhookConfigurations.update")
    if get:
        permissions.append("container.clusters.get")
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
    k8s = {"provider": "k8s", "metadata": {"cluster_id": CLUSTER}, "collections": [
        row("serviceaccount", [{"metadata": {"name": "app", "namespace": namespace}}], "*"),
        row("pod", [{"metadata": {"name": "app-1", "namespace": namespace},
                     "spec": {"serviceAccountName": "app", "containers": [{"name": "app"}]},
                     "status": {"phase": "Running" if running else "Pending"}}], "*"),
        row("mutatingwebhookconfiguration", [{"metadata": {"name": "existing"}}] if existing else [],
            "*", webhook_status),
    ]}
    model = GcpModel(gcp)
    if joined:
        model.set_related([k8s])
    return [(target, grant.confidence) for reach in
            Evaluator(model, [ENTRY], include_unknown=True, admin_scopes={}).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()]


def test_create_requires_active_ksa_and_cluster_authentication():
    target = "k8s:" + CLUSTER + ":sa:work:app"
    assert case() == [(target, "conditional")]
    assert case(running=False)[0][1] == "unknown"
    assert case(get=False) == []
    assert case(joined=False)[0][1] == "unknown"
    assert case(private=True)[0][1] == "unknown"
    assert case(create=False) == []


def test_update_requires_existing_configuration_and_autopilot_scope():
    target = "k8s:" + CLUSTER + ":sa:work:app"
    assert case(create=False, update=True, existing=True) == [(target, "conditional")]
    assert case(create=False, update=True, existing=False) == []
    assert case(create=False, update=True, existing=True, webhook_status="denied")[0][1] == "unknown"
    assert case(autopilot=True, namespace="kube-system")[0][1] == "unknown"
    assert case(autopilot=False, namespace="kube-system")[0][1] == "unknown"
    assert case(autopilot=True, namespace="work") == [(target, "conditional")]
