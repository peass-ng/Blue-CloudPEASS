"""A chosen GKE node identity needs a real Pod execution route."""
from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

PROJECT = "projects/demo-project1"
EMAIL = "node-power@demo-project1.iam.gserviceaccount.com"
SOURCE = "user:operator@example.com"
CLUSTER = PROJECT + "/locations/us-central1/clusters/primary"
ROLE = PROJECT + "/roles/gkeNodeAuthor"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-container-clusters-nodepools-create-actas")


def row(kind, records):
    return {"type": kind, "scope": PROJECT, "status": "collected" if records else "empty",
            "items": records}


def case(*, create=False, update=False, get=True, pod=True, actas=True,
         autopilot=False, private=False, status="RUNNING", disabled=False,
         rbac=False, rbac_cluster=CLUSTER):
    permissions = []
    if create:
        permissions.append("container.clusters.create")
    if update:
        permissions.append("container.clusters.update")
    if get:
        permissions.append("container.clusters.get")
    if pod:
        permissions.append("container.pods.create")
    cluster = {"name": "primary", "location": "us-central1", "status": status,
               "autopilot": {"enabled": autopilot}, "endpoint": "203.0.113.10",
               "privateClusterConfig": {"enablePrivateEndpoint": private},
               "masterAuthorizedNetworksConfig": {"enabled": False}}
    snapshot = {"provider": "gcp", "metadata": {}, "collections": [
        row("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        row("service_account", [{"email": EMAIL, "projectId": "demo-project1",
                                 "disabled": disabled}]),
        row("iam_role", [{"name": ROLE, "includedPermissions": permissions}]),
        row("iam_policy", [{"name": PROJECT, "bindings": [
            {"role": ROLE, "members": [SOURCE]},
            *([{"role": "roles/iam.serviceAccountUser", "members": [SOURCE]}] if actas else [])]}]),
        row("iam_deny_policy", []),
        row("gke_cluster", [cluster]),
    ]}
    model = GcpModel(snapshot)
    if rbac:
        k8s = {"provider": "k8s", "metadata": {"cluster_id": rbac_cluster}, "collections": [
            {"type": "role", "scope": "*", "status": "collected", "items": [
                {"metadata": {"name": "pod-author", "namespace": "work"},
                 "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}]}]},
            {"type": "rolebinding", "scope": "*", "status": "collected", "items": [
                {"metadata": {"name": "pod-author", "namespace": "work"},
                 "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                             "name": "pod-author"},
                 "subjects": [{"kind": "User", "name": SOURCE.removeprefix("user:")}]}]},
        ]}
        model.set_related([k8s])
    return [(target, grant.confidence) for reach in
            Evaluator(model, [ENTRY], include_unknown=True, admin_scopes={}).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()]


def test_new_cluster_requires_create_actas_and_pod_route():
    target = "serviceAccount:" + EMAIL
    assert case(create=True) == [(target, "conditional")]
    assert case(create=True, pod=False)[0][1] == "unknown"
    assert case(create=True, get=False)[0][1] == "unknown"
    assert case(create=True, actas=False) == []
    assert case(create=True, disabled=True) == []


def test_existing_node_pool_requires_running_standard_cluster_and_pod_route():
    target = "serviceAccount:" + EMAIL
    assert case(update=True) == [(target, "conditional")]
    assert case(update=True, autopilot=True)[0][1] == "unknown"
    assert case(update=True, private=True)[0][1] == "unknown"
    assert case(update=True, status="ERROR")[0][1] == "unknown"
    assert case(update=True, pod=False)[0][1] == "unknown"
    assert case(update=True, pod=False, rbac=True) == [(target, "conditional")]
    assert case(update=True, pod=False, rbac=True, rbac_cluster=
                PROJECT + "/locations/us-central1/clusters/other")[0][1] == "unknown"
    assert case() == []


def cross_project_case(*, policy=False, compute_agent=True, gke_agent=True):
    host, target_project = "projects/host", "projects/target"
    email = "node-power@target.iam.gserviceaccount.com"
    compute = "service-100@compute-system.iam.gserviceaccount.com"
    gke = "service-100@container-engine-robot.iam.gserviceaccount.com"
    bindings = [{"role": "roles/iam.serviceAccountUser", "members": [SOURCE]}]
    if compute_agent:
        bindings.append({"role": "roles/iam.serviceAccountTokenCreator",
                         "members": ["serviceAccount:" + compute]})
    if gke_agent:
        bindings.append({"role": "roles/iam.serviceAccountUser",
                         "members": ["serviceAccount:" + gke]})
    collections = [
        {"type": "project", "scope": host, "status": "collected",
         "items": [{"name": "projects/100", "projectId": "host"}]},
        {"type": "project", "scope": target_project, "status": "collected",
         "items": [{"name": "projects/200", "projectId": "target"}]},
        {"type": "iam_role", "scope": host, "status": "collected", "items": [
            {"name": host + "/roles/gkeNodeAuthor", "includedPermissions": [
                "container.clusters.create", "container.clusters.get", "container.pods.create"]}]},
        {"type": "iam_policy", "scope": host, "status": "collected", "items": [
            {"name": host, "bindings": [{"role": host + "/roles/gkeNodeAuthor",
                                            "members": [SOURCE]}]}]},
        {"type": "service_account", "scope": target_project, "status": "collected", "items": [
            {"email": email, "projectId": "target", "iamPolicy": {"bindings": bindings}}]},
        {"type": "org_policy_effective", "scope": target_project, "status": "collected",
         "items": [{"constraint": "iam.disableCrossProjectServiceAccountUsage",
                    "spec": {"rules": [{"enforce": policy}]}}] if policy is not None else []},
        {"type": "iam_deny_policy", "scope": host, "status": "empty", "items": []},
        {"type": "iam_deny_policy", "scope": target_project, "status": "empty", "items": []},
    ]
    model = GcpModel({"provider": "gcp", "metadata": {}, "collections": collections})
    return [(target, grant.confidence) for reach in
            Evaluator(model, [ENTRY], include_unknown=True, admin_scopes={}).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()]


def test_cross_project_attachment_requires_both_service_agents_and_policy():
    target = "serviceAccount:node-power@target.iam.gserviceaccount.com"
    assert cross_project_case() == [(target, "conditional")]
    assert cross_project_case(policy=None)[0][1] == "unknown"
    assert cross_project_case(compute_agent=False)[0][1] == "unknown"
    assert cross_project_case(gke_agent=False)[0][1] == "unknown"
    assert cross_project_case(policy=True) == []
