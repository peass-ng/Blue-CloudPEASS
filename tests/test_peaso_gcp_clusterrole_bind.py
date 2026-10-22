"""GKE IAM bind rights need a real cluster-admin role and a usable binding write."""
from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

PROJECT = "projects/demo-project1"
CLUSTER = PROJECT + "/locations/us-central1/clusters/primary"
SOURCE = "user:operator@example.com"
ROLE = PROJECT + "/roles/rbacWriter"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-container-clusterroles-bind")


def row(kind, records, scope=PROJECT, status=None):
    return {"type": kind, "scope": scope, "status": status or ("collected" if records else "empty"),
            "items": records}


def case(*, create=True, update=False, existing="none", role=True, get=True, bind=True,
         cluster_status="RUNNING", private=False, joined=True, prior=False,
         binding_status=None, custom_group=False):
    permissions = ["container.clusterRoles.bind"] if bind else []
    if create:
        permissions.append("container.clusterRoleBindings.create")
    if update:
        permissions.append("container.clusterRoleBindings.update")
    if get:
        permissions.append("container.clusters.get")
    gcp = {"provider": "gcp", "metadata": {}, "collections": [
        row("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        row("iam_role", [{"name": ROLE, "includedPermissions": permissions}]),
        row("iam_policy", [{"name": PROJECT, "bindings": [{"role": ROLE, "members": [SOURCE]}]}]),
        row("iam_deny_policy", []),
        row("gke_cluster", [{"name": "primary", "location": "us-central1",
                             "status": cluster_status, "endpoint": "203.0.113.10",
                             "privateClusterConfig": {"enablePrivateEndpoint": private},
                             "masterAuthorizedNetworksConfig": {"enabled": False}}]),
    ]}
    binding_role = "cluster-admin" if existing == "admin" else "view"
    subjects = ([{"kind": "User", "name": SOURCE.removeprefix("user:")}] if prior else
                [{"kind": "Group", "name": "team-admins" if custom_group else "system:masters"}])
    bindings = [{"metadata": {"name": "existing"}, "roleRef": {
        "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": binding_role},
        "subjects": subjects}] if existing != "none" else []
    k8s = {"provider": "k8s", "metadata": {"cluster_id": CLUSTER}, "collections": [
        row("clusterrole", [{"metadata": {"name": "cluster-admin"},
                            "rules": [{"apiGroups": ["*"], "resources": ["*"],
                                       "verbs": ["*"]}]}] if role else [], "*"),
        row("clusterrolebinding", bindings, "*", binding_status),
    ]}
    model = GcpModel(gcp)
    if joined:
        model.set_related([k8s])
    return [(target, grant.confidence) for reach in
            Evaluator(model, [ENTRY], include_unknown=True, admin_scopes={}).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()]


def test_create_requires_exact_running_cluster_and_admin_role():
    assert case() == [("k8s_cluster_admin:" + CLUSTER, "conditional")]
    assert case(role=False)[0][1] == "unknown"
    assert case(cluster_status="ERROR")[0][1] == "unknown"
    assert case(joined=False)[0][1] == "unknown"
    assert case(get=False)[0][1] == "unknown"
    assert case(private=True)[0][1] == "unknown"
    assert case(bind=False) == []
    assert case(binding_status="denied")[0][1] == "unknown"


def test_update_cannot_repoint_an_unrelated_binding():
    assert case(create=False, update=True, existing="none") == []
    assert case(create=False, update=True, existing="other") == []
    assert case(create=False, update=True, existing="admin") == [
        ("k8s_cluster_admin:" + CLUSTER, "conditional")]
    assert case(create=False, update=True, existing="admin", prior=True) == []
    assert case(create=False, update=True, existing="admin", custom_group=True)[0][1] == "unknown"
