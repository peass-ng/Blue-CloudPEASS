"""GKE escalate rights reach cluster-admin only through an existing binding."""
from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

PROJECT = "projects/demo-project1"
CLUSTER = PROJECT + "/locations/us-central1/clusters/primary"
SOURCE = "user:operator@example.com"
ROLE = PROJECT + "/roles/roleWriter"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-container-clusterroles-escalate")


def row(kind, records, scope=PROJECT, status=None):
    return {"type": kind, "scope": scope,
            "status": status or ("collected" if records else "empty"), "items": records}


def case(*, update=True, create=False, binding="bound", role_exists=True,
         aggregated=False, wildcard=False, get=True, escalate=True, joined=True,
         private=False, cluster_status="RUNNING", role_status=None):
    permissions = (["container.clusterRoles.escalate"] if escalate else [])
    if update:
        permissions.append("container.clusterRoles.update")
    if create:
        permissions.append("container.clusterRoles.create")
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
    rules = ([{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}] if wildcard else
             [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}])
    clusterrole = {"metadata": {"name": "operator-role"}, "rules": rules}
    if aggregated:
        clusterrole["aggregationRule"] = {"clusterRoleSelectors": [{"matchLabels": {"team": "operators"}}]}
    subjects = [{"kind": "User", "name": SOURCE.removeprefix("user:")}]
    if binding == "other-user":
        subjects = [{"kind": "User", "name": "other@example.com"}]
    elif binding == "unknown-group":
        subjects = [{"kind": "Group", "name": "operators@example.com"}]
    bindings = [{"metadata": {"name": "existing"}, "roleRef": {
        "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
        "name": "operator-role" if binding != "unrelated" else "other-role"},
        "subjects": subjects}] if binding != "none" else []
    k8s = {"provider": "k8s", "metadata": {"cluster_id": CLUSTER}, "collections": [
        row("clusterrole", [clusterrole] if role_exists else [], "*", role_status),
        row("clusterrolebinding", bindings, "*"),
    ]}
    model = GcpModel(gcp)
    if joined:
        model.set_related([k8s])
    return [(target, grant.confidence) for reach in
            Evaluator(model, [ENTRY], include_unknown=True, admin_scopes={}).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()]


def test_existing_bound_clusterrole_update_can_gain_cluster_admin():
    assert case() == [("k8s_cluster_admin:" + CLUSTER, "conditional")]
    assert case(binding="none") == []
    assert case(binding="other-user") == []
    assert case(update=False, create=True) == []
    assert case(escalate=False) == []
    assert case(wildcard=True) == []


def test_existing_binding_to_missing_role_allows_create_route():
    assert case(update=False, create=True, role_exists=False) == [
        ("k8s_cluster_admin:" + CLUSTER, "conditional")]
    assert case(update=True, create=False, role_exists=False) == []
    assert case(update=False, create=True, role_exists=False, binding="none") == []


def test_incomplete_binding_or_endpoint_stays_unresolved():
    for variation in ({"joined": False}, {"get": False}, {"private": True},
                      {"cluster_status": "ERROR"}, {"aggregated": True},
                      {"binding": "unknown-group"}, {"role_status": "denied"}):
        result = case(**variation)
        assert len(result) == 1 and result[0][1] == "unknown", variation
