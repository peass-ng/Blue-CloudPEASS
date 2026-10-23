"""Namespaced GKE RBAC writes must reach an exact KSA through usable rights."""
from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

PROJECT = "projects/demo-project1"
CLUSTER = PROJECT + "/locations/us-central1/clusters/primary"
SOURCE = "user:operator@example.com"
ROLE = PROJECT + "/roles/rbacWriter"
TARGET = "k8s:" + CLUSTER + ":sa:work:app"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-container-namespaced-rbac-ksa")


def row(kind, records, scope=PROJECT, status=None):
    return {"type": kind, "scope": scope, "status": status or ("collected" if records else "empty"),
            "items": records}


def role(kind="ClusterRole", name="admin", namespace="work", authority=True, token=False):
    rules = ([{"apiGroups": [""], "resources": ["serviceaccounts/token" if token else "pods"],
               "verbs": ["create"]}]
             if authority else [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}])
    metadata = {"name": name}
    if kind == "Role":
        metadata["namespace"] = namespace
    return {"metadata": metadata, "rules": rules}


def binding(kind="ClusterRole", name="admin", namespace="work", subject=False):
    return {"metadata": {"name": "existing", "namespace": namespace},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": kind, "name": name},
            "subjects": [{"kind": "User", "name": SOURCE.removeprefix("user:") if subject else
                          "someone-else@example.com"}]}


def case(permissions, *, cluster_roles=(), roles=(), bindings=(), namespace="work",
         get=True, joined=True, private=False, statuses=None):
    permissions = list(permissions) + (["container.clusters.get"] if get else [])
    gcp = {"provider": "gcp", "metadata": {}, "collections": [
        row("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        row("iam_role", [{"name": ROLE, "includedPermissions": permissions}]),
        row("iam_policy", [{"name": PROJECT, "bindings": [{"role": ROLE,
                                                            "members": [SOURCE]}]}]),
        row("iam_deny_policy", []),
        row("gke_cluster", [{"name": "primary", "location": "us-central1",
                             "status": "RUNNING", "endpoint": "203.0.113.10",
                             "privateClusterConfig": {"enablePrivateEndpoint": private},
                             "masterAuthorizedNetworksConfig": {"enabled": False}}]),
    ]}
    statuses = statuses or {}
    k8s = {"provider": "k8s", "metadata": {"cluster_id": CLUSTER}, "collections": [
        row("serviceaccount", [{"metadata": {"name": "app", "namespace": namespace}}],
            "*", statuses.get("serviceaccount")),
        row("role", list(roles), "*", statuses.get("role")),
        row("clusterrole", list(cluster_roles), "*", statuses.get("clusterrole")),
        row("rolebinding", list(bindings), "*", statuses.get("rolebinding")),
    ]}
    model = GcpModel(gcp)
    if joined:
        model.set_related([k8s])
    return [(target, grant.confidence) for reach in
            Evaluator(model, [ENTRY], include_unknown=True, admin_scopes={}).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()]


def test_bind_requires_role_kind_and_binding_write_on_target_namespace():
    cluster = [role()]
    assert case(["container.clusterRoles.bind", "container.roleBindings.create"],
                cluster_roles=cluster) == [(TARGET, "conditional")]
    assert case(["container.roles.bind", "container.roleBindings.create"],
                cluster_roles=cluster) == []
    assert case(["container.clusterRoles.bind", "container.roleBindings.update"],
                cluster_roles=cluster, bindings=[binding()]) == [(TARGET, "conditional")]
    assert case(["container.clusterRoles.bind", "container.roleBindings.update"],
                cluster_roles=cluster, bindings=[binding(name="view")]) == []
    assert case(["container.roles.bind", "container.roleBindings.create"],
                roles=[role("Role")]) == [(TARGET, "conditional")]
    assert case(["container.roles.bind", "container.roleBindings.create"],
                roles=[role("Role", token=True)]) == [(TARGET, "conditional")]
    assert case(["container.clusterRoles.bind", "container.roleBindings.create"],
                cluster_roles=cluster, bindings=[binding(subject=True)]) == []


def test_role_escalation_needs_existing_reaching_binding_or_full_create_chain():
    update = ["container.roles.escalate", "container.roles.update"]
    assert case(update, roles=[role("Role", authority=False)],
                bindings=[binding("Role", subject=True)]) == [(TARGET, "conditional")]
    assert case(update, roles=[role("Role", authority=False)],
                bindings=[binding("Role", subject=False)]) == []
    assert case(["container.roles.escalate", "container.roles.create"],
                bindings=[binding("Role", subject=True)]) == [(TARGET, "conditional")]
    assert case(["container.roles.escalate", "container.roles.create",
                 "container.roles.bind", "container.roleBindings.create"]) == [(TARGET, "conditional")]


def test_missing_or_unrelated_evidence_stays_unresolved():
    perms = ["container.clusterRoles.bind", "container.roleBindings.create"]
    assert case(perms, cluster_roles=[role()], get=False) == []
    assert case(perms, cluster_roles=[role()], joined=False)[0][1] == "unknown"
    assert case(perms, cluster_roles=[role()], private=True)[0][1] == "unknown"
    assert case(perms, cluster_roles=[role()], statuses={"rolebinding": "denied"})[0][1] == "unknown"
    assert case(perms, cluster_roles=[role()], statuses={"serviceaccount": "denied"})[0][1] == "unknown"
    assert case(["container.roles.bind", "container.roleBindings.create"],
                roles=[role("Role", namespace="work")], namespace="other") == []
