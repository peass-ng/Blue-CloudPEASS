"""analysis.principal_exposure on Kubernetes RBAC subjects: only cross-boundary or public subjects."""
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = "k8s-cluster:test"
PUBLIC_INFO = [{"nonResourceURLs": ["/healthz", "/livez", "/readyz", "/version", "/version/"], "verbs": ["get"]}]
SELF_REVIEW = [{"apiGroups": ["authorization.k8s.io"], "resources": ["selfsubjectaccessreviews", "selfsubjectrulesreviews"], "verbs": ["create"]}]


def role(name, rules):
    return {"metadata": {"name": name, "uid": "r-" + name}, "rules": rules}


def binding(name, role_name, subjects):
    return {"metadata": {"name": name, "uid": "b-" + name}, "roleRef": {"kind": "ClusterRole", "name": role_name, "apiGroup": "rbac.authorization.k8s.io"},
            "subjects": subjects}


def exposure(roles, bindings, metadata=None):
    snap = make_snapshot("k8s", [SCOPE], [
        {"type": "clusterrole", "scope": SCOPE, "service": "rbac", "status": "collected", "items": roles},
        {"type": "clusterrolebinding", "scope": SCOPE, "service": "rbac", "status": "collected", "items": bindings}], metadata=metadata)
    return {f["evidence"]["principals"][0]["principal"]: f["status"]
            for f in evaluate_snapshot(snap)["findings"] if f["check_id"] == "analysis.principal_exposure"}


def group(name):
    return {"kind": "Group", "name": name, "apiGroup": "rbac.authorization.k8s.io"}


def test_in_cluster_and_control_plane_subjects_are_not_exposure():
    subjects = [{"kind": "ServiceAccount", "name": "ctrl", "namespace": "kube-system"}, {"kind": "User", "name": "system:kube-scheduler"},
                {"kind": "User", "name": "kubelet-bootstrap"}, {"kind": "User", "name": "cluster-autoscaler"}, group("system:nodes"),
                group("system:serviceaccounts")]
    assert exposure([role("edit-all", [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}])],
                    [binding("b" + str(i), "edit-all", [s]) for i, s in enumerate(subjects)]) == {}


def test_default_discovery_roles_bound_to_everyone_are_not_exposure():
    assert exposure([role("system:public-info-viewer", PUBLIC_INFO), role("system:basic-user", SELF_REVIEW)],
                    [binding("system:public-info-viewer", "system:public-info-viewer", [group("system:authenticated"), group("system:unauthenticated")]),
                     binding("system:basic-user", "system:basic-user", [group("system:authenticated")])]) == {}


def test_public_binding_to_a_widened_discovery_role_fails():
    widened = PUBLIC_INFO + [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]
    assert exposure([role("system:public-info-viewer", widened)],
                    [binding("system:public-info-viewer", "system:public-info-viewer", [group("system:unauthenticated")])]) == {"system:unauthenticated": "FAIL"}


def test_public_binding_to_uncollected_role_still_fails():
    assert exposure([], [binding("anon", "system:discovery", [group("system:unauthenticated")])]) == {"system:unauthenticated": "FAIL"}


def test_idp_users_are_unknown_until_domains_are_trusted():
    bindings = [binding("alice", "view", [{"kind": "User", "name": "alice@corp.example"}]),
                binding("mallory", "view", [{"kind": "User", "name": "mallory@evil.example"}])]
    assert exposure([], bindings) == {"alice@corp.example": "UNKNOWN", "mallory@evil.example": "UNKNOWN"}
    assert exposure([], bindings, metadata={"trusted_domains": ["corp.example"]}) == {"mallory@evil.example": "FAIL"}
