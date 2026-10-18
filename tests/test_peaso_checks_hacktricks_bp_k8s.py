"""HackTricks Cloud Best Practices Kubernetes predicates: semantics beyond the shared fixtures."""
import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES

REGISTRY = {c.id: c for c in CHECKS}


def run(cid, item, index=None):
    return REGISTRY[cid].evaluate(item, index or {})


@pytest.mark.parametrize("kind", ["role", "clusterrole"])
def test_impersonation_matches_wildcards_and_records_resource_names(kind):
    cid = "k8s.htbp." + kind + ".no_impersonation"
    status, evidence = run(cid, {"rules": [{"apiGroups": [""], "resources": ["serviceaccounts"], "verbs": ["impersonate"], "resourceNames": ["deployer"]}]})
    assert status == "FAIL" and evidence["matching_rules"][0]["resourceNames"] == ["deployer"]
    assert run(cid, {"rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]})[0] == "FAIL"
    # Group-only impersonation cannot initiate impersonation (HackTricks rbac-and-identities).
    assert run(cid, {"rules": [{"apiGroups": [""], "resources": ["groups"], "verbs": ["impersonate"]}]})[0] == "PASS"
    # nonResourceURLs rules grant no API resource.
    assert run(cid, {"rules": [{"nonResourceURLs": ["/healthz"], "verbs": ["*"]}]})[0] == "PASS"
    assert run(cid, {"rules": []})[0] == "PASS"


def test_pod_interactive_subresources_and_verbs():
    cid = "k8s.htbp.role.no_pod_interactive_access"
    assert run(cid, {"rules": [{"apiGroups": [""], "resources": ["pods/*"], "verbs": ["create"]}]})[0] == "FAIL"
    assert run(cid, {"rules": [{"apiGroups": [""], "resources": ["pods/ephemeralcontainers"], "verbs": ["patch"]}]})[0] == "FAIL"
    assert run(cid, {"rules": [{"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["get"]}]})[0] == "PASS"
    assert run(cid, {"rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["*"]}]})[0] == "PASS"


def test_controller_writes_require_matching_group():
    cid = "k8s.htbp.clusterrole.no_workload_controller_write"
    assert run(cid, {"rules": [{"apiGroups": ["batch"], "resources": ["cronjobs"], "verbs": ["patch"]}]})[0] == "FAIL"
    assert run(cid, {"rules": [{"apiGroups": ["extensions.example.com"], "resources": ["deployments"], "verbs": ["create"]}]})[0] == "PASS"
    assert run(cid, {"rules": [{"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["get", "list"]}]})[0] == "PASS"


def test_bootstrap_roles_are_provider_managed_not_failures():
    item = {"metadata": {"name": "edit", "labels": {"kubernetes.io/bootstrapping": "rbac-defaults"}},
            "rules": [{"apiGroups": [""], "resources": ["serviceaccounts"], "verbs": ["impersonate"]}]}
    status, evidence = run("k8s.htbp.clusterrole.no_impersonation", item)
    assert status == "NOT_APPLICABLE" and evidence["underlying_status"] == "FAIL"


def test_anonymous_binding_and_kubeadm_cluster_info_exception():
    cid = "k8s.htbp.rolebinding.no_anonymous_user"
    item = {"metadata": {"name": "kubeadm:bootstrap-signer-clusterinfo", "namespace": "kube-public"},
            "roleRef": {"kind": "Role", "name": "kubeadm:bootstrap-signer-clusterinfo"},
            "subjects": [{"kind": "User", "name": "system:anonymous"}]}
    assert run(cid, item)[0] == "NOT_APPLICABLE"
    item["metadata"]["namespace"] = "apps"
    assert run(cid, item)[0] == "FAIL"
    assert run(cid, {"roleRef": {"kind": "Role", "name": "r"}})[0] == "PASS"


def test_service_external_ips_and_legacy_tokens():
    assert run("k8s.htbp.service.no_external_ips", {"spec": {"externalIPs": []}})[0] == "PASS"
    assert run("k8s.htbp.service.no_external_ips", {"spec": {"externalIPs": [1]}})[0] == "UNKNOWN"
    assert run("k8s.htbp.secret.no_legacy_service_account_token", {"metadata": {"name": "s"}, "type": "Opaque"})[0] == "PASS"
    _, evidence = run("k8s.htbp.secret.no_legacy_service_account_token", CASES["k8s.htbp.secret.no_legacy_service_account_token"]["fail"])
    assert evidence["service_account"] == "ci"
