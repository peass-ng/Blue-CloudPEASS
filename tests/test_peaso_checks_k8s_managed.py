"""Provider/control-plane-managed Kubernetes objects: NOT_APPLICABLE with provider_managed evidence.

Every family gets three fixtures: the managed object (NOT_APPLICABLE), the same object without managed markers
(still FAIL), and a customer workload in kube-system (still evaluated).
"""
import copy
import json

import pytest

from peaso.checks import CHECKS
from peaso.checks.k8s_managed import control_plane_subject, managed_reason
from peaso.collectors.k8s import _sanitize
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

REGISTRY = {check.id: check for check in CHECKS}
ADDON = {"addonmanager.kubernetes.io/mode": "Reconcile"}
RBAC_DEFAULTS = {"kubernetes.io/bootstrapping": "rbac-defaults"}
WEAK_CONTAINER = {"name": "c", "image": "registry.example/app:v1", "securityContext": {}}
KINDS = ("pod", "daemonset", "deployment", "replicaset", "namespace", "serviceaccount", "clusterrole",
         "clusterrolebinding", "role", "rolebinding", "resourcequota", "limitrange", "networkpolicy", "node")


def meta(name, namespace=None, labels=None, **extra):
    out = {"name": name, "uid": "uid-" + (namespace or "_") + "-" + name, **extra}
    if namespace:
        out["namespace"] = namespace
    if labels:
        out["labels"] = dict(labels)
    return out


def pod(name, namespace, labels=None, owner=None, **extra):
    m = meta(name, namespace, labels)
    if owner:
        kind, owner_name, owner_ns = owner
        m["ownerReferences"] = [{"apiVersion": "apps/v1", "kind": kind, "name": owner_name, "controller": True,
                                 "uid": "uid-" + owner_ns + "-" + owner_name}]
    return {"metadata": m, "spec": {"containers": [copy.deepcopy(WEAK_CONTAINER)]}, **extra}


def workload(name, namespace, labels=None, owner=None):
    item = {"metadata": meta(name, namespace, labels), "spec": {"template": {"metadata": {}, "spec": {"containers": [copy.deepcopy(WEAK_CONTAINER)]}}}}
    if owner:
        kind, owner_name = owner
        item["metadata"]["ownerReferences"] = [{"kind": kind, "name": owner_name, "controller": True, "uid": "uid-" + namespace + "-" + owner_name}]
    return item


def evaluate(objects, checks):
    collections = [{"type": kind, "scope": "*", "service": "kubernetes", "status": "collected" if objects.get(kind) else "empty",
                    "items": objects.get(kind, [])} for kind in KINDS]
    snapshot = make_snapshot("k8s", ["*"], collections, created_at="2026-10-10T00:00:00Z")
    report = evaluate_snapshot(snapshot, checks=checks, include_not_applicable=True)
    return {(f["native_resource_id"] if "native_resource_id" in f else f["resource_id"], f["check_id"]): (f["status"], f["evidence"])
            for f in report["findings"] if not str(f.get("resource_id", "")).startswith("inventory:")}


def status_of(results, name, check):
    hits = [value for (rid, cid), value in results.items() if cid == check and (rid == name or rid.endswith("/" + name))]
    assert len(hits) == 1, (name, check, sorted(results))
    return hits[0]


def assert_managed(results, name, check, reason_fragment):
    status, evidence = status_of(results, name, check)
    assert status == "NOT_APPLICABLE", (name, check, status, evidence)
    assert evidence["provider_managed"] is True and reason_fragment in evidence["managed_reason"], evidence
    assert evidence["underlying_status"] in ("FAIL", "MANUAL", "UNKNOWN", "DENIED")


def assert_evaluated(results, name, check, expected="FAIL"):
    status, evidence = status_of(results, name, check)
    assert status == expected and not evidence.get("provider_managed"), (name, check, status, evidence)


# --- Workloads ---------------------------------------------------------------------------------------------

WORKLOAD_CHECKS = ["k8s.pod.non_root", "k8s.ports.pod.drop_all", "k8s.claude.pod.cpu_limits_set",
                   "k8s.ports.daemonset.drop_all", "k8s.daemonset.non_root", "k8s.ports.deployment.drop_all",
                   "k8s.ports.replicaset.drop_all"]


def test_workloads_managed_unmarked_and_customer_in_kube_system():
    objects = {
        "daemonset": [workload("fluentbit-gke", "kube-system", ADDON), workload("fluentbit-copy", "kube-system"),
                      workload("agent", "gke-managed-system")],
        "deployment": [workload("kube-dns", "kube-system", ADDON), workload("my-app", "kube-system")],
        "replicaset": [workload("kube-dns-1", "kube-system", owner=("Deployment", "kube-dns")),
                       workload("my-app-1", "kube-system", owner=("Deployment", "my-app"))],
        "pod": [pod("kube-dns-1-a", "kube-system", owner=("ReplicaSet", "kube-dns-1", "kube-system")),
                pod("fluentbit-gke-a", "kube-system", owner=("DaemonSet", "fluentbit-gke", "kube-system")),
                pod("my-app-1-a", "kube-system", owner=("ReplicaSet", "my-app-1", "kube-system")),
                pod("debug", "kube-system"), pod("collector-a", "gmp-system")],
    }
    results = evaluate(objects, WORKLOAD_CHECKS)
    assert_managed(results, "fluentbit-gke", "k8s.ports.daemonset.drop_all", "addonmanager.kubernetes.io/mode=Reconcile")
    assert_managed(results, "fluentbit-gke", "k8s.daemonset.non_root", "addonmanager")
    assert_managed(results, "agent", "k8s.ports.daemonset.drop_all", "provider-managed namespace gke-managed-system")
    assert_managed(results, "kube-dns", "k8s.ports.deployment.drop_all", "addonmanager")
    assert_managed(results, "kube-dns-1", "k8s.ports.replicaset.drop_all", "owned by managed Deployment kube-dns")
    for check in ("k8s.pod.non_root", "k8s.ports.pod.drop_all", "k8s.claude.pod.cpu_limits_set"):
        assert_managed(results, "kube-dns-1-a", check, "owned by managed ReplicaSet kube-dns-1")
        assert_managed(results, "fluentbit-gke-a", check, "owned by managed DaemonSet fluentbit-gke")
        assert_managed(results, "collector-a", check, "gmp-system")
        # Customer workloads in kube-system are evaluated.
        assert_evaluated(results, "my-app-1-a", check)
        assert_evaluated(results, "debug", check)
    # The same objects without managed markers still FAIL.
    assert_evaluated(results, "fluentbit-copy", "k8s.ports.daemonset.drop_all")
    assert_evaluated(results, "my-app", "k8s.ports.deployment.drop_all")
    assert_evaluated(results, "my-app-1", "k8s.ports.replicaset.drop_all")


def test_mirror_pod_only_managed_on_provider_node():
    proxy = lambda name, node: {**pod(name, "kube-system", {"component": "kube-proxy"}), "_static_pod_metadata": True}
    gke, kubeadm = proxy("kube-proxy-gke", "gke-node"), proxy("kube-apiserver-cp", "cp-node")
    for item, node in ((gke, "gke-node"), (kubeadm, "cp-node")):
        item["metadata"]["ownerReferences"] = [{"kind": "Node", "name": node, "controller": True, "uid": "uid-_-" + node}]
    objects = {"pod": [gke, kubeadm], "node": [{"metadata": meta("gke-node", labels={"cloud.google.com/gke-nodepool": "default-pool"})},
                                               {"metadata": meta("cp-node", labels={"node-role.kubernetes.io/control-plane": ""})}]}
    results = evaluate(objects, ["k8s.pod.non_root"])
    assert_managed(results, "kube-proxy-gke", "k8s.pod.non_root", "provider-managed node")
    # Self-managed control-plane static pods remain the customer's (CIS control-plane checks read them).
    assert_evaluated(results, "kube-apiserver-cp", "k8s.pod.non_root")


# --- Namespaces --------------------------------------------------------------------------------------------

NAMESPACE_CHECKS = ["k8s.namespace.quota_limits_cpu", "k8s.ports.namespace.namespace_resource_quota_cpu_limit",
                    "k8s.ports.namespace.network_policy_default_deny_ingress", "k8s.network.namespace_policy_inventory"]


def test_namespace_quota_and_default_deny():
    objects = {"namespace": [{"metadata": meta(name, labels={"kubernetes.io/metadata.name": name, **extra})} for name, extra in (
        ("kube-system", {}), ("kube-public", {}), ("kube-node-lease", {}), ("gke-managed-cim", ADDON),
        ("gmp-public", ADDON), ("team-a", {}), ("kube-system-copy", {}))]}
    results = evaluate(objects, NAMESPACE_CHECKS)
    for check in NAMESPACE_CHECKS:
        for name in ("kube-system", "kube-public", "kube-node-lease"):
            assert_managed(results, name, check, "control-plane namespace " + name)
        assert_managed(results, "gke-managed-cim", check, "provider-managed namespace")
        assert_managed(results, "gmp-public", check, "addonmanager")
        assert_evaluated(results, "team-a", check)
        assert_evaluated(results, "kube-system-copy", check)


# --- RBAC: roles ---------------------------------------------------------------------------------------------

WILDCARD = [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}, {"nonResourceURLs": ["*"], "verbs": ["*"]}]
ROLE_CHECKS = ["k8s.rbac.no_wildcards", "k8s.claude.clusterrole.no_wildcard_resources_or_verbs", "k8s.claude.clusterrole.no_secret_read",
               "k8s.claude.clusterrole.no_pod_create", "k8s.ports.clusterrole.role_with_wildcards_used"]


def test_builtin_clusterroles_versus_customer_roles():
    roles = [{"metadata": meta("cluster-admin", labels=RBAC_DEFAULTS), "rules": WILDCARD},
             {"metadata": meta("gke-spiffe-issuer", labels=ADDON), "rules": WILDCARD},
             {"metadata": meta("system:controller:generic-garbage-collector"), "rules": WILDCARD},
             {"metadata": meta("my-admin"), "rules": WILDCARD},
             {"metadata": meta("cluster-admin-copy", labels={"team": "platform"}), "rules": WILDCARD}]
    results = evaluate({"clusterrole": roles}, ROLE_CHECKS)
    for check in ROLE_CHECKS:
        assert_managed(results, "cluster-admin", check, "rbac-defaults")
        assert_managed(results, "gke-spiffe-issuer", check, "addonmanager")
        assert_managed(results, "system:controller:generic-garbage-collector", check, "reserved RBAC name prefix system:")
        assert_evaluated(results, "my-admin", check)
        assert_evaluated(results, "cluster-admin-copy", check)


def test_customer_role_in_kube_system_is_evaluated():
    roles = [{"metadata": meta("leases-writer", "kube-system", ADDON), "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]},
             {"metadata": meta("ops-secrets", "kube-system"), "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]}]
    results = evaluate({"role": roles}, ["k8s.claude.role.no_secret_read"])
    assert_managed(results, "leases-writer", "k8s.claude.role.no_secret_read", "addonmanager")
    assert_evaluated(results, "ops-secrets", "k8s.claude.role.no_secret_read")


# --- RBAC: bindings ------------------------------------------------------------------------------------------

def crb(name, role, subjects, labels=None):
    return {"metadata": meta(name, labels=labels), "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": role},
            "subjects": subjects}


AUTHENTICATED = [{"apiGroup": "rbac.authorization.k8s.io", "kind": "Group", "name": "system:authenticated"}]


def test_default_discovery_bindings_versus_customer_broad_binding():
    bindings = [crb("system:basic-user", "system:basic-user", AUTHENTICATED, RBAC_DEFAULTS),
                crb("system:discovery", "system:discovery", AUTHENTICATED, RBAC_DEFAULTS),
                crb("everyone-view", "view", AUTHENTICATED)]
    results = evaluate({"clusterrolebinding": bindings, "clusterrole": [{"metadata": meta("view"), "rules": []}]},
                       ["k8s.rbac.review_broad_subjects"])
    assert_managed(results, "system:basic-user", "k8s.rbac.review_broad_subjects", "rbac-defaults")
    assert_managed(results, "system:discovery", "k8s.rbac.review_broad_subjects", "rbac-defaults")
    assert_evaluated(results, "everyone-view", "k8s.rbac.review_broad_subjects")


def test_customer_binding_to_managed_cluster_admin_still_evaluated():
    admin = {"metadata": meta("cluster-admin", labels=RBAC_DEFAULTS), "rules": WILDCARD}
    bindings = [crb("cluster-admin", "cluster-admin", [{"apiGroup": "rbac.authorization.k8s.io", "kind": "Group", "name": "system:masters"}], RBAC_DEFAULTS),
                crb("ops-admin", "cluster-admin", [{"kind": "ServiceAccount", "name": "ops", "namespace": "kube-system"}])]
    results = evaluate({"clusterrolebinding": bindings, "clusterrole": [admin]}, ["k8s.claude.clusterrolebinding.cluster_admin_review"])
    assert_managed(results, "cluster-admin", "k8s.claude.clusterrolebinding.cluster_admin_review", "rbac-defaults")
    assert_evaluated(results, "ops-admin", "k8s.claude.clusterrolebinding.cluster_admin_review", "MANUAL")


def test_kube_apiserver_user_is_not_human():
    proxy = {"metadata": meta("kubelet-api-admin", labels=ADDON), "rules": [{"apiGroups": [""], "resources": ["nodes/proxy"], "verbs": ["get"]}]}
    user = lambda name: [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": name}]
    bindings = [crb("kube-apiserver-kubelet-api-admin", "kubelet-api-admin", user("kube-apiserver"), ADDON),
                crb("apiserver-unlabelled", "kubelet-api-admin", user("kube-apiserver")),
                crb("alice-node-proxy", "kubelet-api-admin", user("alice@example.com"))]
    results = evaluate({"clusterrolebinding": bindings, "clusterrole": [proxy]}, ["k8s.claude.clusterrolebinding.no_human_node_proxy"])
    check = "k8s.claude.clusterrolebinding.no_human_node_proxy"
    assert status_of(results, "kube-apiserver-kubelet-api-admin", check)[0] == "NOT_APPLICABLE"
    # Without markers the binding is evaluated, and kube-apiserver is a control-plane user, not a human.
    status, evidence = status_of(results, "apiserver-unlabelled", check)
    assert status == "NOT_APPLICABLE" and not evidence.get("provider_managed") and "non-system" in evidence["reason"]
    assert_evaluated(results, "alice-node-proxy", check)


def test_control_plane_subject_precision():
    assert control_plane_subject({"kind": "User", "name": "kube-apiserver"})
    assert control_plane_subject({"kind": "User", "name": "system:kube-controller-manager"})
    assert control_plane_subject({"kind": "Group", "name": "system:masters"})
    assert control_plane_subject({"kind": "User", "name": "eks:addon-manager"})
    for subject in ({"kind": "Group", "name": "system:authenticated"}, {"kind": "Group", "name": "system:serviceaccounts:apps"},
                    {"kind": "User", "name": "system:serviceaccount:apps:ci"}, {"kind": "User", "name": "alice"},
                    {"kind": "User", "name": "kube-apiserver-admin"}, {"kind": "ServiceAccount", "name": "kube-apiserver"}):
        assert not control_plane_subject(subject), subject


# --- ServiceAccounts -----------------------------------------------------------------------------------------

def test_controller_serviceaccounts_versus_customer_serviceaccounts():
    accounts = [{"metadata": meta("generic-garbage-collector", "kube-system")},
                {"metadata": meta("kube-dns", "kube-system", ADDON)},
                {"metadata": meta("default", "kube-public")},
                {"metadata": meta("ci-deployer", "kube-system")},
                {"metadata": meta("generic-garbage-collector", "apps")},
                {"metadata": meta("default", "apps")}]
    results = evaluate({"serviceaccount": accounts}, ["k8s.serviceaccount.disable_automount"])
    check = "k8s.serviceaccount.disable_automount"
    assert_managed(results, "kube-system/generic-garbage-collector", check, "control-plane ServiceAccount")
    assert_managed(results, "kube-dns", check, "addonmanager")
    assert_managed(results, "kube-public/default", check, "control-plane ServiceAccount kube-public/default")
    assert_evaluated(results, "ci-deployer", check)
    assert_evaluated(results, "apps/generic-garbage-collector", check)
    assert_evaluated(results, "apps/default", check)


# --- Classifier precision -------------------------------------------------------------------------------------

@pytest.mark.parametrize("item,kind", [
    ({"metadata": {"name": "x", "namespace": "kube-system"}}, "deployment"),
    ({"metadata": {"name": "x", "namespace": "kube-system", "labels": {"addonmanager.kubernetes.io/mode": "Ignore"}}}, "deployment"),
    ({"metadata": {"name": "x", "namespace": "apps", "labels": {"k8s-app": "kube-dns"}}}, "deployment"),
    ({"metadata": {"name": "x", "namespace": "apps", "annotations": {"eks.amazonaws.com/role-arn": "arn:aws:iam::1:role/r"}}}, "serviceaccount"),
    ({"metadata": {"name": "default"}}, "namespace"),
    ({"metadata": {"name": "kubernetes", "namespace": "default"}}, "endpointslice"),
    ({}, "pod"), (None, "pod"),
])
def test_not_managed_without_evidence(item, kind):
    assert managed_reason(item, kind, {}) is None


@pytest.mark.parametrize("labels,annotations", [
    ({"addonmanager.kubernetes.io/mode": "EnsureExists"}, {}),
    ({"eks.amazonaws.com/component": "coredns"}, {}),
    ({"kubernetes.azure.com/managedby": "aks"}, {}),
    ({}, {"components.gke.io/component-name": "gke-metadata-server"}),
])
def test_provider_markers(labels, annotations):
    item = {"metadata": {"name": "x", "namespace": "kube-system", "labels": labels, "annotations": annotations}}
    assert managed_reason(item, "deployment", {})


def test_eks_and_aks_namespaces():
    assert managed_reason({"metadata": {"name": "agent", "namespace": "amazon-guardduty"}}, "daemonset", {})
    assert managed_reason({"metadata": {"name": "c", "namespace": "aks-command"}}, "pod", {})


def test_collector_keeps_gke_component_annotation_only():
    item = _sanitize({"metadata": {"annotations": {"components.gke.io/component-name": "kube-dns", "components.gke.io/x": "y" * 300,
                                                   "kubectl.kubernetes.io/last-applied-configuration": "{\"secret\": 1}"}}})
    assert item["metadata"]["annotations"] == {"components.gke.io/component-name": "kube-dns"}


# --- always_pull: digest-pinned images satisfy the control ---------------------------------------------------

DIGEST = "registry.k8s.io/pause@sha256:" + "e" * 64


@pytest.mark.parametrize("image,policy,expected", [
    (DIGEST, "IfNotPresent", "PASS"), (DIGEST, None, "PASS"), (DIGEST, "Always", "PASS"), (DIGEST, "Never", "FAIL"),
    ("busybox:1.36", "IfNotPresent", "FAIL"), ("busybox:1.36", "Always", "PASS"), ("busybox@sha256:short", "IfNotPresent", "UNKNOWN"),
])
def test_always_pull_accepts_digest_pinned_images(image, policy, expected):
    container = {"name": "c", "image": image, **({"imagePullPolicy": policy} if policy else {})}
    item = {"spec": {"containers": [container]}}
    always = REGISTRY["k8s.ports.pod.always_pull"].evaluate(item, {})[0]
    digest_variant = REGISTRY["k8s.ports.pod.content_digest_or_always_pull"].evaluate(item, {})[0]
    assert always == expected
    assert always == digest_variant, "both image-pull variants agree on digest-pinned images"


# --- Literal credential-like env values ----------------------------------------------------------------------

LITERAL = "k8s.claude.pod.no_literal_secret_env"
SENTINEL = "QA-DUMMY-literal-credential-value-7c1f"


def collected_pod(env, init_env=None):
    raw = {"metadata": {"name": "p", "namespace": "apps"},
           "spec": {"containers": [{"name": "app", "image": DIGEST, "env": env}],
                    **({"initContainers": [{"name": "init", "image": DIGEST, "env": init_env}]} if init_env else {})}}
    return _sanitize(raw)


def test_collector_keeps_only_env_name_and_length():
    item = collected_pod([{"name": "DB_PASSWORD", "value": SENTINEL}, {"name": "EMPTY_TOKEN", "value": ""}, {"name": "NO_VALUE"},
                          {"name": "API_KEY", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}])
    env = item["spec"]["containers"][0]["env"]
    assert env == [{"name": "DB_PASSWORD", "value_redacted": True, "value_length": len(SENTINEL)},
                   {"name": "EMPTY_TOKEN", "value_redacted": True, "value_length": 0},
                   {"name": "NO_VALUE", "value_redacted": True, "value_length": 0},
                   {"name": "API_KEY", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}]
    assert SENTINEL not in json.dumps(item)


def test_literal_secret_env_pass_fail_unknown_without_value_leak():
    check = REGISTRY[LITERAL]
    failing = collected_pod([{"name": "DB_PASSWORD", "value": SENTINEL}, {"name": "PLAIN", "value": SENTINEL}],
                            init_env=[{"name": "githubToken", "value": SENTINEL}])
    status, evidence = check.evaluate(failing, {})
    assert status == "FAIL"
    assert evidence["literal_credential_env"] == [{"container": "app", "env": "DB_PASSWORD"}, {"container": "init", "env": "githubToken"}]
    assert SENTINEL not in json.dumps(evidence) and evidence["value_recorded"] is False
    passing = collected_pod([{"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}},
                             {"name": "POSTGRES_PASSWORD_FILE", "value": "/run/secrets/db"}, {"name": "API_TOKEN", "value": ""},
                             {"name": "AWS_ACCESS_KEY_ID", "value": "AKIAEXAMPLE"}, {"name": "LOG_LEVEL", "value": "debug"}])
    assert check.evaluate(passing, {})[0] == "PASS"
    # Snapshots from before the length was collected cannot tell an empty literal from a credential.
    legacy = {"spec": {"containers": [{"name": "app", "env": [{"name": "API_KEY", "value_redacted": True}]}]}}
    status, evidence = check.evaluate(legacy, {})
    assert status == "UNKNOWN" and evidence["env_needing_review"] == [{"container": "app", "env": "API_KEY"}]


def test_literal_secret_env_report_never_contains_value():
    objects = {"pod": [collected_pod([{"name": "DB_PASSWORD", "value": SENTINEL}])]}
    collections = [{"type": "pod", "scope": "*", "service": "kubernetes", "status": "collected", "items": objects["pod"]}]
    snapshot = make_snapshot("k8s", ["*"], collections, created_at="2026-10-10T00:00:00Z")
    report = evaluate_snapshot(snapshot, checks=[LITERAL], include_not_applicable=True)
    assert [f["status"] for f in report["findings"] if f["check_id"] == LITERAL] == ["FAIL"]
    assert SENTINEL not in json.dumps(report) and SENTINEL not in json.dumps(snapshot)
