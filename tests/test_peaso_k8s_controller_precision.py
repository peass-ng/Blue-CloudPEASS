"""Controller identity and managed-label precision through native findings."""

import copy

import pytest

from peaso.checks.k8s_managed import managed_reason, marker_reason
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


ADDON = {"addonmanager.kubernetes.io/mode": "Reconcile"}
POD_CHECK = "k8s.pod.non_root"


def metadata(name, namespace="kube-system", uid=None, labels=None, owners=None):
    result = {"name": name, "namespace": namespace, "uid": uid or f"uid-{namespace}-{name}"}
    if labels is not None:
        result["labels"] = labels
    if owners is not None:
        result["ownerReferences"] = owners
    return result


def ref(kind="Deployment", name="dns", uid="deployment-uid", controller=True):
    return {"kind": kind, "name": name, "uid": uid, "controller": controller}


def workload(name, *, namespace="kube-system", uid=None, labels=None, owners=None):
    return {"metadata": metadata(name, namespace, uid, labels, owners),
            "spec": {"containers": [{"name": "app", "image": "example.invalid/app:v1", "securityContext": {}}]}}


def parent(name="dns", namespace="kube-system", uid="deployment-uid", labels=None):
    return {"metadata": metadata(name, namespace, uid, ADDON if labels is None else labels)}


def index(*, deployments=(), replicasets=(), nodes=()):
    return {"deployment": [{"data": row} for row in deployments],
            "replicaset": [{"data": row} for row in replicasets],
            "node": [{"data": row} for row in nodes]}


@pytest.mark.parametrize("case", [
    "wrong_namespace", "reused_name", "missing_owner_uid", "missing_parent_uid",
    "missing_child_uid", "missing_parent", "multiple_controllers", "duplicate_parent",
    "noncontroller", "wrong_kind",
])
def test_adversarial_owner_reference_cannot_exempt_replicaset(case):
    managed = parent()
    child = workload("dns-rs", owners=[ref()])
    parents = [managed]
    if case == "wrong_namespace":
        parents = [parent(namespace="apps")]
    elif case == "reused_name":
        child["metadata"]["ownerReferences"][0]["uid"] = "prior-deployment-uid"
    elif case == "missing_owner_uid":
        child["metadata"]["ownerReferences"][0].pop("uid")
    elif case == "missing_parent_uid":
        managed["metadata"].pop("uid")
    elif case == "missing_child_uid":
        child["metadata"].pop("uid")
    elif case == "missing_parent":
        parents = []
    elif case == "multiple_controllers":
        child["metadata"]["ownerReferences"].append(ref(name="other", uid="other-uid"))
    elif case == "duplicate_parent":
        parents.append(copy.deepcopy(managed))
    elif case == "noncontroller":
        child["metadata"]["ownerReferences"][0]["controller"] = False
    elif case == "wrong_kind":
        child["metadata"]["ownerReferences"][0]["kind"] = "StatefulSet"
    assert managed_reason(child, "replicaset", index(deployments=parents)) is None, case


def test_valid_uid_chain_still_identifies_managed_pod():
    deployment = parent()
    replicaset = workload("dns-rs", uid="rs-uid", owners=[ref()])
    pod = workload("dns-pod", uid="pod-uid", owners=[ref("ReplicaSet", "dns-rs", "rs-uid")])
    reason = managed_reason(pod, "pod", index(deployments=[deployment], replicasets=[replicaset]))
    assert reason and "owned by managed ReplicaSet dns-rs" in reason
    assert "owned by managed Deployment dns" in reason


def test_mirror_pod_requires_exact_node_uid_and_well_formed_node_label():
    node = {"metadata": {"name": "node-a", "uid": "node-uid", "labels": {"cloud.google.com/gke-nodepool": "pool-a"}}}
    pod = workload("proxy", uid="pod-uid", owners=[ref("Node", "node-a", "node-uid")])
    pod["_static_pod_metadata"] = True
    assert "provider-managed node" in managed_reason(pod, "pod", index(nodes=[node]))
    pod["metadata"]["ownerReferences"][0]["uid"] = "old-node-uid"
    assert managed_reason(pod, "pod", index(nodes=[node])) is None
    pod["metadata"]["ownerReferences"][0]["uid"] = "node-uid"
    node["metadata"]["labels"]["cloud.google.com/gke-nodepool"] = []
    assert managed_reason(pod, "pod", index(nodes=[node])) is None


def test_marker_and_namespace_precision_preserves_known_managed_cases():
    assert marker_reason({"labels": {"addonmanager.kubernetes.io/mode": "Reconcile"}})
    assert marker_reason({"labels": {"kubernetes.io/bootstrapping": "rbac-defaults"}})
    assert marker_reason({"annotations": {"components.gke.io/component-name": "kube-dns"}})
    assert marker_reason({"labels": {"eks.amazonaws.com/component": "coredns"}})
    assert marker_reason({"labels": {"kubernetes.azure.com/managedby": "aks"}})
    assert managed_reason(workload("agent", namespace="amazon-guardduty"), "pod", {})
    assert managed_reason(workload("agent", namespace="aks-command"), "pod", {})
    assert managed_reason(workload("agent", namespace="gke-managed-system"), "pod", {})
    assert managed_reason({"metadata": metadata("system:controller:deployment", namespace=None)}, "clusterrole", {})
    assert managed_reason({"metadata": metadata("deployment-controller")}, "serviceaccount", {})


@pytest.mark.parametrize("labels, annotations", [
    ({"addonmanager.kubernetes.io/mode": []}, {}),
    ({"components.gke.io/not-an-owner-marker": "x"}, {}),
    ({1: "x", "components.gke.io/not-an-owner-marker": "x"}, {}),
    ({}, {"components.gke.io/component-name": []}),
    ({"eks.amazonaws.com/component": []}, {}),
])
def test_malformed_or_unrelated_labels_do_not_assert_managed_owner(labels, annotations):
    assert marker_reason({"labels": labels, "annotations": annotations}) is None
    item = workload("customer", namespace="apps", labels=labels)
    item["metadata"]["annotations"] = annotations
    assert managed_reason(item, "pod", {}) is None
    assert managed_reason(workload("customer", namespace="amazon-team"), "pod", {}) is None


def test_engine_keeps_false_positive_resource_actionable_and_valid_owner_exempt():
    deployment = parent()
    false_owner = workload("customer-rs", uid="rs-old", owners=[ref(uid="prior-deployment-uid")])
    real_owner = workload("managed-rs", uid="rs-real", owners=[ref()])
    ordinary = workload("customer-pod", uid="pod-customer", owners=[ref("ReplicaSet", "customer-rs", "rs-old")])
    managed = workload("managed-pod", uid="pod-managed", owners=[ref("ReplicaSet", "managed-rs", "rs-real")])
    missing_facts = {"metadata": metadata("unknown-pod", uid="pod-unknown", owners=[ref("ReplicaSet", "customer-rs", "rs-old")])}
    collections = [
        {"type": "deployment", "scope": "*", "status": "collected", "items": [deployment]},
        {"type": "replicaset", "scope": "*", "status": "collected", "items": [false_owner, real_owner]},
        {"type": "pod", "scope": "*", "status": "collected", "items": [ordinary, managed, missing_facts]},
    ]
    snapshot = make_snapshot("k8s", ["*"], collections, created_at="2026-10-13T00:00:00Z")
    report = evaluate_snapshot(snapshot, checks=[POD_CHECK], include_not_applicable=True)
    findings = {row["native_resource_id"].rsplit("/", 1)[-1]: row for row in report["findings"]
                if row["check_id"] == POD_CHECK and "native_resource_id" in row}
    assert findings["customer-pod"]["status"] == "FAIL"
    assert not findings["customer-pod"]["evidence"].get("provider_managed")
    assert findings["unknown-pod"]["status"] == "UNKNOWN"
    assert not findings["unknown-pod"]["evidence"].get("provider_managed")
    assert findings["managed-pod"]["status"] == "NOT_APPLICABLE"
    evidence = findings["managed-pod"]["evidence"]
    assert evidence["provider_managed"] is True
    assert evidence["underlying_status"] == "FAIL"
    assert "owned by managed ReplicaSet managed-rs" in evidence["managed_reason"]
