"""Synthetic native audit fixtures for cache-only runtime socket proposal."""
from __future__ import annotations

from copy import deepcopy
import pytest

from peaso.attack_detection.kubernetes_runtime_socket_next import (
    normalize_kubernetes_runtime_socket_pod as normalize,
)
from peaso.attack_detection.rules import Rule, _detect_events


def event() -> dict:
    return {
        "apiVersion": "audit.k8s.io/v1", "kind": "Event", "stage": "ResponseComplete",
        "verb": "create", "auditID": "audit-runtime-1", "stageTimestamp": "2026-10-18T10:00:00Z",
        "cluster_id": "customer-gke", "user": {"username": "alice@example.com"},
        "requestURI": "/api/v1/namespaces/app/pods",
        "objectRef": {"apiGroup": "", "resource": "pods", "namespace": "app"},
        "responseStatus": {"code": 201, "status": "Success"},
        "responseObject": {"apiVersion": "v1", "kind": "Pod",
                           "metadata": {"name": "review", "namespace": "app", "uid": "pod-1"},
                           "spec": {"containers": [{"name": "debug", "securityContext": {"privileged": True},
                                                   "volumeMounts": [{"name": "runtime", "mountPath": "/run/containerd/containerd.sock", "readOnly": False}]}],
                                    "volumes": [{"name": "runtime", "hostPath": {"path": "/run/containerd/containerd.sock", "type": "Socket"}}]}},
    }


def gke_event() -> dict:
    native = event()
    return {
        "logName": "projects/customer/logs/cloudaudit.googleapis.com%2Factivity",
        "resource": {"type": "k8s_cluster", "labels": {"location": "us-central1-a", "cluster_name": "cluster-one"}},
        "insertId": "gke-pod-create-1", "timestamp": "2026-10-18T10:00:00Z",
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog", "serviceName": "k8s.io",
            "methodName": "io.k8s.core.v1.pods.create", "status": {"code": 0},
            "authenticationInfo": {"principalEmail": "alice@example.com"},
            "response": native["responseObject"],
        },
    }


def test_gke_admin_activity_wrapper_matches_exact_accepted_spec() -> None:
    found = normalize(gke_event())
    assert found is not None
    assert found["event.id"] == "gke-pod-create-1"
    assert found["target.host_socket_path"] == "/run/containerd/containerd.sock"


@pytest.mark.parametrize("change", ["denied", "wrong_method", "wrong_log", "dry_run", "unprivileged"])
def test_gke_wrapper_rejects_incomplete_or_benign_create(change: str) -> None:
    row = gke_event()
    if change == "denied": row["protoPayload"]["status"]["code"] = 7
    if change == "wrong_method": row["protoPayload"]["methodName"] = "io.k8s.core.v1.pods.update"
    if change == "wrong_log": row["logName"] = "projects/customer/logs/cloudaudit.googleapis.com%2Fdata_access"
    if change == "dry_run": row["labels"] = {"command.gke.io/dryRun": "All"}
    if change == "unprivileged": row["protoPayload"]["response"]["spec"]["containers"][0]["securityContext"]["privileged"] = False
    assert normalize(row) is None


def test_exact_accepted_runtime_socket_spec() -> None:
    found = normalize(event())
    assert found is not None
    assert found["target.host_socket_path"] == "/run/containerd/containerd.sock"
    assert found["pod.change_effect"] == "admitted_spec"
    assert found["pod.privileged_runtime_socket_spec_accepted"] is True
    assert "started" not in found and "escape" not in found


def test_flat_matcher_uses_only_observed_accepted_spec() -> None:
    rule = Rule(id="runtime-socket", title="Runtime socket Pod", level="high",
                description="Accepted risky Pod spec", technique_id="k8s-runtime-socket",
                product="kubernetes", selection={
                    "event.source": "kubernetes.audit", "event.name": "create",
                    "event.outcome": "success",
                    "pod.privileged_runtime_socket_spec_accepted": True,
                    "pod.change_effect": "admitted_spec",
                })
    normalized = normalize(gke_event())
    assert normalized is not None
    hits = _detect_events([normalized], [rule], lambda item: item, "kubernetes")
    assert [hit.rule_id for hit in hits] == ["runtime-socket"]
    benign = gke_event()
    benign["protoPayload"]["response"]["spec"]["containers"][0]["securityContext"]["privileged"] = False
    assert normalize(benign) is None


@pytest.mark.parametrize("change", [
    "denied", "dry_run", "not_complete", "wrong_resource", "wrong_namespace", "system_namespace",
    "system_actor", "missing_uid", "missing_response", "not_privileged", "read_only_mount",
    "other_volume", "other_socket", "non_socket_type", "subpath", "windows", "wrong_uri", "gke_wrapper",
    "list_socket_path", "list_mount_name", "malformed_uri",
])
def test_benign_or_incomplete_evidence_does_not_match(change: str) -> None:
    row = event()
    spec = row["responseObject"]["spec"]
    container = spec["containers"][0]
    volume = spec["volumes"][0]
    if change == "denied": row["responseStatus"] = {"code": 403, "status": "Failure"}
    if change == "dry_run": row["requestURI"] += "?dryRun=All"
    if change == "not_complete": row["stage"] = "RequestReceived"
    if change == "wrong_resource": row["objectRef"]["resource"] = "deployments"
    if change == "wrong_namespace": row["objectRef"]["namespace"] = "other"
    if change == "system_namespace":
        row["responseObject"]["metadata"]["namespace"] = row["objectRef"]["namespace"] = "kube-system"
        row["requestURI"] = "/api/v1/namespaces/kube-system/pods"
    if change == "system_actor": row["user"]["username"] = "system:serviceaccount:app:controller"
    if change == "missing_uid": row["responseObject"]["metadata"].pop("uid")
    if change == "missing_response": row.pop("responseObject")
    if change == "not_privileged": container["securityContext"]["privileged"] = False
    if change == "read_only_mount": container["volumeMounts"][0]["readOnly"] = True
    if change == "other_volume": container["volumeMounts"][0]["name"] = "other"
    if change == "other_socket": volume["hostPath"]["path"] = "/tmp/other.sock"
    if change == "list_socket_path": volume["hostPath"]["path"] = ["/run/docker.sock"]
    if change == "list_mount_name": container["volumeMounts"][0]["name"] = ["runtime"]
    if change == "non_socket_type": volume["hostPath"]["type"] = "File"
    if change == "subpath": container["volumeMounts"][0]["subPath"] = "socket"
    if change == "windows": spec["os"] = {"name": "windows"}
    if change == "wrong_uri": row["requestURI"] = "/api/v1/namespaces/app/pods/other"
    if change == "malformed_uri": row["requestURI"] = "http://["
    if change == "gke_wrapper": row["protoPayload"] = {}
    assert normalize(row) is None
