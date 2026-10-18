"""Synthetic RequestResponse Pod audits; no cluster or Pod is created."""

from __future__ import annotations

import pytest

from peaso.attack_detection import Rule, detect_kubernetes_events
from peaso.attack_detection.kubernetes_pod_next import normalize_kubernetes_privileged_host_pod


def _pod_record() -> dict:
    return {
        "apiVersion": "audit.k8s.io/v1", "kind": "Event", "stage": "ResponseComplete",
        "verb": "create", "auditID": "audit-123", "stageTimestamp": "2026-10-18T10:00:00Z",
        "cluster_id": "cluster-one", "user": {"username": "alice@example.com"},
        "requestURI": "/api/v1/namespaces/lab/pods",
        "objectRef": {"apiGroup": "", "resource": "pods", "namespace": "lab", "name": "host-review"},
        "responseStatus": {"code": 201, "status": "Success"},
        "responseObject": {
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "host-review", "namespace": "lab", "uid": "pod-uid"},
            "spec": {
                "hostPID": True,
                "volumes": [{"name": "host-volume", "hostPath": {"path": "/", "type": "Directory"}}],
                "containers": [{"name": "review", "image": "example.invalid/review:1",
                                "securityContext": {"privileged": True},
                                "volumeMounts": [{"name": "host-volume", "mountPath": "/host"}]}],
            },
        },
    }


def _gke_record() -> dict:
    native = _pod_record()
    return {
        "logName": "projects/project-one/logs/cloudaudit.googleapis.com%2Factivity",
        "resource": {"type": "k8s_cluster", "labels": {"location": "us-central1",
                                                     "cluster_name": "cluster-one"}},
        "insertId": "gke-audit-123", "timestamp": "2026-10-18T10:00:00Z",
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "k8s.io", "methodName": "io.k8s.core.v1.pods.create",
            "authenticationInfo": {"principalEmail": "alice@example.com"},
            "status": {"code": 0}, "response": native["responseObject"],
        },
    }


def test_completed_privileged_pod_with_writable_host_root_and_hostpid_is_observed() -> None:
    event = normalize_kubernetes_privileged_host_pod(_pod_record())
    assert event is not None
    assert event["event.id"] == "audit-123"
    assert event["actor.id"] == "alice@example.com"
    assert event["target.id"] == "lab/host-review"
    assert event["target.container"] == "review"
    assert event["target.host_mount_path"] == "/host"
    assert event["pod.host_pid"] is True
    assert event["pod.privileged"] is True
    assert event["pod.writable_host_root_mount"] is True
    assert event["pod.change_effect"] == "admitted_spec"


def test_kubernetes_detection_pipeline_rejects_read_only_host_mount() -> None:
    rule = Rule(id="privileged-host-pod", title="Privileged host Pod", level="high",
                description="Review", technique_id="k8s-host-pod", product="kubernetes",
                selection={"event.source": "kubernetes.audit", "event.name": "create",
                           "event.outcome": "success", "pod.host_pid": True,
                           "pod.privileged": True, "pod.writable_host_root_mount": True,
                           "pod.privileged_host_pod_created": True})
    assert [hit.rule_id for hit in detect_kubernetes_events([_pod_record()], [rule])] == [rule.id]
    read_only = _pod_record()
    read_only["responseObject"]["spec"]["containers"][0]["volumeMounts"][0]["readOnly"] = True
    assert detect_kubernetes_events([read_only], [rule]) == []


def test_explicit_read_write_and_gke_response_object_are_supported() -> None:
    record = _gke_record()
    record["protoPayload"]["response"]["spec"]["containers"][0]["volumeMounts"][0]["readOnly"] = False
    event = normalize_kubernetes_privileged_host_pod(record)
    assert event is not None
    assert event["event.id"] == "gke-audit-123"
    assert event["account.id"] == "projects/project-one/locations/us-central1/clusters/cluster-one"


@pytest.mark.parametrize("change", [
    "request_received", "update", "denied", "dry_run", "missing_response",
    "missing_uid", "missing_spec", "missing_hostpid", "hostpid_false",
    "unprivileged", "privileged_other_container", "hostpath_other_path",
    "hostpath_other_volume", "hostpath_file_type", "read_only_mount",
    "subpath", "subpath_expression", "init_container_only",
    "wrong_resource", "wrong_response_kind", "wrong_name", "wrong_namespace",
    "system_namespace", "windows_pod", "missing_actor", "missing_event_id",
    "missing_time", "missing_cluster", "malformed_mount",
])
def test_unproven_or_benign_native_pod_does_not_match(change: str) -> None:
    record = _pod_record()
    response = record["responseObject"]
    spec = response["spec"]
    container = spec["containers"][0]
    mount = container["volumeMounts"][0]
    if change == "request_received": record["stage"] = "RequestReceived"
    if change == "update": record["verb"] = "update"; record["responseStatus"]["code"] = 200
    if change == "denied": record["responseStatus"] = {"code": 403, "status": "Failure"}
    if change == "dry_run": record["requestURI"] += "?dryRun=All"
    if change == "missing_response": record.pop("responseObject")
    if change == "missing_uid": response["metadata"].pop("uid")
    if change == "missing_spec": response.pop("spec")
    if change == "missing_hostpid": spec.pop("hostPID")
    if change == "hostpid_false": spec["hostPID"] = False
    if change == "unprivileged": container["securityContext"]["privileged"] = False
    if change == "privileged_other_container":
        container["securityContext"]["privileged"] = False
        spec["containers"].append({"name": "other", "securityContext": {"privileged": True}})
    if change == "hostpath_other_path": spec["volumes"][0]["hostPath"]["path"] = "/var/log"
    if change == "hostpath_other_volume": mount["name"] = "other-volume"
    if change == "hostpath_file_type": spec["volumes"][0]["hostPath"]["type"] = "File"
    if change == "read_only_mount": mount["readOnly"] = True
    if change == "subpath": mount["subPath"] = "etc"
    if change == "subpath_expression": mount["subPathExpr"] = "$(POD_NAME)"
    if change == "init_container_only": spec["initContainers"] = spec.pop("containers"); spec["containers"] = []
    if change == "wrong_resource": record["objectRef"]["resource"] = "deployments"
    if change == "wrong_response_kind": response["kind"] = "Deployment"
    if change == "wrong_name": record["objectRef"]["name"] = "other-pod"
    if change == "wrong_namespace": record["objectRef"]["namespace"] = "other"
    if change == "system_namespace": response["metadata"]["namespace"] = "kube-system"; record["objectRef"]["namespace"] = "kube-system"
    if change == "windows_pod": spec["os"] = {"name": "windows"}
    if change == "missing_actor": record["user"] = {}
    if change == "missing_event_id": record.pop("auditID")
    if change == "missing_time": record.pop("stageTimestamp")
    if change == "missing_cluster": record.pop("cluster_id")
    if change == "malformed_mount": container["volumeMounts"] = ["host-volume"]
    assert normalize_kubernetes_privileged_host_pod(record) is None


@pytest.mark.parametrize("change", [
    "denied", "boolean_status", "dry_run_label", "dry_run_request",
    "missing_response", "missing_uid", "wrong_method", "wrong_service",
    "wrong_log", "wrong_resource", "missing_cluster_label", "missing_insert_id",
])
def test_unproven_gke_pod_does_not_match(change: str) -> None:
    record = _gke_record()
    payload = record["protoPayload"]
    if change == "denied": payload["status"]["code"] = 7
    if change == "boolean_status": payload["status"]["code"] = False
    if change == "dry_run_label": record["labels"] = {"command.gke.io/dryRun": "All"}
    if change == "dry_run_request": payload["request"] = {"dryRun": "All"}
    if change == "missing_response": payload.pop("response")
    if change == "missing_uid": payload["response"]["metadata"].pop("uid")
    if change == "wrong_method": payload["methodName"] = "io.k8s.core.v1.pods.update"
    if change == "wrong_service": payload["serviceName"] = "container.googleapis.com"
    if change == "wrong_log": record["logName"] = "projects/project-one/logs/cloudaudit.googleapis.com%2Fdata_access"
    if change == "wrong_resource": record["resource"]["type"] = "gce_instance"
    if change == "missing_cluster_label": record["resource"]["labels"].pop("cluster_name")
    if change == "missing_insert_id": record.pop("insertId")
    assert normalize_kubernetes_privileged_host_pod(record) is None
