"""Synthetic privileged ephemeral-container update audits; no cluster mutations."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection.kubernetes_ephemeral_next import normalize_kubernetes_privileged_ephemeral_update


def _pod() -> dict:
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "app-pod", "namespace": "app", "uid": "pod-uid"},
        "spec": {
            "containers": [{"name": "app", "image": "example.invalid/app:1"}],
            "ephemeralContainers": [{"name": "debugger", "image": "example.invalid/debug:1",
                                     "targetContainerName": "app",
                                     "securityContext": {"privileged": True}}],
        },
    }


def _event() -> dict:
    pod = _pod()
    return {
        "apiVersion": "audit.k8s.io/v1", "kind": "Event", "stage": "ResponseComplete",
        "verb": "update", "auditID": "audit-ephemeral-1", "stageTimestamp": "2026-10-18T10:00:00Z",
        "cluster_id": "cluster-one", "user": {"username": "alice@example.com"},
        "requestURI": "/api/v1/namespaces/app/pods/app-pod/ephemeralcontainers",
        "objectRef": {"apiGroup": "", "resource": "pods", "subresource": "ephemeralcontainers",
                      "namespace": "app", "name": "app-pod"},
        "responseStatus": {"code": 200, "status": "Success"},
        "requestObject": deepcopy(pod), "responseObject": pod,
    }


def _gke() -> dict:
    event = _event()
    return {
        "logName": "projects/customer/logs/cloudaudit.googleapis.com%2Factivity",
        "resource": {"type": "k8s_cluster", "labels": {"location": "us-central1",
                                                     "cluster_name": "cluster-one"}},
        "insertId": "gke-ephemeral-1", "timestamp": "2026-10-18T10:00:00Z",
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "k8s.io", "methodName": "io.k8s.core.v1.pods.ephemeralcontainers.update",
            "authenticationInfo": {"principalEmail": "alice@example.com"},
            "status": {"code": 0}, "request": event["requestObject"],
            "response": event["responseObject"],
        },
    }


def test_completed_privileged_ephemeral_update_has_exact_accepted_state_evidence() -> None:
    event = normalize_kubernetes_privileged_ephemeral_update(_event())
    assert event is not None
    assert event["event.id"] == "audit-ephemeral-1"
    assert event["event.name"] == "update"
    assert event["target.id"] == "app/app-pod"
    assert event["target.ephemeral_container"] == "debugger"
    assert event["pod.privileged_ephemeral_update_observed"] is True
    assert event["pod.change_effect"] == "accepted_state"


def test_gke_wrapper_and_non_system_service_account_actor_match() -> None:
    wrapped = _gke()
    wrapped["protoPayload"]["authenticationInfo"]["principalEmail"] = "system:serviceaccount:app:debug-runner"
    event = normalize_kubernetes_privileged_ephemeral_update(wrapped)
    assert event is not None
    assert event["account.id"] == "projects/customer/locations/us-central1/clusters/cluster-one"
    assert event["actor.id"] == "system:serviceaccount:app:debug-runner"


@pytest.mark.parametrize("change", [
    "request_stage", "patch", "wrong_subresource", "denied", "dry_run",
    "missing_request", "missing_response", "request_no_privilege", "response_no_privilege",
    "other_target", "response_no_ephemeral", "duplicate_name", "read_only_metadata",
    "other_namespace", "system_namespace", "system_actor", "kube_system_sa_actor",
    "missing_uid", "uid_mismatch", "name_mismatch", "namespace_mismatch",
    "missing_time", "missing_event_id", "missing_cluster", "windows_pod",
])
def test_ambiguous_or_unprivileged_native_update_does_not_match(change: str) -> None:
    event = _event()
    request = event["requestObject"]
    response = event["responseObject"]
    if change == "request_stage": event["stage"] = "RequestReceived"
    if change == "patch": event["verb"] = "patch"
    if change == "wrong_subresource": event["objectRef"]["subresource"] = "status"
    if change == "denied": event["responseStatus"] = {"code": 403, "status": "Failure"}
    if change == "dry_run": event["requestURI"] += "?dryRun=All"
    if change == "missing_request": event.pop("requestObject")
    if change == "missing_response": event.pop("responseObject")
    if change == "request_no_privilege": request["spec"]["ephemeralContainers"][0]["securityContext"]["privileged"] = False
    if change == "response_no_privilege": response["spec"]["ephemeralContainers"][0]["securityContext"]["privileged"] = False
    if change == "other_target": request["spec"]["ephemeralContainers"][0]["targetContainerName"] = "other"
    if change == "response_no_ephemeral": response["spec"]["ephemeralContainers"] = []
    if change == "duplicate_name": response["spec"]["ephemeralContainers"].append(deepcopy(response["spec"]["ephemeralContainers"][0]))
    if change == "read_only_metadata": event["responseStatus"]["code"] = 201
    if change == "other_namespace": event["objectRef"]["namespace"] = "other"
    if change == "system_namespace":
        request["metadata"]["namespace"] = response["metadata"]["namespace"] = event["objectRef"]["namespace"] = "kube-system"
    if change == "system_actor": event["user"]["username"] = "system:node:worker-1"
    if change == "kube_system_sa_actor": event["user"]["username"] = "system:serviceaccount:kube-system:debug-runner"
    if change == "missing_uid": response["metadata"].pop("uid")
    if change == "uid_mismatch": request["metadata"]["uid"] = "other-uid"
    if change == "name_mismatch": request["metadata"]["name"] = "other-pod"
    if change == "namespace_mismatch": request["metadata"]["namespace"] = "other"
    if change == "missing_time": event.pop("stageTimestamp")
    if change == "missing_event_id": event.pop("auditID")
    if change == "missing_cluster": event.pop("cluster_id")
    if change == "windows_pod": response["spec"]["os"] = {"name": "windows"}
    assert normalize_kubernetes_privileged_ephemeral_update(event) is None


@pytest.mark.parametrize("change", [
    "denied", "boolean_status", "wrong_method", "dry_run_label", "dry_run_request",
    "missing_request", "missing_response", "wrong_log", "wrong_resource",
    "missing_cluster_label", "missing_insert_id", "missing_actor",
])
def test_ambiguous_gke_wrapper_does_not_match(change: str) -> None:
    wrapped = _gke()
    payload = wrapped["protoPayload"]
    if change == "denied": payload["status"]["code"] = 7
    if change == "boolean_status": payload["status"]["code"] = False
    if change == "wrong_method": payload["methodName"] = "io.k8s.core.v1.pods.ephemeralcontainers.patch"
    if change == "dry_run_label": wrapped["labels"] = {"command.gke.io/dryRun": "All"}
    if change == "dry_run_request": payload["request"]["dryRun"] = "All"
    if change == "missing_request": payload.pop("request")
    if change == "missing_response": payload.pop("response")
    if change == "wrong_log": wrapped["logName"] = "projects/customer/logs/cloudaudit.googleapis.com%2Fdata_access"
    if change == "wrong_resource": wrapped["resource"]["type"] = "gce_instance"
    if change == "missing_cluster_label": wrapped["resource"]["labels"].pop("location")
    if change == "missing_insert_id": wrapped.pop("insertId")
    if change == "missing_actor": payload["authenticationInfo"] = {}
    assert normalize_kubernetes_privileged_ephemeral_update(wrapped) is None
