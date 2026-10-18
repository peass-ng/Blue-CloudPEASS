"""Completed RBAC update/patch audit events prove returned state, not a new grant."""
from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_kubernetes_events, normalize_kubernetes_audit


RULE = Rule(id="reviewed-update", title="Observed cluster-admin binding", level="low",
            description="Returned binding has cluster-admin role", technique_id="synthetic",
            product="kubernetes", selection={"rbac.observed_cluster_admin_binding": True,
                                             "event.outcome": "success"})


def binding_event(resource="clusterrolebindings", verb="update"):
    namespaced = resource == "rolebindings"
    result = {
        "apiVersion": "audit.k8s.io/v1", "kind": "Event", "stage": "ResponseComplete",
        "verb": verb, "auditID": "audit-1", "stageTimestamp": "2026-10-18T08:00:00Z",
        "user": {"username": "system:serviceaccount:app:worker" if namespaced else "alice@example.test"},
        "objectRef": {"apiGroup": "rbac.authorization.k8s.io", "resource": resource,
                      "name": "workload-admin"},
        "responseStatus": {"code": 200, "status": "Success"},
        "responseObject": {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding" if namespaced else "ClusterRoleBinding",
            "metadata": {"name": "workload-admin"},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                        "name": "cluster-admin"},
            "subjects": [{"kind": "ServiceAccount", "name": "worker", "namespace": "app"}],
        },
    }
    if namespaced:
        result["objectRef"]["namespace"] = "app"
        result["responseObject"]["metadata"]["namespace"] = "app"
    return result


@pytest.mark.parametrize("resource", ["clusterrolebindings", "rolebindings"])
@pytest.mark.parametrize("verb", ["update", "patch"])
def test_update_and_patch_match_only_observed_returned_binding(resource, verb):
    record = binding_event(resource, verb)
    normalized = normalize_kubernetes_audit(record)
    assert normalized["event.name"] == verb
    assert normalized["rbac.observed_cluster_admin_binding"] is True
    assert normalized["rbac.change_effect"] == "observed_state"
    assert normalized["rbac.role"] == "cluster-admin"
    assert normalized["rbac.self_namespace_service_account"] is (resource == "rolebindings")
    match = detect_kubernetes_events([record], [RULE])
    assert len(match) == 1
    assert match[0].event_id == "audit-1"


@pytest.mark.parametrize("edit", ["started", "failed", "created", "missing_response",
                                  "weaker_role", "wrong_name", "missing_ref_name",
                                  "system_sa", "dry_run", "encoded_dry_run", "other_namespace"])
def test_update_rejects_unproven_or_inconsistent_state(edit):
    row = binding_event("rolebindings")
    if edit == "started": row["stage"] = "RequestReceived"
    if edit == "failed": row["responseStatus"] = {"code": 403, "status": "Failure"}
    if edit == "created": row["responseStatus"]["code"] = 201
    if edit == "missing_response": row.pop("responseObject")
    if edit == "weaker_role": row["responseObject"]["roleRef"]["name"] = "view"
    if edit == "wrong_name": row["responseObject"]["metadata"]["name"] = "another"
    if edit == "missing_ref_name": row["objectRef"].pop("name")
    if edit == "system_sa": row["responseObject"]["subjects"][0]["namespace"] = "kube-system"
    if edit == "dry_run": row["requestURI"] = "/apis/rbac.authorization.k8s.io/v1/namespaces/app/rolebindings/workload-admin?dryRun=All"
    if edit == "encoded_dry_run": row["requestURI"] = "/apis/rbac.authorization.k8s.io/v1/namespaces/app/rolebindings/workload-admin?%64ryRun=All"
    if edit == "other_namespace": row["objectRef"]["namespace"] = "other"
    assert normalize_kubernetes_audit(row) is None
    assert detect_kubernetes_events([row], [RULE]) == []


def test_cluster_scoped_binding_rejects_namespace_in_response():
    row = binding_event()
    row["responseObject"]["metadata"]["namespace"] = "app"
    assert normalize_kubernetes_audit(row) is None


@pytest.mark.parametrize("verb", ["update", "patch"])
def test_gke_wrapped_update_requires_response_and_rejects_dry_run(verb):
    original = binding_event(verb=verb)
    row = {
        "logName": "projects/customer/logs/cloudaudit.googleapis.com%2Factivity",
        "insertId": "gke-event-1", "timestamp": "2026-10-18T08:00:00Z",
        "resource": {"type": "k8s_cluster", "labels": {"cluster_name": "demo", "location": "us-central1"}},
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "k8s.io",
            "methodName": f"io.k8s.authorization.rbac.v1.clusterrolebindings.{verb}",
            "authenticationInfo": {"principalEmail": "alice@example.test"},
            "status": {"code": 0}, "response": original["responseObject"],
        },
    }
    normal = normalize_kubernetes_audit(row)
    assert normal["event.name"] == verb
    assert normal["rbac.change_effect"] == "observed_state"
    assert len(detect_kubernetes_events([row], [RULE])) == 1
    denied = deepcopy(row)
    denied["protoPayload"]["status"]["code"] = 7
    assert normalize_kubernetes_audit(denied) is None
    no_response = deepcopy(row)
    no_response["protoPayload"].pop("response")
    assert normalize_kubernetes_audit(no_response) is None
    dry_run = deepcopy(row)
    dry_run["labels"] = {"command.gke.io/dryRun": "All"}
    assert normalize_kubernetes_audit(dry_run) is None
