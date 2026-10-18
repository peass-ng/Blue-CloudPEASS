"""Synthetic Kubernetes RequestResponse and GKE Cloud Audit binding evidence."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_kubernetes_events
from peaso.attack_detection.kubernetes_next import normalize_kubernetes_cluster_admin_grant


def _native() -> dict:
    return {
        "apiVersion": "audit.k8s.io/v1", "kind": "Event", "stage": "ResponseComplete",
        "verb": "create", "auditID": "audit-123", "stageTimestamp": "2026-10-18T10:00:00Z",
        "cluster_id": "cluster-one", "user": {"username": "alice@example.com"},
        "requestURI": "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
        "objectRef": {"apiGroup": "rbac.authorization.k8s.io", "resource": "clusterrolebindings",
                      "name": "alice-admin"},
        "responseStatus": {"code": 201, "status": "Success"},
        "responseObject": {
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
            "metadata": {"name": "alice-admin", "uid": "binding-uid"},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                        "name": "cluster-admin"},
            "subjects": [{"kind": "User", "apiGroup": "rbac.authorization.k8s.io",
                          "name": "alice@example.com"}],
        },
    }


def _gke() -> dict:
    record = _native()
    return {
        "logName": "projects/project-one/logs/cloudaudit.googleapis.com%2Factivity",
        "resource": {"type": "k8s_cluster", "labels": {"location": "us-central1",
                                                     "cluster_name": "cluster-one"}},
        "insertId": "gke-audit-123", "timestamp": "2026-10-18T10:00:00Z",
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "k8s.io",
            "methodName": "io.k8s.authorization.rbac.v1.clusterrolebindings.create",
            "authenticationInfo": {"principalEmail": "alice@example.com"},
            "status": {"code": 0}, "response": record["responseObject"],
        },
    }


def test_completed_self_user_cluster_admin_binding_is_observed() -> None:
    event = normalize_kubernetes_cluster_admin_grant(_native())
    assert event is not None
    assert event["event.id"] == "audit-123"
    assert event["actor.id"] == "alice@example.com"
    assert event["target.id"] == "alice-admin"
    assert event["rbac.subject_kind"] == "User"
    assert event["rbac.self_user_grant"] is True
    assert event["rbac.cluster_admin_binding_created"] is True
    assert event["rbac.change_effect"] == "created_binding"


def test_completed_broad_group_grant_is_observed_without_claiming_actor_is_subject() -> None:
    record = _native()
    record["responseObject"]["subjects"] = [
        {"kind": "Group", "apiGroup": "rbac.authorization.k8s.io",
         "name": "system:authenticated"}]
    event = normalize_kubernetes_cluster_admin_grant(record)
    assert event is not None
    assert event["rbac.broad_group_grant"] is True
    assert event["rbac.self_user_grant"] is False
    assert event["target.principal"] == "system:authenticated"


def test_sigma_selection_matches_self_and_broad_group_separately() -> None:
    rules = [
        Rule(id="self", title="Self grant", level="high", description="Self grant",
             technique_id="k8s-self", product="kubernetes",
             selection={"event.source": "kubernetes.audit", "event.name": "create",
                        "event.outcome": "success", "rbac.cluster_admin_binding_created": True,
                        "rbac.self_user_grant": True, "rbac.role": "cluster-admin"}),
        Rule(id="broad", title="Broad grant", level="critical", description="Broad grant",
             technique_id="k8s-broad", product="kubernetes",
             selection={"event.source": "kubernetes.audit", "event.name": "create",
                        "event.outcome": "success", "rbac.cluster_admin_binding_created": True,
                        "rbac.broad_group_grant": True, "rbac.role": "cluster-admin"}),
    ]
    assert [item.rule_id for item in detect_kubernetes_events([_native()], rules)] == ["self"]
    broad = _native()
    broad["responseObject"]["subjects"] = [{"kind": "Group", "apiGroup": "rbac.authorization.k8s.io",
                                               "name": "system:authenticated"}]
    assert [item.rule_id for item in detect_kubernetes_events([broad], rules)] == ["broad"]


def test_service_account_actor_can_create_broad_group_grant() -> None:
    record = _native()
    record["user"]["username"] = "system:serviceaccount:build:deployer"
    record["responseObject"]["subjects"] = [
        {"kind": "Group", "apiGroup": "rbac.authorization.k8s.io",
         "name": "system:unauthenticated"}]
    event = normalize_kubernetes_cluster_admin_grant(record)
    assert event is not None
    assert event["actor.id"] == "system:serviceaccount:build:deployer"
    assert event["rbac.broad_group_grant"] is True
    assert event["rbac.self_user_grant"] is False


@pytest.mark.parametrize("actor", [
    "system:serviceaccount:build:deployer", "system:serviceaccount:build:",
    "system:serviceaccount::deployer", "system:node:worker-1", "system:anonymous",
    "system:serviceaccount:build:deployer:extra",
])
def test_system_actor_does_not_match_self_user_subject(actor: str) -> None:
    record = _native()
    record["user"]["username"] = actor
    record["responseObject"]["subjects"][0]["name"] = actor
    assert normalize_kubernetes_cluster_admin_grant(record) is None


@pytest.mark.parametrize("actor", [
    "system:serviceaccount:build:", "system:serviceaccount::deployer",
    "system:serviceaccount:build:deployer:extra", "system:serviceaccount:Bad:deployer",
    "system:node:worker-1", "system:anonymous",
])
def test_other_or_malformed_system_actor_does_not_match_broad_group(actor: str) -> None:
    record = _native()
    record["user"]["username"] = actor
    record["responseObject"]["subjects"] = [
        {"kind": "Group", "apiGroup": "rbac.authorization.k8s.io",
         "name": "system:authenticated"}]
    assert normalize_kubernetes_cluster_admin_grant(record) is None


def test_gke_wrapper_requires_response_object_and_identifies_cluster() -> None:
    event = normalize_kubernetes_cluster_admin_grant(_gke())
    assert event is not None
    assert event["account.id"] == "projects/project-one/locations/us-central1/clusters/cluster-one"
    assert event["event.id"] == "gke-audit-123"
    assert event["rbac.self_user_grant"] is True


def test_gke_wrapper_service_account_actor_can_create_broad_group_grant() -> None:
    record = _gke()
    record["protoPayload"]["authenticationInfo"]["principalEmail"] = "system:serviceaccount:build:deployer"
    record["protoPayload"]["response"]["subjects"] = [
        {"kind": "Group", "apiGroup": "rbac.authorization.k8s.io",
         "name": "system:authenticated"}]
    event = normalize_kubernetes_cluster_admin_grant(record)
    assert event is not None
    assert event["actor.id"] == "system:serviceaccount:build:deployer"
    assert event["rbac.broad_group_grant"] is True


@pytest.mark.parametrize("change", [
    "request_stage", "update", "patch", "denied", "dry_run", "missing_response",
    "missing_uid", "missing_subjects", "other_user", "ordinary_group",
    "service_account", "system_actor", "wrong_role", "wrong_role_kind",
    "namespaced_role_binding", "namespaced_cluster_binding", "wrong_ref_name",
    "wrong_response_kind", "missing_event_id", "missing_time", "missing_cluster",
    "missing_actor", "missing_api_version", "missing_subject_api_group",
])
def test_native_request_without_proven_high_risk_creation_does_not_match(change: str) -> None:
    record = _native()
    response = record["responseObject"]
    if change == "request_stage": record["stage"] = "RequestReceived"
    if change == "update": record["verb"] = "update"; record["responseStatus"]["code"] = 200
    if change == "patch": record["verb"] = "patch"; record["responseStatus"]["code"] = 200
    if change == "denied": record["responseStatus"] = {"code": 403, "status": "Failure"}
    if change == "dry_run": record["requestURI"] += "?dryRun=All"
    if change == "missing_response": record.pop("responseObject")
    if change == "missing_uid": response["metadata"].pop("uid")
    if change == "missing_subjects": response.pop("subjects")
    if change == "other_user": response["subjects"][0]["name"] = "bob@example.com"
    if change == "ordinary_group": response["subjects"][0] = {"kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "developers"}
    if change == "service_account": response["subjects"][0]["kind"] = "ServiceAccount"
    if change == "system_actor": record["user"]["username"] = "system:serviceaccount:default:controller"
    if change == "wrong_role": response["roleRef"]["name"] = "view"
    if change == "wrong_role_kind": response["roleRef"]["kind"] = "Role"
    if change == "namespaced_role_binding": record["objectRef"]["resource"] = "rolebindings"
    if change == "namespaced_cluster_binding": response["metadata"]["namespace"] = "default"
    if change == "wrong_ref_name": record["objectRef"]["name"] = "other-binding"
    if change == "wrong_response_kind": response["kind"] = "RoleBinding"
    if change == "missing_event_id": record.pop("auditID")
    if change == "missing_time": record.pop("stageTimestamp")
    if change == "missing_cluster": record.pop("cluster_id")
    if change == "missing_actor": record["user"] = {}
    if change == "missing_api_version": response.pop("apiVersion")
    if change == "missing_subject_api_group": response["subjects"][0].pop("apiGroup")
    assert normalize_kubernetes_cluster_admin_grant(record) is None


@pytest.mark.parametrize("change", [
    "denied", "boolean_status", "dry_run_label", "dry_run_request", "missing_response", "missing_uid",
    "wrong_method", "wrong_service", "wrong_log", "wrong_resource", "missing_cluster_label",
    "other_actor", "missing_insert_id", "missing_time",
])
def test_gke_wrapper_without_proven_creation_does_not_match(change: str) -> None:
    record = _gke()
    payload = record["protoPayload"]
    if change == "denied": payload["status"]["code"] = 7
    if change == "boolean_status": payload["status"]["code"] = False
    if change == "dry_run_label": record["labels"] = {"command.gke.io/dryRun": "All"}
    if change == "dry_run_request": payload["request"] = {"dryRun": "All"}
    if change == "missing_response": payload.pop("response")
    if change == "missing_uid": payload["response"]["metadata"].pop("uid")
    if change == "wrong_method": payload["methodName"] = "io.k8s.authorization.rbac.v1.clusterrolebindings.update"
    if change == "wrong_service": payload["serviceName"] = "container.googleapis.com"
    if change == "wrong_log": record["logName"] = "projects/project-one/logs/cloudaudit.googleapis.com%2Fdata_access"
    if change == "wrong_resource": record["resource"]["type"] = "gce_instance"
    if change == "missing_cluster_label": record["resource"]["labels"].pop("cluster_name")
    if change == "other_actor": payload["authenticationInfo"]["principalEmail"] = "bob@example.com"
    if change == "missing_insert_id": record.pop("insertId")
    if change == "missing_time": record.pop("timestamp")
    assert normalize_kubernetes_cluster_admin_grant(record) is None
