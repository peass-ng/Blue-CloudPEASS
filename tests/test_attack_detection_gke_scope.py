"""GKE wrapper project labels must agree with the audited log's project."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection.gke_scope import project_scope
from peaso.attack_detection.kubernetes import normalize_kubernetes_audit
from peaso.attack_detection.kubernetes_ephemeral_next import normalize_kubernetes_privileged_ephemeral_update
from peaso.attack_detection.kubernetes_next import normalize_kubernetes_cluster_admin_grant
from peaso.attack_detection.kubernetes_pod_next import normalize_kubernetes_privileged_host_pod
from tests.test_attack_detection_gcp_kubernetes import k8s_binding_event
from tests.test_attack_detection_kubernetes_ephemeral_next import _gke as ephemeral_gke
from tests.test_attack_detection_kubernetes_next import _gke as binding_gke
from tests.test_attack_detection_kubernetes_pod_next import _gke_record as pod_gke


def _base_binding_gke() -> dict:
    return {
        "logName": "projects/customer/logs/cloudaudit.googleapis.com%2Factivity",
        "insertId": "gke-binding-1", "timestamp": "2026-10-18T10:00:00Z",
        "resource": {"type": "k8s_cluster", "labels": {"cluster_name": "demo"}},
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "k8s.io",
            "methodName": "io.k8s.authorization.rbac.v1.clusterrolebindings.create",
            "authenticationInfo": {"principalEmail": "alice@example.com"},
            "status": {"code": 0}, "response": k8s_binding_event()["responseObject"],
        },
    }


WRAPPERS = (
    (normalize_kubernetes_audit, _base_binding_gke),
    (normalize_kubernetes_cluster_admin_grant, binding_gke),
    (normalize_kubernetes_privileged_host_pod, pod_gke),
    (normalize_kubernetes_privileged_ephemeral_update, ephemeral_gke),
)


@pytest.mark.parametrize("normalize,fixture", WRAPPERS)
def test_gke_wrappers_accept_matching_project_label(normalize, fixture):
    row = fixture()
    project = row["logName"].split("/", 2)[1]
    row["resource"]["labels"]["project_id"] = project
    assert normalize(row) is not None


@pytest.mark.parametrize("normalize,fixture", WRAPPERS)
@pytest.mark.parametrize("bad", ["other-project", None, 123, ["customer"]])
def test_gke_wrappers_reject_conflicting_or_malformed_project_label(normalize, fixture, bad):
    row = deepcopy(fixture())
    row["resource"]["labels"]["project_id"] = bad
    assert normalize(row) is None


@pytest.mark.parametrize("log_name", [
    "projects/customer/other/logs/cloudaudit.googleapis.com%2Factivity",
    "organizations/123/logs/cloudaudit.googleapis.com%2Factivity",
    "projects//logs/cloudaudit.googleapis.com%2Factivity",
    "projects/customer/logs/cloudaudit.googleapis.com%2Fdata_access",
])
def test_gke_log_name_must_be_an_exact_project_admin_activity_path(log_name):
    assert project_scope(log_name, {"project_id": "customer"}) is None
