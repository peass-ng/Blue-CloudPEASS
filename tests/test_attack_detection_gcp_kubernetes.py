"""Public, synthetic matcher fixtures for GCP and Kubernetes audit records."""

from __future__ import annotations

from copy import deepcopy

from peaso.attack_detection import Rule, detect_gcp_events, detect_kubernetes_events, normalize_gcp_audit, normalize_kubernetes_audit


GCP_TEST_RULE = Rule(id="unit-gcp", title="Synthetic credential event", level="low",
                     description="Test only", technique_id="synthetic", product="gcp",
                     selection={"event.outcome": "success", "credential.effect_confirmed": True,
                                "event.name": "google.iam.admin.v1.CreateServiceAccountKey"})
K8S_TEST_RULE = Rule(id="unit-k8s", title="Synthetic RBAC event", level="low",
                     description="Test only", technique_id="synthetic", product="kubernetes",
                     selection={"event.outcome": "success", "rbac.non_system_service_account": True})


def gcp_key_event() -> dict:
    return {
        "logName": "projects/customer/logs/cloudaudit.googleapis.com%2Factivity",
        "insertId": "key-1",
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "iam.googleapis.com",
            "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
            "authenticationInfo": {"principalEmail": "operator@example.com"},
            "request": {"name": "projects/-/serviceAccounts/target@customer.iam.gserviceaccount.com"},
            "status": {"code": 0},
        },
    }


def k8s_binding_event() -> dict:
    return {
        "apiVersion": "audit.k8s.io/v1", "kind": "Event", "auditID": "audit-1",
        "stage": "ResponseComplete", "verb": "create",
        "user": {"username": "alice@example.com"},
        "objectRef": {"apiGroup": "rbac.authorization.k8s.io", "resource": "clusterrolebindings", "name": "workload-admin"},
        "responseStatus": {"code": 201, "status": "Success"},
        "responseObject": {
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
            "metadata": {"name": "workload-admin"},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [{"kind": "ServiceAccount", "name": "worker", "namespace": "app"}],
        },
    }


def test_gcp_requires_confirmed_success_and_target() -> None:
    good = gcp_key_event()
    matches = detect_gcp_events([good], [GCP_TEST_RULE])
    assert len(matches) == 1
    assert matches[0].target_id == "projects/-/serviceAccounts/target@customer.iam.gserviceaccount.com"
    returned = deepcopy(good)
    returned["protoPayload"].pop("status")
    returned["protoPayload"]["response"] = {"name": "projects/customer/serviceAccounts/target@customer.iam.gserviceaccount.com/keys/abc"}
    assert len(detect_gcp_events([returned], [GCP_TEST_RULE])) == 1
    negatives = []
    for edit in ("failure", "unknown", "data_log", "wrong_method", "wrong_target"):
        row = deepcopy(good)
        if edit == "failure": row["protoPayload"]["status"] = {"code": 7}
        if edit == "unknown": row["protoPayload"].pop("status")
        if edit == "data_log": row["logName"] = row["logName"].replace("activity", "data_access")
        if edit == "wrong_method": row["protoPayload"]["methodName"] = "google.iam.admin.v1.GetServiceAccountKey"
        if edit == "wrong_target": row["protoPayload"]["request"]["name"] = "invalid"
        negatives.append(row)
    assert detect_gcp_events(negatives, [GCP_TEST_RULE]) == []
    assert normalize_gcp_audit(good)["credential.effect_confirmed"] is True


def test_kubernetes_requires_completed_create_and_returned_privileged_binding() -> None:
    good = k8s_binding_event()
    matches = detect_kubernetes_events([good], [K8S_TEST_RULE])
    assert len(matches) == 1
    assert normalize_kubernetes_audit(good)["rbac.role"] == "cluster-admin"
    negatives = []
    for edit in ("failed", "request_stage", "metadata_only", "weaker_role", "system_sa", "mismatched_binding", "update", "dry_run"):
        row = deepcopy(good)
        if edit == "failed": row["responseStatus"] = {"code": 403, "status": "Failure"}
        if edit == "request_stage": row["stage"] = "RequestReceived"
        if edit == "metadata_only": row.pop("responseObject")
        if edit == "weaker_role": row["responseObject"]["roleRef"]["name"] = "view"
        if edit == "system_sa": row["responseObject"]["subjects"][0]["namespace"] = "kube-system"
        if edit == "mismatched_binding": row["responseObject"]["metadata"]["name"] = "other"
        if edit == "update": row["verb"] = "update"
        if edit == "dry_run": row["requestURI"] = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings?dryRun=All"
        negatives.append(row)
    assert detect_kubernetes_events(negatives, [K8S_TEST_RULE]) == []
    assert normalize_kubernetes_audit(good)["target.principal"] == "system:serviceaccount:app:worker"


def test_gke_cloud_logging_wrapper_requires_returned_object_and_excludes_dry_run() -> None:
    binding = k8s_binding_event()["responseObject"]
    wrapped = {
        "logName": "projects/customer/logs/cloudaudit.googleapis.com%2Factivity",
        "insertId": "gke-1", "timestamp": "2026-10-18T00:00:00Z",
        "resource": {"type": "k8s_cluster", "labels": {"cluster_name": "demo"}},
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "k8s.io", "methodName": "io.k8s.authorization.rbac.v1.clusterrolebindings.create",
            "authenticationInfo": {"principalEmail": "alice@example.com"},
            "status": {"code": 0}, "response": binding,
        },
    }
    matches = detect_kubernetes_events([wrapped], [K8S_TEST_RULE])
    assert len(matches) == 1
    assert matches[0].actor_id == "alice@example.com"
    assert matches[0].account_id == "projects/customer"
    negatives = []
    for edit in ("failure", "no_response", "wrong_resource", "dry_run"):
        row = deepcopy(wrapped)
        if edit == "failure": row["protoPayload"]["status"] = {"code": 7}
        if edit == "no_response": row["protoPayload"].pop("response")
        if edit == "wrong_resource": row["resource"]["type"] = "gke_cluster"
        if edit == "dry_run": row["labels"] = {"command.gke.io/dryRun": "All"}
        negatives.append(row)
    assert detect_kubernetes_events(negatives, [K8S_TEST_RULE]) == []
