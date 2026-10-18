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
K8S_SELF_ROLEBINDING_RULE = Rule(
    id="unit-k8s-self", title="Synthetic self RoleBinding event", level="low",
    description="Test only", technique_id="synthetic", product="kubernetes",
    selection={"event.outcome": "success", "rbac.self_namespace_service_account": True,
               "rbac.role": "cluster-admin"},
)


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
    assert normalize_gcp_audit(good)["account.id"] == "customer"
    returned = deepcopy(good)
    returned["protoPayload"].pop("status")
    returned["protoPayload"]["response"] = {"name": "projects/customer/serviceAccounts/target@customer.iam.gserviceaccount.com/keys/abc"}
    assert len(detect_gcp_events([returned], [GCP_TEST_RULE])) == 1
    negatives = []
    for edit in ("failure", "unknown", "data_log", "wrong_method", "wrong_target",
                 "foreign_target", "foreign_returned_key", "foreign_resource", "malformed_log"):
        row = deepcopy(good)
        if edit == "failure": row["protoPayload"]["status"] = {"code": 7}
        if edit == "unknown": row["protoPayload"].pop("status")
        if edit == "data_log": row["logName"] = row["logName"].replace("activity", "data_access")
        if edit == "wrong_method": row["protoPayload"]["methodName"] = "google.iam.admin.v1.GetServiceAccountKey"
        if edit == "wrong_target": row["protoPayload"]["request"]["name"] = "invalid"
        if edit == "foreign_target": row["protoPayload"]["request"]["name"] = "projects/-/serviceAccounts/target@foreign.iam.gserviceaccount.com"
        if edit == "foreign_returned_key": row["protoPayload"]["response"] = {"name": "projects/foreign/serviceAccounts/target@foreign.iam.gserviceaccount.com/keys/abc"}
        if edit == "foreign_resource": row["resource"] = {"type": "service_account", "labels": {"project_id": "foreign"}}
        if edit == "malformed_log": row["logName"] = "organizations/123/logs/cloudaudit.googleapis.com%2Factivity"
        negatives.append(row)
    assert detect_gcp_events(negatives, [GCP_TEST_RULE]) == []
    assert normalize_gcp_audit(good)["credential.effect_confirmed"] is True


def test_malformed_gcp_method_does_not_abort_following_valid_record() -> None:
    good = gcp_key_event()
    malformed = deepcopy(good)
    malformed["protoPayload"]["methodName"] = []
    assert [hit.event_id for hit in detect_gcp_events([malformed, good], [GCP_TEST_RULE])] == ["key-1"]


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


def test_cluster_admin_binding_reports_each_distinct_service_account() -> None:
    row = k8s_binding_event()
    row["responseObject"]["subjects"].extend([
        {"kind": "ServiceAccount", "name": "other", "namespace": "app"},
        {"kind": "ServiceAccount", "name": "worker", "namespace": "app"},
        {"kind": "ServiceAccount", "name": "system", "namespace": "kube-system"},
    ])
    matches = detect_kubernetes_events([row], [K8S_TEST_RULE])
    assert {item.target_id for item in matches} == {
        "system:serviceaccount:app:worker", "system:serviceaccount:app:other"}
    assert len(matches) == 2
    assert {item.event_id for item in matches} == {"audit-1"}
    assert {item.evidence["correlation"]["binding_name"] for item in matches} == {"workload-admin"}
    assert {item.evidence["correlation"]["service_account"] for item in matches} == {
        "system:serviceaccount:app:worker", "system:serviceaccount:app:other"}

    wrapped = {"logName": "projects/customer/logs/cloudaudit.googleapis.com%2Factivity",
               "insertId": "gke-multi", "timestamp": "2026-10-18T00:00:00Z",
               "resource": {"type": "k8s_cluster", "labels": {"cluster_name": "demo"}},
               "protoPayload": {"@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                                "serviceName": "k8s.io",
                                "methodName": "io.k8s.authorization.rbac.v1.clusterrolebindings.create",
                                "authenticationInfo": {"principalEmail": "alice@example.com"},
                                "status": {"code": 0}, "response": row["responseObject"]}}
    assert {item.target_id for item in detect_kubernetes_events([wrapped], [K8S_TEST_RULE])} == {
        "system:serviceaccount:app:worker", "system:serviceaccount:app:other"}


def test_malformed_kubernetes_verb_and_uri_do_not_abort_following_valid_record() -> None:
    good = k8s_binding_event()
    malformed_verb = deepcopy(good)
    malformed_verb["verb"] = []
    malformed_uri = deepcopy(good)
    malformed_uri["requestURI"] = "http://["
    assert [hit.event_id for hit in detect_kubernetes_events(
        [malformed_verb, malformed_uri, good], [K8S_TEST_RULE]
    )] == ["audit-1"]


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


def k8s_self_rolebinding_event() -> dict:
    record = k8s_binding_event()
    record["user"]["username"] = "system:serviceaccount:app:worker"
    record["objectRef"]["resource"] = "rolebindings"
    record["objectRef"]["namespace"] = "app"
    record["responseObject"]["kind"] = "RoleBinding"
    record["responseObject"]["metadata"]["namespace"] = "app"
    return record


def test_namespace_self_rolebinding_requires_same_actor_namespace_and_confirmed_create() -> None:
    good = k8s_self_rolebinding_event()
    match = detect_kubernetes_events([good], [K8S_SELF_ROLEBINDING_RULE])
    assert len(match) == 1
    assert match[0].actor_id == "system:serviceaccount:app:worker"
    assert normalize_kubernetes_audit(good)["target.principal"] == "system:serviceaccount:app:worker"
    assert normalize_kubernetes_audit(good)["rbac.binding_kind"] == "RoleBinding"
    negatives = []
    for edit in ("denied", "dry_run", "request_only", "missing_object", "other_actor", "other_subject",
                 "other_namespace", "missing_namespace", "wrong_role", "wrong_kind", "system_namespace"):
        row = deepcopy(good)
        if edit == "denied": row["responseStatus"] = {"code": 403, "status": "Failure"}
        if edit == "dry_run": row["requestURI"] = "/apis/rbac.authorization.k8s.io/v1/namespaces/app/rolebindings?dryRun=All"
        if edit == "request_only": row["stage"] = "RequestReceived"
        if edit == "missing_object": row.pop("responseObject")
        if edit == "other_actor": row["user"]["username"] = "system:serviceaccount:app:other"
        if edit == "other_subject": row["responseObject"]["subjects"][0]["name"] = "other"
        if edit == "other_namespace": row["objectRef"]["namespace"] = "other"
        if edit == "missing_namespace": row["responseObject"]["metadata"].pop("namespace")
        if edit == "wrong_role": row["responseObject"]["roleRef"]["name"] = "view"
        if edit == "wrong_kind": row["responseObject"]["kind"] = "ClusterRoleBinding"
        if edit == "system_namespace":
            row["objectRef"]["namespace"] = "kube-system"
            row["responseObject"]["metadata"]["namespace"] = "kube-system"
            row["responseObject"]["subjects"][0]["namespace"] = "kube-system"
            row["user"]["username"] = "system:serviceaccount:kube-system:worker"
        negatives.append(row)
    assert detect_kubernetes_events(negatives, [K8S_SELF_ROLEBINDING_RULE]) == []


def test_cluster_wide_service_account_rule_excludes_namespaced_rolebinding() -> None:
    cluster = k8s_binding_event()
    namespaced = k8s_self_rolebinding_event()
    assert normalize_kubernetes_audit(cluster)["rbac.binding_kind"] == "ClusterRoleBinding"
    rule = Rule(
        id="cluster-wide-only", title="Cluster-wide service account grant", level="high",
        description="Exact binding kind", technique_id="synthetic", product="kubernetes",
        selection={"event.name": "create", "event.outcome": "success",
                   "rbac.role": "cluster-admin", "rbac.binding_kind": "ClusterRoleBinding",
                   "rbac.non_system_service_account": True},
    )
    assert [hit.rule_id for hit in detect_kubernetes_events([cluster], [rule])] == [rule.id]
    assert detect_kubernetes_events([namespaced], [rule]) == []


def test_gke_wrapper_namespace_self_rolebinding_requires_returned_object_and_no_dry_run() -> None:
    binding = k8s_self_rolebinding_event()["responseObject"]
    wrapped = {
        "logName": "projects/customer/logs/cloudaudit.googleapis.com%2Factivity",
        "insertId": "gke-rolebinding-1", "timestamp": "2026-10-18T00:00:00Z",
        "resource": {"type": "k8s_cluster", "labels": {"cluster_name": "demo"}},
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog", "serviceName": "k8s.io",
            "methodName": "io.k8s.authorization.rbac.v1.rolebindings.create",
            "authenticationInfo": {"principalEmail": "system:serviceaccount:app:worker"},
            "status": {"code": 0}, "response": binding,
        },
    }
    assert len(detect_kubernetes_events([wrapped], [K8S_SELF_ROLEBINDING_RULE])) == 1
    negatives = []
    for edit in ("denied", "dry_run", "missing_response", "other_actor", "other_namespace"):
        row = deepcopy(wrapped)
        if edit == "denied": row["protoPayload"]["status"] = {"code": 7}
        if edit == "dry_run": row["labels"] = {"command.gke.io/dryRun": "All"}
        if edit == "missing_response": row["protoPayload"].pop("response")
        if edit == "other_actor": row["protoPayload"]["authenticationInfo"]["principalEmail"] = "other@example.com"
        if edit == "other_namespace": row["protoPayload"]["response"]["subjects"][0]["namespace"] = "other"
        negatives.append(row)
    assert detect_kubernetes_events(negatives, [K8S_SELF_ROLEBINDING_RULE]) == []
