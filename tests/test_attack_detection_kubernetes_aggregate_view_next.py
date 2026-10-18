"""Synthetic tests for accepted aggregate-to-view Secret read roles."""

import pytest
from peaso.attack_detection import Rule, detect_kubernetes_events, load_rules
from peaso.attack_detection.kubernetes_aggregate_view_next import normalize_aggregate_view_secret_read
from peaso.attack_detection.kubernetes import normalize_kubernetes_audit
from peaso.attack_detection.kubernetes_next import normalize_kubernetes_cluster_admin_grant
from peaso.attack_detection.kubernetes_pod_next import normalize_kubernetes_privileged_host_pod
from peaso.attack_detection.kubernetes_ephemeral_next import normalize_kubernetes_privileged_ephemeral_update
from peaso.attack_detection.kubernetes_runtime_socket_next import normalize_kubernetes_runtime_socket_pod


normalize = normalize_aggregate_view_secret_read
SELECTION = {"event.source": "kubernetes.audit", "event.name": "create",
             "event.outcome": "success", "rbac.aggregate_to_view_secret_read_role_accepted": True,
             "rbac.change_effect": "admitted_role_spec"}
RULE = Rule(id="164b656b-f269-4a4e-9d22-d6bb6e4364d8",
            title="Kubernetes ClusterRole accepted with Secret reads aggregated to view",
            level="high", description="Accepted ClusterRole specification; effective privilege and intent unproven.",
            technique_id="kubernetes-rbac-aggregate-to-view-secret-read", product="kubernetes",
            selection=SELECTION)


def native():
    return {
        "apiVersion": "audit.k8s.io/v1", "kind": "Event", "stage": "ResponseComplete", "verb": "create",
        "auditID": "synthetic-id", "stageTimestamp": "2026-10-18T17:30:00Z",
        "cluster_id": "projects/example/locations/us-central1-a/clusters/lab",
        "user": {"username": "operator@example.test"},
        "requestURI": "/apis/rbac.authorization.k8s.io/v1/clusterroles",
        "objectRef": {"apiGroup": "rbac.authorization.k8s.io", "resource": "clusterroles", "name": "aggregate-secret-reader"},
        "responseStatus": {"code": 201, "status": "Success"},
        "responseObject": {
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
            "metadata": {"name": "aggregate-secret-reader", "uid": "synthetic-uid",
                         "labels": {"rbac.authorization.k8s.io/aggregate-to-view": "true"}},
            "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}],
        },
    }


def gke():
    row = native()
    return {
        "logName": "projects/example/logs/cloudaudit.googleapis.com%2Factivity",
        "resource": {"type": "k8s_cluster", "labels": {"project_id": "example", "location": "us-central1-a", "cluster_name": "lab"}},
        "insertId": row["auditID"], "timestamp": row["stageTimestamp"],
        "protoPayload": {"@type": "type.googleapis.com/google.cloud.audit.AuditLog", "serviceName": "k8s.io",
                         "methodName": "io.k8s.authorization.rbac.v1.clusterroles.create", "status": {"code": 0},
                         "authenticationInfo": {"principalEmail": "operator@example.test"},
                         "request": {"metadata": {"name": "aggregate-secret-reader"}},
                         "response": row["responseObject"]},
    }


@pytest.mark.parametrize("factory", [native, gke])
def test_exact_accepted_role_matches_sigma_but_claims_no_effective_access(factory):
    event = normalize(factory())
    assert event and event["rbac.change_effect"] == "admitted_role_spec"
    assert all(event.get(k) == v for k, v in SELECTION.items())
    assert [hit.rule_id for hit in detect_kubernetes_events([factory()], [RULE])] == [RULE.id]
    assert set(event) == {"cloud.provider", "event.source", "event.name", "event.outcome",
                          "event.id", "event.time", "account.id", "actor.id", "target.id",
                          "rbac.aggregate_to_view_secret_read_role_accepted", "rbac.change_effect"}
    assert "effective_access" not in event


@pytest.mark.parametrize("mutate", [
    lambda x: x["responseObject"]["metadata"]["labels"].update({"rbac.authorization.k8s.io/aggregate-to-view": "false"}),
    lambda x: x["responseObject"]["rules"][0].update(resources=["configmaps"]),
    lambda x: x["responseObject"]["rules"][0].update(apiGroups=["apps"]),
    lambda x: x["responseObject"]["rules"][0].update(verbs=["create"]),
    lambda x: x["responseObject"]["rules"][0].update(resourceNames=["one-secret"]),
    lambda x: x["responseObject"].update(rules="{malformed-json"),
    lambda x: x["responseObject"].update(kind="Role"),
    lambda x: x["responseObject"]["metadata"].update(uid=""),
    lambda x: x["objectRef"].update(name="other"),
    lambda x: x.update(requestURI="/apis/rbac.authorization.k8s.io/v1/clusterroles?%64ryRun=All"),
    lambda x: x.update(requestURI="http://["),
    lambda x: x["responseStatus"].update(code=403, status="Failure"),
    lambda x: x.update(stage="RequestReceived"),
    lambda x: x.update(verb="patch"),
    lambda x: x["user"].update(username="system:kube-controller-manager"),
])
def test_benign_or_ambiguous_native_excluded(mutate):
    row = native()
    mutate(row)
    assert normalize(row) is None


@pytest.mark.parametrize("mutate", [
    lambda x: x["protoPayload"].update(request="{malformed-json"),
    lambda x: x["protoPayload"].update(response="{malformed-json"),
    lambda x: x["protoPayload"]["request"].update(dryRun="All"),
    lambda x: x.update(labels={"command.gke.io/dryRun": "All"}),
    lambda x: x["protoPayload"].update(status={"code": 7}),
    lambda x: x["protoPayload"].update(methodName="io.k8s.authorization.rbac.v1.clusterroles.patch"),
    lambda x: x["resource"]["labels"].update(project_id="other"),
    lambda x: x["protoPayload"]["request"]["metadata"].update(name="other"),
    lambda x: x.update(logName="projects/example/logs/cloudaudit.googleapis.com%2Fdata_access"),
])
def test_gke_denied_malformed_dryrun_or_scope_mismatch_excluded(mutate):
    row = gke()
    mutate(row)
    assert normalize(row) is None


def test_clusterrole_event_does_not_overlap_current_kubernetes_rules():
    row = native()
    assert normalize(row)
    for existing in (normalize_kubernetes_audit, normalize_kubernetes_cluster_admin_grant,
                     normalize_kubernetes_privileged_host_pod,
                     normalize_kubernetes_privileged_ephemeral_update,
                     normalize_kubernetes_runtime_socket_pod):
        assert existing(row) is None, existing.__name__


def test_published_rule_matches_gke_audit_without_other_matches():
    rules = load_rules(product="kubernetes")
    assert RULE.id in {item.id for item in rules}
    assert [hit.rule_id for hit in detect_kubernetes_events([gke()], rules)] == [RULE.id]
