"""Synthetic conformance tests for the DaemonSet audit detector."""

from __future__ import annotations

import copy
import pytest
from peaso.attack_detection import Rule, detect_kubernetes_events, load_rules
from peaso.attack_detection.kubernetes_daemonset_next import normalize_kubernetes_privileged_daemonset

from peaso.attack_detection.kubernetes import normalize_kubernetes_audit
from peaso.attack_detection.kubernetes_next import normalize_kubernetes_cluster_admin_grant
from peaso.attack_detection.kubernetes_pod_next import normalize_kubernetes_privileged_host_pod
from peaso.attack_detection.kubernetes_ephemeral_next import normalize_kubernetes_privileged_ephemeral_update
from peaso.attack_detection.kubernetes_runtime_socket_next import normalize_kubernetes_runtime_socket_pod


normalize = normalize_kubernetes_privileged_daemonset
SELECTION = {"event.source": "kubernetes.audit", "event.name": "create",
             "event.outcome": "success", "daemonset.privileged_host_root_spec_accepted": True,
             "daemonset.change_effect": "admitted_spec"}
RULE = Rule(id="2af2c7cc-c3cb-4a6c-b51d-20dad79e0f16",
            title="Kubernetes DaemonSet accepted with privileged host-root template",
            level="high", description="Accepted template; scheduling, host access and intent remain unproven.",
            technique_id="kubernetes-daemonset-privileged-host-root-template", product="kubernetes",
            selection=SELECTION)


def native_event():
    return {
        "apiVersion": "audit.k8s.io/v1", "kind": "Event", "stage": "ResponseComplete",
        "verb": "create", "auditID": "synthetic-id", "stageTimestamp": "2026-10-18T17:29:06Z",
        "cluster_id": "projects/example/locations/us-central1-a/clusters/test",
        "user": {"username": "operator@example.test"},
        "requestURI": "/apis/apps/v1/namespaces/lab/daemonsets",
        "objectRef": {"apiGroup": "apps", "resource": "daemonsets", "namespace": "lab", "name": "risky-spec"},
        "responseStatus": {"code": 201, "status": "Success"},
        "responseObject": {
            "apiVersion": "apps/v1", "kind": "DaemonSet",
            "metadata": {"name": "risky-spec", "namespace": "lab", "uid": "synthetic-uid"},
            "spec": {
                "selector": {"matchLabels": {"app": "risky-spec"}},
                "template": {
                    "metadata": {"labels": {"app": "risky-spec"}},
                    "spec": {
                        "hostPID": True,
                        "volumes": [{"name": "host", "hostPath": {"path": "/", "type": "Directory"}}],
                        "containers": [{"name": "agent", "securityContext": {"privileged": True},
                                        "volumeMounts": [{"name": "host", "mountPath": "/host", "readOnly": False}]}],
                    },
                },
            },
        },
    }


def gke_event():
    event = native_event()
    response = event["responseObject"]
    return {
        "logName": "projects/example/logs/cloudaudit.googleapis.com%2Factivity",
        "resource": {"type": "k8s_cluster", "labels": {"project_id": "example", "location": "us-central1-a", "cluster_name": "test"}},
        "insertId": "synthetic-id", "timestamp": event["stageTimestamp"],
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog", "serviceName": "k8s.io",
            "methodName": "io.k8s.apps.v1.daemonsets.create", "status": {"code": 0},
            "authenticationInfo": {"principalEmail": "operator@example.test"},
            "request": {"metadata": {"name": "risky-spec", "namespace": "lab"}},
            "response": response,
        },
    }


@pytest.mark.parametrize("factory", [native_event, gke_event])
def test_admitted_spec_matches_flat_sigma_selection_only(factory):
    normalized = normalize(factory())
    assert normalized is not None
    assert normalized["daemonset.change_effect"] == "admitted_spec"
    assert normalized["target.id"] == "lab/risky-spec"
    assert all(normalized.get(field) == expected for field, expected in SELECTION.items())
    assert [hit.rule_id for hit in detect_kubernetes_events([factory()], [RULE])] == [RULE.id]
    assert "execution" not in normalized and "host_access" not in normalized


@pytest.mark.parametrize("mutate", [
    lambda x: x["responseObject"]["spec"]["template"]["spec"].update(hostPID=False),
    lambda x: x["responseObject"]["spec"]["template"]["spec"]["containers"][0]["securityContext"].update(privileged=False),
    lambda x: x["responseObject"]["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][0].update(readOnly=True),
    lambda x: x["responseObject"]["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][0].update(name="other"),
    lambda x: x["responseObject"]["spec"]["template"]["spec"].update(os={"name": "windows"}),
    lambda x: x.update(verb="patch"),
    lambda x: x.update(stage="RequestReceived"),
    lambda x: x["responseStatus"].update(code=403, status="Failure"),
    lambda x: x["objectRef"].update(namespace="other"),
    lambda x: x.update(requestURI="/apis/apps/v1/namespaces/lab/daemonsets?%64ryRun=All"),
    lambda x: x.pop("requestURI"),
    lambda x: x.update(requestURI="http://["),
    lambda x: x["responseObject"]["spec"]["selector"]["matchLabels"].update(app="other"),
    lambda x: x["responseObject"]["spec"]["selector"].update(matchExpressions=[{"key": "app", "operator": "Exists"}]),
    lambda x: x["responseObject"]["spec"]["template"]["metadata"].update(namespace="other"),
    lambda x: x["responseObject"]["metadata"].update(uid=""),
])
def test_native_ambiguous_or_benign_is_excluded(mutate):
    event = native_event()
    mutate(event)
    assert normalize(event) is None


@pytest.mark.parametrize("mutate", [
    lambda x: x["protoPayload"].update(request="{malformed-json"),
    lambda x: x["protoPayload"].pop("request"),
    lambda x: x["protoPayload"].update(response="{malformed-json"),
    lambda x: x["protoPayload"]["request"].update(dryRun="All"),
    lambda x: x.update(labels={"command.gke.io/dryRun": "All"}),
    lambda x: x.update(labels="{malformed-json"),
    lambda x: x["protoPayload"]["request"]["metadata"].update(name="other"),
    lambda x: x["protoPayload"]["request"]["metadata"].update(namespace="other"),
    lambda x: x["protoPayload"].update(status={"code": 7}),
    lambda x: x["protoPayload"].update(methodName="io.k8s.apps.v1.daemonsets.patch"),
    lambda x: x["resource"]["labels"].update(project_id="foreign"),
    lambda x: x["resource"]["labels"].update(location="../../foreign"),
    lambda x: x["resource"]["labels"].update(cluster_name="invalid/name"),
    lambda x: x["resource"].update(type="gce_instance"),
    lambda x: x.update(logName="projects/example/logs/cloudaudit.googleapis.com%2Fdata_access"),
])
def test_gke_malformed_dry_run_or_foreign_scope_is_excluded(mutate):
    event = gke_event()
    mutate(event)
    assert normalize(event) is None


def test_no_overlap_with_existing_kubernetes_normalizers():
    record = native_event()
    assert normalize(record)
    for existing in (normalize_kubernetes_audit, normalize_kubernetes_cluster_admin_grant,
                     normalize_kubernetes_privileged_host_pod,
                     normalize_kubernetes_privileged_ephemeral_update,
                     normalize_kubernetes_runtime_socket_pod):
        assert existing(copy.deepcopy(record)) is None, existing.__name__


def test_synthetic_benign_daemonset_same_method_is_excluded():
    event = gke_event()
    event["protoPayload"]["response"]["metadata"]["name"] = "ordinary-spec"
    event["protoPayload"]["request"]["metadata"]["name"] = "ordinary-spec"
    event["protoPayload"]["response"]["spec"]["template"]["spec"]["hostPID"] = False
    assert normalize(event) is None


def test_published_rule_matches_gke_audit_without_other_matches():
    rules = load_rules(product="kubernetes")
    assert RULE.id in {item.id for item in rules}
    assert [hit.rule_id for hit in detect_kubernetes_events([gke_event()], rules)] == [RULE.id]
