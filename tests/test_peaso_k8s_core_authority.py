"""Registered native K8s predicates retain selected fact authority."""
import pytest

from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


def status(cid, kind, item):
    snapshot = make_snapshot("k8s", ["*"], [{"type": kind, "scope": "*", "status": "collected", "items": [item]}], created_at="2026-10-17T00:00:00Z")
    rows = [r for r in evaluate_snapshot(snapshot, checks=[cid])["findings"] if r["check_id"] == cid]
    assert len(rows) == 1
    return rows[0]["status"]


@pytest.mark.parametrize("cid,kind,item,expected", [
    ("k8s.rbac.role_no_wildcards", "role", {"rules": [{"verbs": ["get"], "resources": ["pods"], "_coverage": {"resources": {"status": "denied"}}}]}, "UNKNOWN"),
    ("k8s.rbac.role_no_wildcards", "role", {"rules": [{"verbs": ["get"], "resources": ["pods"], "_coverage": {"verbs": {"status": "denied"}}}]}, "UNKNOWN"),
    ("k8s.rbac.role_no_wildcards", "role", {"rules": [{"verbs": ["*"], "resources": ["pods"]}, {"verbs": None}]}, "FAIL"),
    ("k8s.rbac.role_no_wildcards", "role", {"rules": [{"verbs": ["get"], "resources": ["pods"]}]}, "PASS"),
    ("k8s.rbac.review_namespaced_subjects", "rolebinding", {"roleRef": {"kind": "Role", "name": "view"}, "subjects": [{"kind": "User", "name": "alice", "_coverage": {"kind": {"status": "denied"}}}]}, "UNKNOWN"),
    ("k8s.rbac.review_namespaced_subjects", "rolebinding", {"roleRef": {"kind": "Role", "name": "view"}, "_coverage": {"roleRef": {"status": "denied"}}, "subjects": []}, "UNKNOWN"),
    ("k8s.rbac.review_namespaced_subjects", "rolebinding", {"roleRef": {"kind": "Role", "name": "view"}, "subjects": [{"kind": "Group", "name": "system:authenticated"}, None]}, "FAIL"),
    ("k8s.rbac.review_namespaced_subjects", "rolebinding", {"roleRef": {"kind": "Role", "name": "view"}, "subjects": []}, "PASS"),
    ("k8s.pod.no_privileged_containers", "pod", {"spec": {"containers": [{"name": "app"}], "_coverage": {"initContainers": {"status": "denied"}}}}, "UNKNOWN"),
    ("k8s.pod.no_privileged_containers", "pod", {"spec": {"containers": [{"name": "app", "securityContext": {"privileged": False, "_coverage": {"privileged": {"status": "denied"}}}}]}}, "UNKNOWN"),
    ("k8s.pod.no_privileged_containers", "pod", {"spec": {"containers": [{"name": "bad", "securityContext": {"privileged": True}}, {"name": "peer", "securityContext": None}]}}, "FAIL"),
    ("k8s.pod.no_privileged_containers", "pod", {"spec": {"containers": [{"name": "app"}]}}, "PASS"),
    ("k8s.pod.no_host_namespaces", "pod", {"spec": {"hostPID": True, "hostIPC": False, "_coverage": {"hostIPC": {"status": "denied"}}}}, "FAIL"),
    ("k8s.pod.no_host_namespaces", "pod", {"spec": {"hostPID": False, "hostIPC": False, "_coverage": {"hostIPC": {"status": "denied"}}}}, "UNKNOWN"),
    ("k8s.pod.no_host_namespaces", "pod", {"spec": {}}, "PASS"),
])
def test_selected_fact_authority(cid, kind, item, expected):
    assert status(cid, kind, item) == expected
