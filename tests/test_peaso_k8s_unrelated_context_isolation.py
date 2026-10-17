"""Unrelated securityContext availability does not govern independent declarations."""
import pytest

from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


def _pod(*, context=None, denied=False):
    container = {"name": "kube-apiserver", "resources": {"limits": {"cpu": "1"}},
                 "_component_config": {"component": "kube-apiserver", "flags_complete": True,
                                       "flags": {"enable-admission-plugins": "DenyServiceExternalIPs"},
                                       "version": "v1.30.0"}}
    if context is not None:
        container["securityContext"] = context
    if denied:
        container["_coverage"] = {"securityContext": {"status": "denied"}}
    return {"metadata": {"name": "api", "namespace": "kube-system", "labels": {"component": "kube-apiserver"}},
            "spec": {"containers": [container]}}


def _status(cid, pod):
    snap = make_snapshot("k8s", ["*"], [{"type": "pod", "scope": "*", "status": "collected", "items": [pod]}],
                         created_at="2026-10-17T00:00:00Z")
    rows = [row for row in evaluate_snapshot(snap, checks=[cid])["findings"] if row["check_id"] == cid]
    assert len(rows) == 1
    return rows[0]["status"]


@pytest.mark.parametrize("present", [False, True])
def test_cpu_limit_unrelated_denied_context_still_passes(present):
    pod = _pod(context={"runAsNonRoot": True} if present else None, denied=True)
    assert _status("k8s.ports.pod.cpu_limit", pod) == "PASS"


@pytest.mark.parametrize("present", [False, True])
def test_component_plugin_unrelated_denied_context_still_passes(present):
    pod = _pod(context={"runAsNonRoot": True} if present else None, denied=True)
    assert _status("k8s.gap.apiserver.deny_service_external_ips", pod) == "PASS"


def test_relevant_nonroot_context_denial_remains_unknown():
    assert _status("k8s.ports.pod.declared_nonroot", _pod(context={"runAsNonRoot": True}, denied=True)) == "UNKNOWN"


def test_relevant_readonly_context_denial_remains_unknown():
    assert _status("k8s.pod.read_only_root", _pod(context={"readOnlyRootFilesystem": True}, denied=True)) == "UNKNOWN"


def test_independent_cpu_and_plugin_valid_without_unrelated_denial():
    pod = _pod(context={"runAsNonRoot": True})
    assert _status("k8s.ports.pod.cpu_limit", pod) == "PASS"
    assert _status("k8s.gap.apiserver.deny_service_external_ips", pod) == "PASS"


@pytest.mark.parametrize("cid,fields,expected", [
    ("k8s.ports.pod.host_network", {"hostNetwork": False}, "PASS"),
    ("k8s.ports.pod.host_namespaces", {"hostPID": True}, "FAIL"),
    ("k8s.ports.pod.explicit_serviceaccount", {"serviceAccountName": "app"}, "PASS"),
    ("k8s.ports.pod.pod_runtime_default_seccomp", {"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}}}, "PASS"),
])
def test_pod_level_declaration_independent_of_unreadable_container_inventory(cid, fields, expected):
    pod = {"metadata": {"name": "workload", "namespace": "apps"},
           "spec": {**fields, "_coverage": {"containers": {"status": "denied"}}}}
    assert _status(cid, pod) == expected
