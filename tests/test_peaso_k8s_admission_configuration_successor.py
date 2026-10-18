"""Registered admission declarations respect field-level collection authority."""
import pytest

from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

IDS = {
    "deny": ("k8s.gap.apiserver.deny_service_external_ips", "DenyServiceExternalIPs"),
    "rate": ("k8s.gap.apiserver.event_rate_limit", "EventRateLimit"),
}


def _pod(plugin="DenyServiceExternalIPs", *, component="kube-apiserver", version="v1.30.0"):
    return {
        "metadata": {"name": "api", "namespace": "kube-system", "labels": {"component": "kube-apiserver"}},
        "spec": {"containers": [{"name": "kube-apiserver", "_component_config": {
            "component": component, "version": version, "flags_complete": True,
            "flags": {"enable-admission-plugins": "NodeRestriction," + plugin},
        }}]},
    }


def _status(cid, pod):
    snap = make_snapshot("k8s", ["*"], [
        {"type": "pod", "scope": "*", "status": "collected", "items": [pod]}
    ], created_at="2026-10-17T00:00:00Z")
    rows = [row for row in evaluate_snapshot(snap, checks=[cid])["findings"] if row["check_id"] == cid]
    assert len(rows) == 1
    return rows[0]["status"]


@pytest.mark.parametrize("cid,plugin", IDS.values())
def test_native_declared_plugin_and_known_absence(cid, plugin):
    assert _status(cid, _pod(plugin)) == "PASS"
    assert _status(cid, _pod("NodeRestriction")) == "FAIL"


@pytest.mark.parametrize("cid,plugin", IDS.values())
def test_denied_component_identity_cannot_admit_positive(cid, plugin):
    pod = _pod(plugin)
    pod["spec"]["containers"][0]["_component_config"]["_coverage"] = {
        "component": {"status": "denied"}}
    assert _status(cid, pod) == "UNKNOWN"


def test_denied_component_identity_cannot_admit_negative():
    pod = _pod("NodeRestriction")
    pod["spec"]["containers"][0]["_component_config"]["_coverage"] = {
        "component": {"status": "denied"}}
    assert _status(IDS["deny"][0], pod) == "UNKNOWN"


def test_malformed_component_coverage_cannot_admit_positive():
    pod = _pod()
    pod["spec"]["containers"][0]["_component_config"]["_coverage"] = {"component": "collected"}
    assert _status(IDS["deny"][0], pod) == "UNKNOWN"


def test_missing_component_remains_uncertain():
    pod = _pod()
    del pod["spec"]["containers"][0]["_component_config"]["component"]
    assert _status(IDS["deny"][0], pod) == "UNKNOWN"


def test_other_captured_component_not_applicable():
    pod = _pod(component="kubelet")
    assert _status(IDS["deny"][0], pod) == "NOT_APPLICABLE"


def test_unavailable_legacy_version_cannot_admit_plugin_positive():
    pod = _pod("PodSecurityPolicy", version="v1.24.0")
    cid = "k8s.ports.pod.container_argument_pod_security_policy_enabled"
    assert _status(cid, pod) == "PASS"
    pod["spec"]["containers"][0]["_component_config"]["_coverage"] = {
        "version": {"status": "denied"}}
    assert _status(cid, pod) == "UNKNOWN"
