"""Registered PodSpec checks must honor optional container field authority."""
import pytest

from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

INVENTORY_CID = "k8s.ports.pod.no_host_ports"
CONTEXT_CID = "k8s.ports.pod.declared_nonroot"


def _pod():
    return {"metadata": {"name": "workload", "namespace": "apps"},
            "spec": {"containers": [{"name": "app", "securityContext": {"runAsNonRoot": True}}]}}


def _status(pod, cid=INVENTORY_CID):
    snap = make_snapshot("k8s", ["*"], [{"type": "pod", "scope": "*", "status": "collected", "items": [pod]}],
                         created_at="2026-10-17T00:00:00Z")
    rows = [row for row in evaluate_snapshot(snap, checks=[cid])["findings"] if row["check_id"] == cid]
    assert len(rows) == 1
    return rows[0]["status"]


@pytest.mark.parametrize("field", ["initContainers", "ephemeralContainers"])
def test_unreadable_omitted_optional_inventory_cannot_prove_safe(field):
    pod = _pod()
    pod["spec"]["_coverage"] = {field: {"status": "denied"}}
    assert _status(pod) == "UNKNOWN"


@pytest.mark.parametrize("field", ["initContainers", "ephemeralContainers"])
def test_unreadable_present_optional_inventory_cannot_prove_safe(field):
    pod = _pod()
    pod["spec"][field] = [{"name": "side", "securityContext": {"runAsNonRoot": True}}]
    pod["spec"]["_coverage"] = {field: {"status": "denied"}}
    assert _status(pod) == "UNKNOWN"


def test_malformed_optional_container_list_cannot_prove_safe():
    pod = _pod()
    pod["spec"]["initContainers"] = {"name": "side"}
    assert _status(pod) == "UNKNOWN"


def test_explicit_safe_optional_containers_and_valid_omission_pass():
    pod = _pod()
    assert _status(pod) == "PASS"
    pod["spec"]["initContainers"] = [{"name": "side", "securityContext": {"runAsNonRoot": True}}]
    pod["spec"]["ephemeralContainers"] = [{"name": "debug", "securityContext": {"runAsNonRoot": True}}]
    assert _status(pod) == "PASS"


def test_observed_unsafe_init_container_fails():
    pod = _pod()
    pod["spec"]["initContainers"] = [{"name": "init", "ports": [{"containerPort": 8080, "hostPort": 8080}]}]
    assert _status(pod) == "FAIL"


@pytest.mark.parametrize("present", [False, True])
def test_unreadable_container_security_context_cannot_prove_safe(present):
    pod = _pod()
    container = pod["spec"]["containers"][0]
    if not present:
        del container["securityContext"]
    container["_coverage"] = {"securityContext": {"status": "denied"}}
    assert _status(pod, CONTEXT_CID) == "UNKNOWN"


def test_valid_omitted_security_context_keeps_default():
    pod = _pod()
    assert _status(pod, CONTEXT_CID) == "PASS"
    del pod["spec"]["containers"][0]["securityContext"]
    assert _status(pod, CONTEXT_CID) == "FAIL"
