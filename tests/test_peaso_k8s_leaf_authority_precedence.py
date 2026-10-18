"""Registered Kubernetes declarations keep unavailable leaves distinct from known violations."""
import pytest

from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

HOST = "k8s.ports.pod.host_namespaces"
PORT = "k8s.ports.pod.no_host_ports"


def _status(cid, spec):
    item = {"metadata": {"name": "workload", "namespace": "apps"}, "spec": spec}
    snapshot = make_snapshot("k8s", ["*"], [
        {"type": "pod", "scope": "*", "status": "collected", "items": [item]}],
        created_at="2026-10-17T00:00:00Z")
    rows = [r for r in evaluate_snapshot(snapshot, checks=[cid])["findings"] if r["check_id"] == cid]
    assert len(rows) == 1
    return rows[0]


def _ports(*rows):
    return {"containers": [{"name": "app", "ports": list(rows)}]}


@pytest.mark.parametrize("field", ["hostPID", "hostIPC"])
def test_conclusive_host_namespace_violation_survives_unknown_peer(field):
    other = "hostIPC" if field == "hostPID" else "hostPID"
    row = _status(HOST, {field: True, "_coverage": {other: {"status": "denied"}}})
    assert row["status"] == "FAIL"
    assert other not in row["evidence"] or row["evidence"][other] is not False


def test_unavailable_host_peer_without_violation_is_unknown():
    assert _status(HOST, {"hostPID": False, "_coverage": {"hostIPC": {"status": "denied"}}})["status"] == "UNKNOWN"


def test_known_host_namespace_defaults_and_violation():
    assert _status(HOST, {})["status"] == "PASS"
    assert _status(HOST, {"hostPID": True})["status"] == "FAIL"


def test_omitted_denied_host_port_is_unknown():
    port = {"containerPort": 8080, "_coverage": {"hostPort": {"status": "denied"}}}
    assert _status(PORT, _ports(port))["status"] == "UNKNOWN"


def test_malformed_host_port_coverage_is_unknown():
    port = {"containerPort": 8080, "_coverage": {"hostPort": "collected"}}
    assert _status(PORT, _ports(port))["status"] == "UNKNOWN"


def test_known_absent_and_explicit_present_host_port_keep_verdicts():
    assert _status(PORT, _ports({"containerPort": 8080}))["status"] == "PASS"
    assert _status(PORT, _ports({"containerPort": 8080, "hostPort": 0}))["status"] == "FAIL"
    assert _status(PORT, _ports({"containerPort": 8080, "hostPort": 8080}))["status"] == "FAIL"


@pytest.mark.parametrize("unsafe_first", [False, True])
def test_known_prohibited_port_survives_unreadable_peer(unsafe_first):
    good = {"containerPort": 80, "hostPort": 80}
    unknown = {"containerPort": 8080, "_coverage": {"hostPort": {"status": "denied"}}}
    rows = [good, unknown] if unsafe_first else [unknown, good]
    assert _status(PORT, _ports(*rows))["status"] == "FAIL"


def test_unknown_only_other_container_cannot_yield_pass():
    spec = {"containers": [{"name": "safe", "ports": [{"containerPort": 80}]},
                           {"name": "unknown", "ports": [{"containerPort": 8080,
                            "_coverage": {"hostPort": {"status": "denied"}}}]}]}
    assert _status(PORT, spec)["status"] == "UNKNOWN"


@pytest.mark.parametrize("unsafe_first", [False, True])
def test_known_violating_container_survives_unreadable_peer(unsafe_first):
    unsafe = {"name": "unsafe", "ports": [{"containerPort": 80, "hostPort": 80}]}
    unreadable = {"name": "unreadable", "ports": [{"containerPort": 8080,
                  "_coverage": {"hostPort": {"status": "denied"}}}]}
    spec = {"containers": [unsafe, unreadable] if unsafe_first else [unreadable, unsafe]}
    assert _status(PORT, spec)["status"] == "FAIL"
