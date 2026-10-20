"""Registered workload predicates honor explicit parent fact coverage."""
import copy
import pytest

from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


def _snapshot_status(cid, spec, kind="pod"):
    body = {"spec": spec} if kind == "pod" else {"spec": {"template": {"spec": spec}}}
    body["metadata"] = {"name": "workload", "namespace": "apps"}
    snapshot = make_snapshot("k8s", ["*"], [
        {"type": kind, "scope": "*", "status": "collected", "items": [body]}
    ], created_at="2026-10-17T00:00:00Z")
    rows = [r for r in evaluate_snapshot(snapshot, checks=[cid])["findings"] if r["check_id"] == cid]
    assert len(rows) == 1
    return rows[0]["status"]


def _spec(container=None):
    return {"containers": [{"name": "app", **(container or {})}]}


CASES = (
    ("k8s.ports.pod.pod_runtime_default_seccomp", "pod", {"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}}}, ("spec", "securityContext")),
    ("k8s.ports.pod.pod_runtime_default_seccomp", "pod", {"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}}}, ("pod_context", "seccompProfile")),
    ("k8s.ports.pod.explicit_serviceaccount", "pod", {"serviceAccountName": "app"}, ("spec", "serviceAccountName")),
    ("k8s.ports.pod.no_added_capabilities", "pod", {"securityContext": {"capabilities": {"add": []}}}, ("context", "capabilities")),
    ("k8s.ports.pod.cpu_limit", "pod", {"resources": {"limits": {"cpu": "1"}}}, ("container", "resources")),
    ("k8s.ports.pod.cpu_limit", "pod", {"resources": {"limits": {"cpu": "1"}}}, ("resources", "limits")),
    ("k8s.ports.pod.cpu_limit", "pod", {"resources": {"limits": {"cpu": "1"}}}, ("limits", "cpu")),
    ("k8s.ports.pod.readiness_probe", "pod", {"readinessProbe": {"tcpSocket": {"port": 8080}}}, ("container", "readinessProbe")),
    ("k8s.ports.pod.no_host_ports", "pod", {"ports": []}, ("container", "ports")),
    ("k8s.ports.pod.always_pull", "pod", {"image": "app:v2", "imagePullPolicy": "Always"}, ("container", "imagePullPolicy")),
    ("k8s.ports.deployment.container_runtime_default_seccomp", "deployment", {"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}}}, ("context", "seccompProfile")),
)


def _case(kind, container, location):
    spec = _spec(container)
    if location[0] == "spec":
        spec[location[1]] = spec["containers"][0].pop(location[1])
        parent = spec
    elif location[0] == "pod_context":
        spec["securityContext"] = spec["containers"][0].pop("securityContext")
        parent = spec["securityContext"]
    elif location[0] == "container":
        parent = spec["containers"][0]
    elif location[0] == "context":
        parent = spec["containers"][0]["securityContext"]
    elif location[0] == "resources":
        parent = spec["containers"][0]["resources"]
    elif location[0] == "limits":
        parent = spec["containers"][0]["resources"]["limits"]
    else:
        raise AssertionError(location)
    return spec, parent


@pytest.mark.parametrize("cid,kind,container,location", CASES)
def test_denied_consumed_parent_cannot_grade(cid, kind, container, location):
    spec, parent = _case(kind, copy.deepcopy(container), location)
    assert _snapshot_status(cid, copy.deepcopy(spec), kind) == "PASS"
    parent["_coverage"] = {location[1]: {"status": "denied"}}
    assert _snapshot_status(cid, spec, kind) == "UNKNOWN"


def test_malformed_optional_parent_coverage_unknown():
    cid, kind, container, location = CASES[3]
    spec, parent = _case(kind, copy.deepcopy(container), location)
    parent["_coverage"] = {location[1]: "collected"}
    assert _snapshot_status(cid, spec, kind) == "UNKNOWN"


def test_valid_omission_defaults_remain_distinct():
    assert _snapshot_status("k8s.ports.pod.explicit_serviceaccount", _spec()) == "FAIL"
    assert _snapshot_status("k8s.ports.pod.pod_runtime_default_seccomp", _spec()) == "FAIL"
    assert _snapshot_status("k8s.ports.pod.no_added_capabilities", _spec()) == "PASS"
    assert _snapshot_status("k8s.ports.pod.no_host_ports", _spec()) == "PASS"
    assert _snapshot_status("k8s.ports.pod.readiness_probe", _spec()) == "FAIL"
    assert _snapshot_status("k8s.ports.pod.always_pull", _spec({"image": "app:latest"})) == "FAIL"


def test_valid_unsafe_declared_facts_still_fail():
    assert _snapshot_status("k8s.ports.pod.explicit_serviceaccount", _spec() | {"serviceAccountName": ""}) == "FAIL"
    assert _snapshot_status("k8s.ports.pod.no_added_capabilities", _spec({"securityContext": {"capabilities": {"add": ["NET_ADMIN"]}}})) == "FAIL"
    assert _snapshot_status("k8s.ports.pod.no_host_ports", _spec({"ports": [{"containerPort": 80, "hostPort": 80}]})) == "FAIL"
