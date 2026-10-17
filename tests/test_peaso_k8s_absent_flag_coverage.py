"""A captured absent flag needs available field authority, not just no key."""
import pytest

from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

CASES = (
    ("k8s.ports.pod.container_no_argument_basic_auth_file", "basic-auth-file"),
    ("k8s.ports.pod.container_no_argument_insecure_bind_address", "insecure-bind-address"),
    ("k8s.ports.pod.container_token_auth_file_not_configured", "token-auth-file"),
)


def _status(cid, flag, *, value=None, coverage=None):
    flags = {}
    if value is not None:
        flags[flag] = value
    if coverage is not None:
        flags["_coverage"] = {flag: coverage}
    pod = {"metadata": {"name": "api", "namespace": "kube-system", "labels": {"component": "kube-apiserver"}},
           "spec": {"containers": [{"name": "kube-apiserver", "_component_config": {
               "component": "kube-apiserver", "flags_complete": True, "flags": flags, "version": "v1.18.0"}}]}}
    snapshot = make_snapshot("k8s", ["*"], [{"type": "pod", "scope": "*", "status": "collected", "items": [pod]}],
                             created_at="2026-10-17T00:00:00Z")
    rows = [row for row in evaluate_snapshot(snapshot, checks=[cid])["findings"] if row["check_id"] == cid]
    assert len(rows) == 1
    return rows[0]["status"]


@pytest.mark.parametrize("cid,flag", CASES)
def test_denied_flag_absence_does_not_prove_safe_declaration(cid, flag):
    assert _status(cid, flag, coverage={"status": "denied"}) == "UNKNOWN"


@pytest.mark.parametrize("cid,flag", CASES)
def test_available_absence_and_present_prohibited_flag_retain_verdicts(cid, flag):
    assert _status(cid, flag) == "PASS"
    assert _status(cid, flag, value="/etc/unsafe") == "FAIL"


def test_malformed_field_coverage_cannot_prove_absence():
    cid, flag = CASES[0]
    assert _status(cid, flag, coverage="collected") == "UNKNOWN"


def test_explicitly_empty_field_coverage_allows_projected_absence():
    cid, flag = CASES[1]
    assert _status(cid, flag, coverage={"status": "empty"}) == "PASS"


def test_unavailable_present_flag_does_not_prove_negative():
    cid, flag = CASES[2]
    assert _status(cid, flag, value="/etc/unsafe", coverage={"status": "denied"}) == "UNKNOWN"
