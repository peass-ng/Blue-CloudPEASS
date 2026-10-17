"""Selected LoginProfile receipt cannot contradict its retained profile."""
from copy import deepcopy
import pytest
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

CID = "aws.iam.console_mfa"
PROFILE = {"LoginProfile": {"UserName": "alice"}}
DEVICE = {"SerialNumber": "arn:aws:iam::123456789012:mfa/alice"}


def verdict(login, devices):
    item = {"UserName": "alice", "LoginProfile": deepcopy(login), "MFADevices": deepcopy(devices)}
    snap = make_snapshot("aws", ["*"], [{"type": "iam_user", "scope": "*", "status": "collected", "items": [item]}], created_at="2026-10-17T00:00:00Z")
    before = deepcopy(snap)
    rows = [r for r in evaluate_snapshot(snap, checks=[CID])["findings"] if r["check_id"] == CID]
    assert before == snap and len(rows) == 1
    return rows[0]["status"]


@pytest.mark.parametrize("login", [
    {"collection_status": "empty", "absent": True, **PROFILE},
    {"collection_status": "empty", "absent": False, **PROFILE},
    {"collection_status": "collected", "absent": True, **PROFILE},
    {"collection_status": "collected", "absent": True},
])
def test_contradictory_login_receipt_is_unknown(login):
    assert verdict(login, [DEVICE]) == "UNKNOWN"


@pytest.mark.parametrize("login", [
    {"collection_status": "empty", "absent": True},
    {"absent": True},
    None,
])
def test_genuine_no_login_remains_not_applicable(login):
    assert verdict(login, []) == "NOT_APPLICABLE"


@pytest.mark.parametrize("login", [PROFILE, {"collection_status": "collected", "absent": False, **PROFILE}])
def test_collected_login_uses_device_evidence(login):
    assert verdict(login, [DEVICE]) == "PASS"
    assert verdict(login, []) == "FAIL"


@pytest.mark.parametrize("field", ["collection_status", "absent", "LoginProfile"])
def test_denied_selected_login_field_is_unknown(field):
    login = {"collection_status": "collected", "absent": False, **PROFILE, "_coverage": {field: {"status": "denied"}}}
    assert verdict(login, [DEVICE]) == "UNKNOWN"


def test_empty_status_without_absence_receipt_and_bad_profile_shape_are_unknown():
    assert verdict({"collection_status": "empty", **PROFILE}, [DEVICE]) == "UNKNOWN"
    assert verdict({"collection_status": "collected", "absent": False, "LoginProfile": 42}, [DEVICE]) == "UNKNOWN"
