"""Trust statement selected-field authority through the registered snapshot engine."""
import copy
import pytest

from peaso.checks import claude_aws_a_iam as iam
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

CID = "aws.claude_a.iam.role_readonly_not_cross_account"


def outcome(*statements):
    role = copy.deepcopy(iam.HUMAN_ROLE)
    role["AssumeRolePolicyDocument"] = iam.doc(*copy.deepcopy(statements))
    role = iam.attach("iam_role", iam.READONLY, role)
    snapshot = make_snapshot("aws", [iam.ACCOUNT], [{"type": "iam_role", "scope": iam.ACCOUNT,
        "status": "collected", "items": [role]}], created_at="2026-10-17T00:00:00Z")
    rows = [x for x in evaluate_snapshot(snapshot, checks=[CID])["findings"] if x["check_id"] == CID]
    assert len(rows) == 1
    return rows[0]["status"]


def trust(principal, effect="Allow"):
    return {"Effect": effect, "Action": "sts:AssumeRole", "Principal": principal}


@pytest.mark.parametrize("principal", [42, [], {}, {"AWS": None}, {"AWS": {}},
    {"AWS": []}, {"AWS": ""}, {"AWS": ["arn:aws:iam::123456789012:root", ""]}])
def test_malformed_selected_allow_principal_is_unknown(principal):
    assert outcome(trust(principal)) == "UNKNOWN"


def test_nonempty_service_only_principal_is_not_cross_account_aws():
    assert outcome(trust({"Service": "ec2.amazonaws.com"})) == "PASS"


def test_known_aws_principals_keep_literal_membership():
    own = "arn:aws:iam::" + iam.ACCOUNT + ":root"
    assert outcome(trust({"AWS": own})) == "PASS"
    assert outcome(trust({"AWS": "arn:aws:iam::999999999999:root"})) == "FAIL"
    assert outcome(trust("*")) == "FAIL"


def test_known_deny_does_not_consume_irrelevant_unavailable_principal():
    denied = {"Effect": "Deny", "Action": "sts:AssumeRole",
        "_coverage": {"Principal": {"status": "denied"}}}
    assert outcome(denied) == "PASS"
    assert outcome(denied, trust({"AWS": "arn:aws:iam::999999999999:root"})) == "FAIL"


def test_allow_declared_unavailable_principal_remains_unknown():
    statement = {"Effect": "Allow", "Action": "sts:AssumeRole",
        "_coverage": {"Principal": {"status": "denied"}}}
    assert outcome(statement) == "UNKNOWN"


def test_service_only_with_declared_unreadable_aws_child_is_unknown():
    principal = {"Service": "ec2.amazonaws.com",
        "_coverage": {"AWS": {"status": "denied"}}}
    assert outcome(trust(principal)) == "UNKNOWN"
