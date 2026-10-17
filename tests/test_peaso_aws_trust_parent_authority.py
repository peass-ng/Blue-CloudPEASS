"""Selected trust Principal parent authority in registered Prowler IAM checks."""
import copy
import pytest
from peaso.checks import claude_aws_a_iam as iam
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

READONLY = "aws.claude_a.iam.prowler_role_readonly_not_cross_account"
ADMIN = "aws.claude_a.iam.prowler_role_no_administratoraccess"

def verdict(cid, statements, *, attach_readonly=True, attach_admin=False):
    role = copy.deepcopy(iam.HUMAN_ROLE)
    role["AssumeRolePolicyDocument"] = iam.doc(*copy.deepcopy(statements))
    if attach_readonly:
        role = iam.attach("iam_role", iam.READONLY, role)
    if attach_admin:
        role = iam.attach("iam_role", iam.ADMIN, role)
    snapshot = make_snapshot("aws", [iam.ACCOUNT], [{"type": "iam_role", "scope": iam.ACCOUNT,
        "status": "collected", "items": [role]}], created_at="2026-10-17T00:00:00Z")
    rows = [r for r in evaluate_snapshot(snapshot, checks=[cid])["findings"] if r["check_id"] == cid]
    assert len(rows) == 1
    return rows[0]["status"]

def statement(principal, *, effect="Allow", action="sts:AssumeRole"):
    return {"Effect": effect, "Action": action, "Principal": principal}

@pytest.mark.parametrize("principal", [42, None, [], {}, "", {"AWS": None}])
def test_malformed_allow_parent_or_child_cannot_prove_safe_readonly(principal):
    assert verdict(READONLY, [statement(principal)]) == "UNKNOWN"

def test_missing_or_denied_allow_parent_is_unknown():
    base = {"Effect": "Allow", "Action": "sts:AssumeRole"}
    assert verdict(READONLY, [base]) == "UNKNOWN"
    base["_coverage"] = {"Principal": {"status": "denied"}}
    assert verdict(READONLY, [base]) == "UNKNOWN"

def test_valid_scalar_and_service_only_parent_preserve_nonservice_and_service_cases():
    assert verdict(READONLY, [statement("*")]) == "PASS"
    assert verdict(READONLY, [statement({"Service": "ec2.amazonaws.com"})]) == "NOT_APPLICABLE"
    assert verdict(ADMIN, [statement({"Service": "ec2.amazonaws.com"})], attach_admin=True) == "NOT_APPLICABLE"

def test_valid_aws_parent_preserves_own_and_foreign_result():
    own = "arn:aws:iam::" + iam.ACCOUNT + ":root"
    assert verdict(READONLY, [statement({"AWS": own})]) == "PASS"
    assert verdict(READONLY, [statement({"AWS": "arn:aws:iam::999999999999:root"})]) == "FAIL"

@pytest.mark.parametrize("reverse", [False, True])
def test_known_cross_account_allow_is_conclusive_with_malformed_peer(reverse):
    rows = [statement(42), statement({"AWS": "arn:aws:iam::999999999999:root"})]
    if reverse:
        rows.reverse()
    assert verdict(READONLY, rows) == "FAIL"

def test_malformed_allow_parent_cannot_prove_nonservice_for_admin():
    assert verdict(ADMIN, [statement(42)], attach_admin=True) == "UNKNOWN"

def test_known_deny_and_non_assume_role_skip_unused_parent():
    assert verdict(READONLY, [statement(42, effect="Deny")]) == "PASS"
    assert verdict(ADMIN, [statement(42, action="s3:GetObject")], attach_admin=True) == "FAIL"

def test_no_readonly_attachment_keeps_early_safe_decision():
    assert verdict(READONLY, [statement(42)], attach_readonly=False) == "PASS"


def test_service_role_without_readonly_keeps_historical_not_applicable():
    assert verdict(READONLY, [statement({"Service": "ec2.amazonaws.com"})],
        attach_readonly=False) == "NOT_APPLICABLE"
