"""Selected IAM trust principal values have provider-shaped types before verdicts."""
import copy
import pytest

from peaso.checks import claude_aws_a_iam as iam
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

ADMIN = "aws.claude_a.iam.prowler_role_no_administratoraccess"
READONLY = "aws.claude_a.iam.prowler_role_readonly_not_cross_account"


def status(cid, role):
    snapshot = make_snapshot("aws", [iam.ACCOUNT], [
        {"type": "iam_role", "scope": iam.ACCOUNT, "status": "collected", "items": [copy.deepcopy(role)]}],
        created_at="2026-10-17T00:00:00Z")
    findings = [row for row in evaluate_snapshot(snapshot, checks=[cid])["findings"]
                if row["check_id"] == cid]
    assert len(findings) == 1
    return findings[0]["status"]


def service_role(value, action="sts:AssumeRole", admin=True):
    role = copy.deepcopy(iam.ROLE)
    role["AssumeRolePolicyDocument"] = iam.doc({"Effect": "Allow", "Action": action,
                                                  "Principal": {"Service": value}})
    return iam.attach("iam_role", iam.ADMIN, role) if admin else role


def aws_role(value, readonly=True):
    role = copy.deepcopy(iam.HUMAN_ROLE)
    role["AssumeRolePolicyDocument"] = iam.doc({"Effect": "Allow", "Action": "sts:AssumeRole",
                                                  "Principal": {"AWS": value}})
    return iam.attach("iam_role", iam.READONLY, role) if readonly else role


@pytest.mark.parametrize("value", [None, {}, [], "", "   ", [""], ["ec2.amazonaws.com", ""]])
def test_malformed_selected_service_principal_cannot_skip_admin_review(value):
    assert status(ADMIN, service_role(value)) == "UNKNOWN"


@pytest.mark.parametrize("value", [{}, [], "", "   ", [""], ["arn:aws:iam::999999999999:root", ""], 7])
def test_malformed_selected_aws_principal_cannot_prove_cross_account(value):
    assert status(READONLY, aws_role(value)) == "UNKNOWN"


def test_valid_service_scalar_and_list_still_skip_service_roles():
    assert status(ADMIN, service_role("ec2.amazonaws.com")) == "NOT_APPLICABLE"
    assert status(ADMIN, service_role(["ec2.amazonaws.com", "lambda.amazonaws.com"])) == "NOT_APPLICABLE"


def test_valid_aws_scalar_and_list_keep_cross_account_verdicts():
    foreign = "arn:aws:iam::999999999999:root"
    own = "arn:aws:iam::" + iam.ACCOUNT + ":root"
    assert status(READONLY, aws_role(foreign)) == "FAIL"
    assert status(READONLY, aws_role([own, foreign])) == "FAIL"
    assert status(READONLY, aws_role(own)) == "PASS"


def test_known_non_assume_role_action_ignores_unreadable_service_value():
    assert status(ADMIN, service_role({}, action="s3:GetObject")) == "FAIL"


def test_no_readonly_policy_keeps_early_safe_decision_with_malformed_aws():
    assert status(READONLY, aws_role({}, readonly=False)) == "PASS"
