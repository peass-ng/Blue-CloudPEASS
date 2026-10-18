"""Selected IAM statement facts need authority in registered snapshot evaluation."""
import copy
import pytest

from peaso.checks import claude_aws_a_iam as iam
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

POLICY = "aws.claude_a.iam.custom_policy_no_star_star"
ROLE = "aws.claude_a.iam.role_readonly_not_cross_account"
PROWLER_ADMIN = "aws.claude_a.iam.prowler_role_no_administratoraccess"
PROWLER_READONLY = "aws.claude_a.iam.prowler_role_readonly_not_cross_account"


def status(cid, kind, item):
    snapshot = make_snapshot("aws", [iam.ACCOUNT], [
        {"type": kind, "scope": iam.ACCOUNT, "status": "collected", "items": [copy.deepcopy(item)]}],
        created_at="2026-10-17T00:00:00Z")
    findings = [row for row in evaluate_snapshot(snapshot, checks=[cid])["findings"]
                if row["check_id"] == cid]
    assert len(findings) == 1
    return findings[0]["status"]


def denied(row, field):
    row.setdefault("_coverage", {})[field] = {"status": "denied"}
    return row


def policy(statement):
    return iam.pol(copy.deepcopy(statement))


def role(statement, readonly=True):
    item = copy.deepcopy(iam.HUMAN_ROLE)
    item["AssumeRolePolicyDocument"] = iam.doc(copy.deepcopy(statement))
    return iam.attach("iam_role", iam.READONLY, item) if readonly else item


@pytest.mark.parametrize("field", ["Effect", "Action", "Resource"])
def test_selected_policy_statement_field_denial_is_unknown(field):
    statement = denied(iam.allow("*"), field)
    assert status(POLICY, "iam_policy", policy(statement)) == "UNKNOWN"


def test_selected_safe_action_denial_cannot_prove_no_star_star():
    statement = denied(iam.allow("s3:GetObject", "arn:aws:s3:::bucket/*"), "Action")
    assert status(POLICY, "iam_policy", policy(statement)) == "UNKNOWN"


def test_identity_policy_does_not_require_principal_or_extra_resource():
    assert status(POLICY, "iam_policy", policy(iam.allow("s3:GetObject"))) == "PASS"
    assert status(POLICY, "iam_policy", policy(iam.allow("*"))) == "FAIL"


def test_selected_cross_account_principal_child_denial_is_unknown():
    statement = {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}}
    denied(statement["Principal"], "AWS")
    assert status(ROLE, "iam_role", role(statement)) == "UNKNOWN"


@pytest.mark.parametrize("field", ["Effect", "Action", "Principal"])
def test_service_role_classifier_selected_denial_is_unknown(field):
    statement = denied({"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "ec2.amazonaws.com"}}, field)
    item = copy.deepcopy(iam.ROLE)
    item["AssumeRolePolicyDocument"] = iam.doc(statement)
    assert status(PROWLER_ADMIN, "iam_role", item) == "UNKNOWN"


def test_prowler_cross_account_principal_child_denial_is_unknown():
    statement = {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}}
    denied(statement["Principal"], "AWS")
    assert status(PROWLER_READONLY, "iam_role", role(statement)) == "UNKNOWN"


def test_known_cross_account_and_safe_trust_baselines():
    bad = {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}}
    good = {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "arn:aws:iam::" + iam.ACCOUNT + ":root"}}
    assert status(ROLE, "iam_role", role(bad)) == "FAIL"
    assert status(ROLE, "iam_role", role(good)) == "PASS"


def test_identity_policy_ignores_unconsumed_principal_authority():
    statement = denied(iam.allow("s3:GetObject"), "Principal")
    assert status(POLICY, "iam_policy", policy(statement)) == "PASS"


def test_trust_policy_rejects_declared_unreadable_omitted_principal():
    statement = denied({"Effect": "Allow", "Action": "sts:AssumeRole"}, "Principal")
    assert status(ROLE, "iam_role", role(statement)) == "UNKNOWN"


def test_trust_policy_does_not_require_resource_field():
    statement = denied({"Effect": "Allow", "Action": "sts:AssumeRole",
                        "Principal": {"AWS": "arn:aws:iam::999999999999:root"}}, "Resource")
    assert status(ROLE, "iam_role", role(statement)) == "FAIL"


def test_selected_service_principal_child_denial_is_unknown():
    statement = {"Effect": "Allow", "Action": "sts:AssumeRole",
                 "Principal": {"Service": "ec2.amazonaws.com"}}
    denied(statement["Principal"], "Service")
    item = copy.deepcopy(iam.ROLE)
    item["AssumeRolePolicyDocument"] = iam.doc(statement)
    assert status(PROWLER_ADMIN, "iam_role", item) == "UNKNOWN"


def test_identity_projection_ignores_unconsumed_alternate_fields():
    statement = iam.allow("*")
    denied(statement, "NotAction")
    denied(statement, "NotResource")
    assert status(POLICY, "iam_policy", policy(statement)) == "FAIL"


def test_known_nonservice_principal_does_not_consume_unrelated_service_child():
    statement = {"Effect": "Allow", "Action": "sts:AssumeRole",
                 "Principal": {"AWS": "arn:aws:iam::999999999999:root"}}
    denied(statement["Principal"], "Service")
    assert status(PROWLER_READONLY, "iam_role", role(statement)) == "FAIL"
