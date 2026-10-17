"""S3 stored-public-grant checks distinguish future guards from existing policy facts."""
import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks import claude_aws_a_s3 as s3


CHECK_BY_ID = {check.id: check for check in CHECKS}
READ_ID = "aws.claude_a.s3.restrict_public_read"
POLICY_ID = "aws.claude_a.s3.policy_restrict_public_access"


def run(check_id, item):
    return CHECK_BY_ID[check_id].evaluate(copy.deepcopy(item), copy.deepcopy(s3.IDX))


def with_policy(condition=None):
    statement = copy.deepcopy(s3.PUBLIC_POLICY["Policy"]["Statement"][0])
    if condition is not None:
        statement["Condition"] = condition
    policy = {"collection_status": "collected", "Policy": {"Version": "2012-10-17", "Statement": [statement]}}
    return s3.w(s3.B, Policy=policy, PolicyStatus__PolicyStatus__IsPublic=True)


def with_flags(item, **settings):
    result = copy.deepcopy(item)
    result["PublicAccessBlock"]["PublicAccessBlockConfiguration"].update(settings)
    return result


def test_existing_public_read_policy_survives_future_only_block_public_policy():
    item = with_flags(with_policy(), BlockPublicPolicy=True, RestrictPublicBuckets=False)
    status, evidence = run(READ_ID, item)
    assert status == "FAIL"
    assert evidence["read_policy"] is True
    assert evidence["runtime_public_policy_restricted"] is False
    # RestrictPublicBuckets limits runtime access, but does not remove the stored policy.
    status, evidence = run(READ_ID, with_flags(item, RestrictPublicBuckets=True))
    assert status == "FAIL"
    assert evidence["runtime_public_policy_restricted"] is True
    assert evidence["effective_public_access"] == "not determined by stored-policy check"


def test_existing_public_acl_survives_block_public_acls_and_is_ignored_at_runtime():
    item = s3.w(s3.B, Acl=s3.acl_with(s3.ALL_USERS, "READ"))
    status, evidence = run(READ_ID, item)
    assert status == "FAIL"
    assert evidence["public_acl"] is True
    assert evidence["runtime_acl_ignored"] is True
    status, evidence = run(READ_ID, with_flags(item, IgnorePublicAcls=False))
    assert status == "FAIL"
    assert evidence["runtime_acl_ignored"] is False


@pytest.mark.parametrize("condition,want", [
    ({"StringEquals": {"aws:PrincipalOrgID": "o-abcdefghij"}}, "PASS"),
    ({"StringEquals": {"aws:SourceAccount": "123456789012"}}, "PASS"),
    ({"StringEquals": {"aws:PrincipalAccount": ["123456789012", "999999999999"]}}, "PASS"),
    ({"ArnEquals": {"aws:SourceArn": "arn:aws:lambda:us-east-1:123456789012:function:reader"}}, "PASS"),
    # StringEquals compares literal text; the star is not an all-match pattern.
    ({"StringEquals": {"aws:PrincipalOrgID": "*"}}, "UNKNOWN"),
    ({"StringEquals": {"aws:SourceAccount": ["123456789012", "*"]}}, "UNKNOWN"),
    ({"StringLike": {"aws:PrincipalOrgID": "*"}}, "UNKNOWN"),
    ({"StringEquals": {"aws:PrincipalAccount": ""}}, "UNKNOWN"),
    ({"StringEquals": {"aws:PrincipalOrgID": "o-bad"}}, "UNKNOWN"),
    ({"StringEqualsIfExists": {"aws:SourceAccount": "123456789012"}}, "UNKNOWN"),
    ({"ForAllValues:StringEquals": {"aws:PrincipalOrgID": "o-abcdefghij"}}, "UNKNOWN"),
    ({"StringNotEquals": {"aws:SourceAccount": "123456789012"}}, "UNKNOWN"),
    ({"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}, "UNKNOWN"),
    ({"ArnLike": {"aws:SourceArn": "arn:aws:lambda:us-east-1:123456789012:function:*"}}, "UNKNOWN"),
    ({"ArnEquals": {"aws:SourceArn": "arn:aws:lambda:us-east-1:123456789012:function:*"}}, "UNKNOWN"),
    ({"StringEquals": {"aws:SourceAccount": "${aws:PrincipalAccount}"}}, "UNKNOWN"),
    ({"StringEquals": {"aws:SourceAccount": []}}, "UNKNOWN"),
])
def test_fixed_restriction_requires_actual_safe_operator_and_all_list_values(condition, want):
    assert run(POLICY_ID, with_policy(condition))[0] == want


def test_and_conditions_fixed_constraint_wins_and_explicit_deny_is_not_allow():
    condition = {"StringEquals": {"aws:SourceAccount": "123456789012"},
                 "StringEqualsIfExists": {"aws:PrincipalOrgID": "o-abcdefghij"}}
    assert run(POLICY_ID, with_policy(condition))[0] == "PASS"
    item = with_policy()
    item["Policy"]["Policy"]["Statement"][0]["Effect"] = "Deny"
    assert run(POLICY_ID, item)[0] == "PASS"


def test_unconditioned_allow_is_fail_even_with_other_uncertain_statement():
    item = with_policy({"StringEqualsIfExists": {"aws:SourceAccount": "123456789012"}})
    item["Policy"]["Policy"]["Statement"].append(copy.deepcopy(s3.PUBLIC_POLICY["Policy"]["Statement"][0]))
    assert run(POLICY_ID, item)[0] == "FAIL"


@pytest.mark.parametrize("condition", [
    {"StringEquals": {"aws:PrincipalOrgID": "*"}},
    {"StringEquals": {"aws:SourceAccount": ["123456789012", "*"]}},
    {"ArnLike": {"aws:SourceArn": "arn:aws:lambda:us-east-1:123456789012:function:*"}},
    {"StringEquals": {"aws:SourceAccount": "${aws:PrincipalAccount}"}},
])
def test_uncertain_read_condition_does_not_claim_public_exposure(condition):
    status, evidence = run(READ_ID, with_policy(condition))
    assert status == "UNKNOWN"
    assert "condition" in evidence["reason"]


def test_malformed_condition_block_is_unknown():
    item = with_policy()
    item["Policy"]["Policy"]["Statement"][0]["Condition"] = {"StringEquals": "aws:SourceAccount=123456789012"}
    assert run(POLICY_ID, item)[0] == "UNKNOWN"


def test_missing_or_denied_policy_and_public_status_are_not_clean():
    assert run(POLICY_ID, s3.w(s3.B, Policy={"collection_status": "denied"}))[0] == "UNKNOWN"
    assert run(READ_ID, s3.w(with_policy(), PolicyStatus={"collection_status": "denied"}))[0] == "UNKNOWN"
    assert run(READ_ID, s3.w(s3.B, Acl={"collection_status": "denied"}))[0] == "UNKNOWN"
    policy_without_status = s3.w(with_policy({"StringEquals": {"aws:SourceAccount": "123456789012"}}),
                                 PolicyStatus=s3.ABSENT)
    assert run(READ_ID, policy_without_status)[0] == "UNKNOWN"


def test_public_status_without_identified_read_statement_is_unknown_for_read_scope():
    item = s3.w(s3.B, Policy=s3.PUBLIC_WRITE_POLICY, PolicyStatus__PolicyStatus__IsPublic=True)
    status, evidence = run(READ_ID, item)
    assert status == "UNKNOWN"
    assert "read scope" in evidence["reason"]
