"""Native EC2 instance-role configuration joins and policy verdicts."""

import pytest

from peaso.checks import CHECKS
from peaso.checks import aws_gap_ec2 as ec2
from peaso.checks.claude_aws_a_common import idx
from peaso.checks.claude_aws_a_ec2 import w
from peaso.checks.claude_aws_a_iam import doc

CHECK = next(check for check in CHECKS if check.id ==
             "aws.gap.ec2.instance_no_iam_role_with_management_level_access")
ALL_OF = next(check for check in CHECKS if check.id ==
              "aws.gap.ec2.instance_no_iam_role_with_new_group_creation_with_attached_policy_access")


def verdict(check, role, policies=None):
    return check.evaluate(ec2.INST, idx(iam_role=[role], iam_policy=policies or []))[0]


def role(*statements):
    return w(ec2.APP, RolePolicyList=[{"PolicyName": "test", "PolicyDocument": doc(*statements)}])


def test_unresolved_instance_profile_role_join_is_unknown():
    assert CHECK.evaluate(ec2.INST, idx(iam_role=[], iam_policy=[]))[0] == "UNKNOWN"
    wrong = w(ec2.APP, InstanceProfileList=[{"Arn": ec2.PROFILE + "-other"}])
    assert verdict(CHECK, wrong) == "UNKNOWN"


@pytest.mark.parametrize("statement", [
    {"Effect": "Allow", "Action": "iam:CreatePolicy", "Resource": []},
    {"Effect": "Allow", "Action": "iam:CreatePolicy"},
    {"Effect": "Allow", "Action": "iam:CreatePolicy", "Resource": "arn:aws:iam::123456789012:policy/one"},
    {"Effect": "Allow", "Action": "iam:CreatePolicy", "NotResource": "arn:aws:iam::123456789012:policy/one"},
    {"Effect": "Allow", "Action": "iam:CreatePolicy", "Resource": "*", "Condition": {"StringEquals": {"aws:PrincipalTag/team": "app"}}},
])
def test_unresolved_policy_grants_are_unknown(statement):
    assert verdict(CHECK, role(statement)) == "UNKNOWN"


@pytest.mark.parametrize("statement", [
    {"Effect": "Allow", "Action": [], "Resource": "*"},
    {"Effect": "Allow", "Action": "iam:CreatePolicy", "NotAction": "iam:DeletePolicy", "Resource": "*"},
])
def test_malformed_action_form_is_unknown(statement):
    assert verdict(CHECK, role(statement)) == "UNKNOWN"


def test_explicit_all_resource_deny_proves_pass():
    assert verdict(CHECK, role(
        {"Effect": "Allow", "Action": "iam:CreatePolicy", "Resource": "*"},
        {"Effect": "Deny", "Action": "iam:CreatePolicy", "Resource": "*"})) == "PASS"


def test_scoped_deny_makes_wildcard_grant_unresolved():
    assert verdict(CHECK, role(
        {"Effect": "Allow", "Action": "iam:CreatePolicy", "Resource": "*"},
        {"Effect": "Deny", "Action": "iam:CreatePolicy", "Resource": "arn:aws:iam::123456789012:policy/one"})) == "UNKNOWN"


def test_all_of_requires_each_proven_grant():
    conditional = {"Effect": "Allow", "Action": "iam:AttachGroupPolicy", "Resource": "*",
                   "Condition": {"StringEquals": {"aws:PrincipalTag/team": "app"}}}
    create = {"Effect": "Allow", "Action": "iam:CreateGroup", "Resource": "*"}
    assert verdict(ALL_OF, role(create, conditional)) == "UNKNOWN"
    assert verdict(ALL_OF, role(conditional)) == "PASS"
