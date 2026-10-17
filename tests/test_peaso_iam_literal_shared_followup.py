"""Registered IAM trust-policy evidence cannot be authenticated by bad literal coverage."""
import copy

import pytest

from peaso.checks import evaluate_check
from peaso.checks.fixtures import CASES


CID = "aws.claude_a.iam.role_trust_not_public"


def verdict(item):
    return evaluate_check(CID, item, {})[0]


def conditioned():
    return copy.deepcopy(CASES[CID]["variants"][0][1])


def test_registered_originals():
    assert verdict(CASES[CID]["pass"]) == "PASS"
    assert verdict(CASES[CID]["fail"]) == "FAIL"
    assert verdict(conditioned()) == "PASS"


@pytest.mark.parametrize("level,marker", [
    ("key", None),
    ("key", {"status": "empty"}),
    ("operator", None),
    ("operator", {"status": "empty"}),
])
def test_literal_condition_coverage_must_authenticate_value(level, marker):
    item = conditioned()
    condition = item["AssumeRolePolicyDocument"]["Statement"][0]["Condition"]
    if level == "key":
        condition["StringEquals"]["_coverage"] = {"aws:PrincipalOrgID": marker}
    else:
        condition["_coverage"] = {"StringEquals": marker}
    assert verdict(item) == "UNKNOWN"


def test_explicit_null_condition_is_unavailable():
    item = conditioned()
    item["AssumeRolePolicyDocument"]["Statement"][0]["Condition"] = None
    assert verdict(item) == "UNKNOWN"


def test_explicit_null_operator_is_unavailable():
    item = conditioned()
    item["AssumeRolePolicyDocument"]["Statement"][0]["Condition"]["StringEquals"] = None
    assert verdict(item) == "UNKNOWN"
