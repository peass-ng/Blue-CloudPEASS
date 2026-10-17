"""Required IAM policy Statement remains authoritative across native consumers."""

import copy
import json
from urllib.parse import quote

import pytest

from peaso.checks import CHECKS
from peaso.checks import aws_gap_ec2 as ec2
from peaso.checks.claude_aws_a_common import idx, policy_document
from peaso.checks.claude_aws_a_ec2 import w
from peaso.checks.facts import Unavailable

CHECK = next(check for check in CHECKS if check.id ==
             "aws.gap.ec2.instance_no_iam_role_with_management_level_access")
GRANT = {"Effect": "Allow", "Action": "iam:CreatePolicy", "Resource": "*"}


def verdict(document):
    role = w(ec2.APP, RolePolicyList=[{"PolicyName": "audit", "PolicyDocument": document}])
    return CHECK.evaluate(ec2.INST, idx(iam_role=[role], iam_policy=[]))[0]


def test_missing_or_denied_statement_cannot_prove_role_safe_or_unsafe():
    assert verdict({"Version": "2012-10-17"}) == "UNKNOWN"
    denied = {"Version": "2012-10-17", "Statement": [GRANT],
              "_coverage": {"Statement": {"status": "denied"}}}
    assert verdict(denied) == "UNKNOWN"


@pytest.mark.parametrize("document", [
    {"Statement": GRANT},
    {"Statement": [GRANT]},
    json.dumps({"Statement": GRANT}),
    quote(json.dumps({"Statement": [GRANT]})),
])
def test_object_array_json_and_urlencoded_document_forms_still_work(document):
    assert verdict(document) == "FAIL"


def test_explicit_empty_statement_retains_no_grant_semantics():
    assert verdict({"Statement": []}) == "PASS"


def test_statement_rows_are_copied_before_consumers_change_them():
    document = {"Statement": [copy.deepcopy(GRANT)]}
    rows = policy_document(document)
    rows[0]["Action"] = "iam:DeletePolicy"
    assert document["Statement"][0]["Action"] == "iam:CreatePolicy"


@pytest.mark.parametrize("document", [
    {"Version": "2012-10-17"},
    {"Statement": None},
    {"Statement": ["not a statement"]},
    {"Statement": [GRANT], "_coverage": {"Statement": {"status": "denied"}}},
])
def test_unreadable_or_malformed_statement_raises_unavailable(document):
    with pytest.raises(Unavailable):
        policy_document(document)
