"""Firewall Manager evaluation rows are evidence, not a complete account census."""
import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks.claude2_aws_b_common import SCOPE, inventory
from peaso.checks.claude2_aws_b_identity import _fms_policy


CHECK = next(check for check in CHECKS if check.id == "aws.c2b.fms.policies_compliant")


def evaluate(policies, collection_status=None):
    index = inventory("fms_policy", policies, collection_status)
    before = copy.deepcopy(index)
    outcome = CHECK.evaluate({"scope": SCOPE}, index)
    assert index == before
    return outcome


def one_row(evaluations):
    policy = _fms_policy("COMPLIANT")
    policy["ComplianceStatus"]["items"][0]["EvaluationResults"] = evaluations
    return policy


def test_all_returned_results_compliant_pass_only_observed_scope():
    status, evidence = evaluate([_fms_policy("COMPLIANT", "COMPLIANT")])
    assert status == "PASS"
    assert evidence["policy_count"] == 1
    assert evidence["member_account_rows"] == evidence["compliant_evaluations"] == 2
    assert "organization-wide account completeness is not established" in evidence["coverage"]


def test_later_noncompliant_result_is_not_hidden_by_first_result():
    status, evidence = evaluate([one_row([{"ComplianceStatus": "COMPLIANT"}, {"ComplianceStatus": "NON_COMPLIANT"}])])
    assert status == "FAIL"
    assert evidence["non_compliant"] == [{"policy": "p", "account": "222222222220", "status": "NON_COMPLIANT"}]


def test_observed_violation_still_fails_with_another_missing_result():
    status, evidence = evaluate([one_row([{}, {"ComplianceStatus": "NON_COMPLIANT"}])])
    assert status == "FAIL"
    assert evidence["incomplete_evaluations"]


@pytest.mark.parametrize("evaluations", [
    [], [{}], [{"ComplianceStatus": "PENDING"}], [{"ComplianceStatus": None}],
    [None], {"ComplianceStatus": "COMPLIANT"},
])
def test_empty_missing_unknown_and_malformed_results_are_unknown(evaluations):
    assert evaluate([one_row(evaluations)])[0] == "UNKNOWN"


def test_missing_result_field_and_missing_account_are_unknown():
    policy = one_row([{"ComplianceStatus": "COMPLIANT"}])
    del policy["ComplianceStatus"]["items"][0]["EvaluationResults"]
    assert evaluate([policy])[0] == "UNKNOWN"
    policy = one_row([{"ComplianceStatus": "COMPLIANT"}])
    del policy["ComplianceStatus"]["items"][0]["MemberAccount"]
    assert evaluate([policy])[0] == "UNKNOWN"


def test_unavailable_or_empty_policy_status_is_unknown():
    policy = _fms_policy()
    assert evaluate([policy])[0] == "UNKNOWN"
    policy["ComplianceStatus"] = {"collection_status": "denied"}
    assert evaluate([policy])[0] == "UNKNOWN"


def test_complete_empty_policy_inventory_is_not_applicable_but_denial_unknown():
    assert evaluate([])[0] == "NOT_APPLICABLE"
    assert evaluate([], "denied")[0] == "UNKNOWN"
