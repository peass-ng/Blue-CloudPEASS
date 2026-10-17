"""Reviewed CloudWatch truth variants and documented optional omissions."""
import copy

import pytest

from peaso.checks import CHECKS, aws_a_cloudwatch
from peaso.checks.fixtures import CASES
from peaso.checks.aws_a_facts import scope_fixture

REGISTRY = {c.id: c for c in CHECKS if c.id in aws_a_cloudwatch.NATIVE_IDS}


@pytest.mark.parametrize("cid", sorted(REGISTRY))
def test_real_cloudwatch_predicates_have_pass_fail_missing_denied_malformed_and_purity(cid):
    check, cases = REGISTRY[cid], CASES[cid]
    for state, expected in (("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("not_applicable", "NOT_APPLICABLE")):
        if state not in cases:
            continue
        item = copy.deepcopy(cases[state])
        index = copy.deepcopy(cases.get(state + "_index", cases.get("index", {})))
        before = copy.deepcopy((item, index))
        assert check.evaluate(item, index)[0] == expected, (cid, state)
        assert (item, index) == before
    assert check.evaluate({"collection_status": "denied"}, cases.get("index", {}))[0] == "UNKNOWN"


@pytest.mark.parametrize("days,expected", [(30, "FAIL"), (364, "FAIL"), (365, "PASS"), (400, "PASS"), (True, "UNKNOWN"), (0, "UNKNOWN")])
def test_retention_minimum_365_is_distinct_from_existing_finite_retention_presence_rule(days, expected):
    check = REGISTRY["aws.a.cloudwatch.log_retention_at_least_365"]
    assert check.evaluate({"logGroupName": "audit", "retentionInDays": days}, {})[0] == expected


def test_documented_omission_requires_complete_native_operation_proof():
    item = {"logGroupName": "audit", "_provenance": aws_a_cloudwatch.LOG_PROVENANCE}
    assert REGISTRY["aws.a.cloudwatch.log_retention_at_least_365"].evaluate(item, {})[0] == "PASS"
    assert REGISTRY["aws.a.cloudwatch.log_kms_encryption"].evaluate(item, {})[0] == "FAIL"
    assert REGISTRY["aws.a.cloudwatch.log_retention_at_least_365"].evaluate({"logGroupName": "audit"}, {})[0] == "UNKNOWN"
    item["_coverage"] = {"retentionInDays": {"status": "denied"}}
    assert REGISTRY["aws.a.cloudwatch.log_retention_at_least_365"].evaluate(item, {})[0] == "UNKNOWN"


def test_account_role_absence_cannot_pass_if_inventory_unavailable_or_foreign():
    check = REGISTRY["aws.a.cloudwatch.cross_account_role_absent"]
    subject = {"scope": "123456789012/us-east-1"}
    assert check.evaluate(subject, scope_fixture("iam_role", [], status="denied"))[0] == "UNKNOWN"
    assert check.evaluate(subject, scope_fixture("iam_role", [{"RoleName": "OtherRole"}]))[0] == "PASS"
    index = scope_fixture("iam_role", [])
    index["collections"]["iam_role"][0]["account_id"] = "999999999999"
    index["collections"]["iam_role"][0]["scope"] = "999999999999/us-east-1"
    assert check.evaluate(subject, index)[0] == "UNKNOWN"


@pytest.mark.parametrize("status,inherited,expected", [("ACTIVATED", [], "PASS"), ("ARCHIVED", ["ACCOUNT_DATA_PROTECTION"], "PASS"), ("DISABLED", [], "FAIL"), ("DELETED", [], "FAIL"), ("UNKNOWN", [], "UNKNOWN")])
def test_agentcore_local_and_inherited_masking_alternatives(status, inherited, expected):
    item = {"logGroupName": "/aws/vendedlogs/bedrock-agentcore/memory/app", "dataProtectionStatus": status, "inheritedProperties": inherited}
    assert REGISTRY["aws.a.cloudwatch.agentcore_data_protection"].evaluate(item, {})[0] == expected


def test_alarm_action_boolean_and_list_variants_are_independent():
    assert REGISTRY["aws.a.cloudwatch.alarm_actions_enabled"].evaluate({"ActionsEnabled": True}, {})[0] == "PASS"
    assert REGISTRY["aws.a.cloudwatch.alarm_state_actions"].evaluate({"AlarmActions": []}, {})[0] == "FAIL"
    assert REGISTRY["aws.a.cloudwatch.alarm_actions_enabled"].evaluate({"ActionsEnabled": "true"}, {})[0] == "UNKNOWN"
    assert REGISTRY["aws.a.cloudwatch.alarm_state_actions"].evaluate({"AlarmActions": [None]}, {})[0] == "UNKNOWN"


def test_any_state_action_is_separate_from_alarm_state_only_and_action_enablement():
    item = {"AlarmActions": [], "OKActions": ["arn:aws:sns:us-east-1:123456789012:alerts"], "InsufficientDataActions": [], "ActionsEnabled": False}
    assert REGISTRY["aws.a.cloudwatch.any_state_actions"].evaluate(item, {})[0] == "PASS"
    assert REGISTRY["aws.a.cloudwatch.alarm_state_actions"].evaluate(item, {})[0] == "FAIL"
    assert REGISTRY["aws.a.cloudwatch.alarm_actions_enabled"].evaluate(item, {})[0] == "FAIL"
