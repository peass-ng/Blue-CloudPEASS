"""Mixed policy statements and scan rules must keep their own conditions."""
from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.checks import CHECKS
from peaso.checks import claude2_aws_b_analytics as analytics
from peaso.checks import claude2_aws_b_devtools as devtools


REGISTRY = {check.id: check for check in CHECKS}
ECR = REGISTRY["aws.c2b.ecr.registry_automated_scanning"]
EFS = REGISTRY["aws.c2b.efs.policy_not_open_to_vpc_clients"]
ALL = {"filter": "*", "filterType": "WILDCARD"}
PROD = {"filter": "prod-*", "filterType": "WILDCARD"}


def ecr_evaluate(scan_type, rules, *, status="collected"):
    configuration = {"registryId": "111111111111", "scanningConfiguration": {"scanType": scan_type}}
    if rules is not None:
        configuration["scanningConfiguration"]["rules"] = rules
    index = devtools.indexes(devtools.inventory("ecr_registry_scanning_configuration", [configuration], status), devtools._REPOS)
    before = deepcopy(index)
    outcome = ECR.evaluate(deepcopy(devtools.ANCHOR), index)
    assert index == before
    return outcome[0]


def rule(frequency, filters):
    return {"scanFrequency": frequency, "repositoryFilters": filters}


def test_ecr_automatic_wildcard_must_belong_to_an_automatic_rule():
    assert ecr_evaluate("ENHANCED", [rule("MANUAL", [ALL]), rule("SCAN_ON_PUSH", [PROD])]) == "FAIL"
    assert ecr_evaluate("ENHANCED", [rule("SCAN_ON_PUSH", [PROD]), rule("CONTINUOUS_SCAN", [ALL])]) == "PASS"
    assert ecr_evaluate("BASIC", [rule("SCAN_ON_PUSH", [ALL])]) == "PASS"
    assert ecr_evaluate("BASIC", [rule("MANUAL", [ALL])]) == "FAIL"


def test_ecr_documented_no_rule_defaults_require_observed_complete_rules():
    assert ecr_evaluate("ENHANCED", []) == "PASS"
    assert ecr_evaluate("BASIC", []) == "FAIL"
    assert ecr_evaluate("ENHANCED", None) == "UNKNOWN"
    assert ecr_evaluate("ENHANCED", [], status="partial") == "UNKNOWN"
    assert ecr_evaluate("ENHANCED", [], status="denied") == "UNKNOWN"


@pytest.mark.parametrize("scan_type,rules", [
    ("FUTURE", []),
    ("BASIC", [rule("CONTINUOUS_SCAN", [ALL])]),
    ("ENHANCED", [rule("SCAN_ON_PUSH", [{"filter": "*", "filterType": "FUTURE"}])]),
    ("ENHANCED", [rule("SCAN_ON_PUSH", [{"filterType": "WILDCARD"}])]),
    ("ENHANCED", [rule("SCAN_ON_PUSH", [])]),
    ("ENHANCED", [{"scanFrequency": "SCAN_ON_PUSH"}]),
])
def test_ecr_malformed_or_unrecognized_rules_are_unknown(scan_type, rules):
    assert ecr_evaluate(scan_type, rules) == "UNKNOWN"


def efs_evaluate(policy):
    item = analytics._fs(policy=policy)
    before = deepcopy(item)
    outcome = EFS.evaluate(item, {"context": dict(analytics.CONTEXT)})
    assert item == before
    return outcome[0]


def allow(principal, condition=None):
    statement = {"Effect": "Allow", "Principal": {"AWS": principal},
                 "Action": "elasticfilesystem:ClientMount", "Resource": analytics.FS_ARN}
    if condition is not None:
        statement["Condition"] = condition
    return statement


MOUNT = {"Bool": {"elasticfilesystem:AccessedViaMountTarget": "true"}}
PUBLIC = allow("*")
CONSTRAINED = allow("*", MOUNT)
PRIVATE = allow("arn:aws:iam::111111111111:role/app")
DENY = {"Effect": "Deny", "Principal": {"AWS": "*"}, "Action": "elasticfilesystem:ClientMount", "Resource": analytics.FS_ARN}


def test_efs_unrelated_statements_do_not_defeat_mount_target_condition():
    assert efs_evaluate({"Statement": [CONSTRAINED]}) == "PASS"
    assert efs_evaluate({"Statement": [CONSTRAINED, DENY]}) == "PASS"
    assert efs_evaluate({"Statement": [CONSTRAINED, PRIVATE]}) == "PASS"
    assert efs_evaluate({"Statement": [CONSTRAINED, PUBLIC]}) == "FAIL"
    assert efs_evaluate({"Statement": [PUBLIC]}) == "FAIL"


def test_efs_missing_and_unavailable_policy_or_unsupported_condition():
    assert EFS.evaluate(analytics._fs(), {"context": dict(analytics.CONTEXT)})[0] == "FAIL"
    item = analytics._fs(policy={"Statement": [PUBLIC]})
    item["Policy"] = {"collection_status": "denied"}
    assert EFS.evaluate(item, {"context": dict(analytics.CONTEXT)})[0] == "UNKNOWN"
    assert efs_evaluate({"Statement": [allow("*", {"Bool": {"elasticfilesystem:AccessedViaMountTarget": "maybe"}})]}) == "UNKNOWN"
    assert efs_evaluate({"Statement": [allow("*", {"BoolIfExists": {"elasticfilesystem:AccessedViaMountTarget": "true"}})]}) == "UNKNOWN"


@pytest.mark.parametrize("value", [1, 0, 1.0, 0.0, None, [], {}])
def test_efs_numeric_and_structural_bool_condition_values_remain_unknown(value):
    condition = {"Bool": {"elasticfilesystem:AccessedViaMountTarget": value}}
    assert efs_evaluate({"Statement": [allow("*", condition)]}) == "UNKNOWN"
