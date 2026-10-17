"""Source SQL date filters, joins, NULL and applicability truth cases."""
import copy

import pytest

from peaso.checks import CHECKS, aws_a_cloudtrail_variants as rules
from peaso.checks.fixtures import CASES
from peaso.checks.aws_a_facts import scope_fixture

REGISTRY = {c.id: c for c in CHECKS if c.id in rules.NATIVE_IDS}


@pytest.mark.parametrize("cid", sorted(REGISTRY))
def test_variants_real_states_preserve_snapshot_input(cid):
    check, cases = REGISTRY[cid], CASES[cid]
    for state, expected in (("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN")):
        item = copy.deepcopy(cases[state])
        index = copy.deepcopy(cases.get(state + "_index", cases.get("index", {})))
        before = copy.deepcopy((item, index))
        assert check.evaluate(item, index)[0] == expected
        assert (item, index) == before
    assert check.evaluate({"collection_status": "denied"}, {})[0] == "UNKNOWN"
    if "not_applicable" in cases:
        assert check.evaluate(cases["not_applicable"], {})[0] == "NOT_APPLICABLE"


@pytest.mark.parametrize("cid", ["aws.a.cloudtrail.home_cloudwatch_date", "aws.a.cloudtrail.home_multiregion_cloudwatch_date"])
def test_previous_date_is_not_rolling_24_hours_and_exact_boundary_fails(cid):
    item = copy.deepcopy(CASES[cid]["pass"])
    check = REGISTRY[cid]
    assert check.evaluate(item, rules.CLOCK)[0] == "PASS"  # 36hours old is after previous midnight.
    item["Status"]["LatestCloudWatchLogsDeliveryTime"] = "2026-10-09T00:00:00+00:00"
    assert check.evaluate(item, rules.CLOCK)[0] == "FAIL"
    item["Status"] = {"collection_status": "collected"}
    assert check.evaluate(item, rules.CLOCK)[0] == "FAIL"
    item["Status"] = {"collection_status": "denied"}
    assert check.evaluate(item, rules.CLOCK)[0] == "UNKNOWN"
    item["CloudWatchLogsLogGroupArn"] = ""
    assert check.evaluate(item, rules.CLOCK)[0] == "FAIL"


def test_multiregion_only_variant_does_not_cover_single_region_source():
    cid = "aws.a.cloudtrail.home_multiregion_cloudwatch_date"
    item = {**CASES[cid]["pass"], "IsMultiRegionTrail": False}
    assert REGISTRY[cid].evaluate(item, rules.CLOCK)[0] == "NOT_APPLICABLE"
    assert REGISTRY["aws.a.cloudtrail.home_cloudwatch_date"].evaluate(item, rules.CLOCK)[0] == "PASS"


def test_logging_disabled_is_failure_even_when_additional_insights_fact_denied():
    item = {**rules.BASE, "Status": {"IsLogging": False}, "InsightSelectors": {"collection_status": "denied"}}
    check = REGISTRY["aws.a.cloudtrail.home_logging_with_insights"]
    assert check.evaluate(item, {})[0] == "FAIL"
    item["Status"]["IsLogging"] = True
    assert check.evaluate(item, {})[0] == "UNKNOWN"


def test_finite_retention_and_indefinite_allowed_variant_are_distinct():
    item = {"logGroupName": "audit", "_provenance": rules.LOG_PROVENANCE}
    assert REGISTRY["aws.a.cloudwatch.finite_retention_365"].evaluate(item, {})[0] == "FAIL"
    from peaso.checks.aws_a_cloudwatch import retention
    assert retention(item, {})[0] == "PASS"


def test_bucket_inner_join_excludes_outside_inventory_but_denial_is_unknown():
    cid = "aws.a.cloudtrail.home_bucket_access_logging"
    item = CASES[cid]["pass"]
    index = {**scope_fixture("bucket", []), "context": {"scope": "123456789012/us-east-1"}}
    assert REGISTRY[cid].evaluate(item, index)[0] == "NOT_APPLICABLE"
    index["collections"]["bucket"][0]["status"] = "denied"
    assert REGISTRY[cid].evaluate(item, index)[0] == "UNKNOWN"


def test_bucket_public_source_declared_policy_group_and_missing_dependency_are_separate():
    cid = "aws.a.cloudtrail.joined_bucket_declared_public_grants"
    check = REGISTRY[cid];item = CASES[cid]["pass"]
    bucket = copy.deepcopy(rules.PRIVATE_BUCKET)
    bucket["Policy"] = {"Policy": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::audit-bucket/*", "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-inert12345"}}}]}}
    index = {**scope_fixture("bucket", [bucket]), "context": {"scope": "123456789012/us-east-1"}}
    # The source is a declared wildcard-principal lint, not an effective public
    # access test: its SQL does not consult conditions or Public Access Block.
    assert check.evaluate(item, index)[0] == "FAIL"
    bucket["Policy"] = {"collection_status": "denied"}
    assert check.evaluate(item, index)[0] == "UNKNOWN"
    bucket["Acl"] = rules.PUBLIC_BUCKET["Acl"]
    assert check.evaluate(item, index)[0] == "FAIL"
    index["collections"]["bucket"][0].update(status="empty", items=[])
    assert check.evaluate(item, index)[0] == "NOT_APPLICABLE"


def test_mfa_source_leftjoin_failure_keeps_remote_fact_unknown_and_denial_unknown():
    cid="aws.a.cloudtrail.home_bucket_mfa_join";check=REGISTRY[cid];item=CASES[cid]["pass"]
    index={**scope_fixture("bucket",[]),"context":{"scope":"123456789012/us-east-1"}}
    state,evidence=check.evaluate(item,index)
    assert state=="FAIL" and evidence["remote_mfa_delete"]=="unknown"
    index["collections"]["bucket"][0]["status"]="denied"
    assert check.evaluate(item,index)[0]=="UNKNOWN"
