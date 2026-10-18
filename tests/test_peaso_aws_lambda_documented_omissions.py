"""Documented Lambda absence is a known default, not unavailable evidence."""
import copy
import pytest
from peaso.checks import evaluate_check
from peaso.collectors.aws import _documented_omission
from peaso.collectors.aws_lambda_omission_native import normalize_documented_omissions


def fixture():
    item = {"FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:fixture",
            "Configuration": {"collection_status": "collected"}}
    _documented_omission(item, "VpcConfig", {"VpcId": ""}, "lambda:GetFunctionConfiguration")
    return item


@pytest.mark.parametrize("ident,expected", [("aws.lambda.vpc_configuration", "FAIL"), ("aws.cb.lambda.vpc_multiple_az", "NOT_APPLICABLE")])
def test_native_no_vpc_default_has_a_conclusive_native_result(ident, expected):
    item = fixture()
    assert evaluate_check(ident, item, {})[0] == "UNKNOWN"  # Original contradiction.
    normalize_documented_omissions(item)
    assert evaluate_check(ident, item, {})[0] == expected
    assert item["_coverage"]["VpcConfig"]["reason"] == "documented_optional_api_omission"


@pytest.mark.parametrize("mutation", ["denied", "partial", "wrong_operation", "undocumented", "contradictory", "missing_value"])
def test_unavailable_or_inconsistent_omission_is_not_normalized(mutation):
    item = fixture()
    if mutation in {"denied", "partial"}:
        item["Configuration"]["collection_status"] = mutation
    elif mutation == "wrong_operation":
        item["_coverage"]["VpcConfig"]["source_operation"] = "other:Read"
    elif mutation == "undocumented":
        item["_coverage"]["VpcConfig"]["reason"] = "missing_field"
    elif mutation == "contradictory":
        item["VpcConfig"] = {"VpcId": "vpc-existing"}
    else:
        item.pop("VpcConfig")
    original = copy.deepcopy(item)
    normalize_documented_omissions(item)
    assert item == original


def test_explicit_empty_vpc_object_keeps_documented_scalar_default_and_dead_letter():
    item = {"Configuration": {"collection_status": "collected"}, "VpcConfig": {}}
    _documented_omission(item["VpcConfig"], "VpcId", "", "lambda:GetFunctionConfiguration")
    _documented_omission(item, "DeadLetterConfig", {}, "lambda:GetFunctionConfiguration")
    normalize_documented_omissions(item)
    assert item["VpcConfig"]["_coverage"]["VpcId"]["status"] == "collected"
    assert item["_coverage"]["DeadLetterConfig"]["status"] == "collected"
    assert evaluate_check("aws.lambda.vpc_configuration", item, {})[0] == "FAIL"
