"""AWS-B source semantics and immutable positive/negative metadata facts."""
import copy
import pytest
from peaso.checks import CHECKS, HACKTRICKS
from peaso.checks import aws_b_core, aws_b_loadbalancing, aws_b_regional, aws_b_cloudfront, aws_b_storage, aws_b_compute
from peaso.checks.fixtures import CASES
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


@pytest.mark.parametrize("cid", aws_b_core.IDS)
def test_first_wave_native_predicates(cid):
    check = next(c for c in CHECKS if c.id == cid)
    cases = CASES[cid]
    for label, expected in [("pass", "PASS"), ("fail", "FAIL"), ("manual", "MANUAL"), ("not_applicable", "NOT_APPLICABLE")]:
        if label not in cases:
            continue
        item, index = copy.deepcopy(cases[label]), copy.deepcopy(cases.get(label + "_index", cases.get("index", {})))
        original = copy.deepcopy(item)
        assert check.evaluate(item, index)[0] == expected
        assert item == original
    for bad in ({}, None, {"collection_status": "denied"}, {"_coverage": []}):
        assert check.evaluate(bad, {})[0] == "UNKNOWN"
    assert HACKTRICKS in check.frameworks


def test_eks_version_default_encryption_and_pre_128_requirements():
    check = next(c for c in CHECKS if c.id == "aws.b.eks.secret_envelope_encryption")
    for version in ("1.28", "1.35", "2.0"):
        assert check.evaluate({"Cluster": {"cluster": {"version": version}}}, {})[0] == "PASS"
    assert check.evaluate({"Cluster": {"cluster": {"version": "1.27"}}}, {})[0] == "UNKNOWN"
    assert check.evaluate({"Cluster": {"cluster": {"version": "1.27", "encryptionConfig": [{"resources": ["secrets"]}]}}}, {})[0] == "PASS"
    assert check.evaluate({"Cluster": {"cluster": {"version": "1.27", "encryptionConfig": [{"resources": ["other"]}]}}}, {})[0] == "FAIL"
    assert check.evaluate({"Cluster": {"cluster": {"version": "invented", "encryptionConfig": []}}}, {})[0] == "UNKNOWN"


def test_lambda_concurrency_zero_is_configured_and_denied_is_unknown():
    check = next(c for c in CHECKS if c.id == "aws.b.lambda.reserved_concurrency")
    assert check.evaluate({"Concurrency": {"ReservedConcurrentExecutions": 0}}, {})[0] == "PASS"
    assert check.evaluate({"Concurrency": {}}, {})[0] == "FAIL"
    assert check.evaluate({"Concurrency": {"collection_status": "denied"}}, {})[0] == "UNKNOWN"
    assert check.evaluate({"Concurrency": {"ReservedConcurrentExecutions": -1}}, {})[0] == "UNKNOWN"


def test_rds_engine_eligibility_and_all_required_categories():
    check = next(c for c in CHECKS if c.id == "aws.b.rds.engine_log_exports")
    assert check.evaluate({"Engine": "sqlserver-ex", "EnabledCloudwatchLogsExports": ["error"]}, {})[0] == "PASS"
    assert check.evaluate({"Engine": "sqlserver-se", "EnabledCloudwatchLogsExports": ["error"]}, {})[0] == "FAIL"
    assert check.evaluate({"Engine": "sqlserver-se", "EnabledCloudwatchLogsExports": ["error", "agent"]}, {})[0] == "PASS"
    assert check.evaluate({"Engine": "docdb"}, {})[0] == "NOT_APPLICABLE"
    assert check.evaluate({"Engine": "oracle-ee", "EnabledCloudwatchLogsExports": ["alert", "audit", "trace", "listener"]}, {})[0] == "PASS"


def test_join_cannot_pass_on_partial_vpc_or_foreign_scope():
    cid = "aws.b.eks.no_default_vpc"
    check = next(c for c in CHECKS if c.id == cid)
    item = {"Cluster": {"cluster": {"resourcesVpcConfig": {"vpcId": "same-name"}}}}
    assert check.evaluate(item, {"collections": {"vpc": [{"status": "partial"}]}, "vpc": [{"data": {"VpcId": "same-name", "IsDefault": False}}]})[0] == "UNKNOWN"
    scope = "111111111111/us-east-1"
    snapshot = make_snapshot("aws", [scope], [
        {"type": "eks_cluster", "scope": scope, "status": "collected", "items": [item]},
        {"type": "vpc", "scope": "222222222222/us-east-1", "status": "collected", "items": [{"VpcId": "same-name", "IsDefault": False}]}])
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[cid])
    assert report["findings"][0]["status"] == "UNKNOWN"


def test_cors_exact_source_equality_is_not_silently_broadened():
    check = next(c for c in CHECKS if c.id == "aws.b.lambda.url_cors_single_wildcard")
    assert check.evaluate({"FunctionUrl": {"Cors": {"AllowOrigins": ["*", "https://example.test"]}}}, {})[0] == "PASS"
    assert check.evaluate({"FunctionUrl": {"Cors": {"AllowOrigins": ["*"]}}}, {})[0] == "FAIL"
