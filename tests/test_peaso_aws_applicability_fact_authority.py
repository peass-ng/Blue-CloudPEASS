"""AWS applicability branches require readable selected native fields."""
import pytest
from peaso.checks import evaluate_check
from peaso.checks.compliance_new_aws_apigateway import CACHE_ID
from tests.test_peaso_compliance_new_aws_apigateway import stage, evaluate

@pytest.mark.parametrize("marker", [None, {"status": "denied"}, {"status": "empty"}])
def test_rds_unreadable_replica_identity_cannot_skip_retention(marker):
    item = {"BackupRetentionPeriod": 0, "ReadReplicaSourceDBInstanceIdentifier": "primary",
            "_coverage": {"ReadReplicaSourceDBInstanceIdentifier": marker}}
    assert evaluate_check("aws.rds.backups", item)[0] == "UNKNOWN"

@pytest.mark.parametrize("value", [None, [], {}])
def test_rds_malformed_replica_identity_is_unknown(value):
    assert evaluate_check("aws.rds.backups", {"BackupRetentionPeriod": 7,
        "ReadReplicaSourceDBInstanceIdentifier": value})[0] == "UNKNOWN"

@pytest.mark.parametrize("marker", [None, {"status": "denied"}, {"status": "empty"}])
def test_cache_cluster_availability_must_be_readable(marker):
    row = stage(_coverage={"cacheClusterStatus": marker})
    assert evaluate(CACHE_ID, row)[0] == "UNKNOWN"


def test_disabled_cache_explicit_null_status_is_unknown():
    row = stage(cacheClusterEnabled=False, cacheClusterStatus=None)
    assert evaluate(CACHE_ID, row)[0] == "UNKNOWN"


def test_native_omission_and_confirmed_applicability_are_preserved():
    assert evaluate_check("aws.rds.backups", {"BackupRetentionPeriod": 7})[0] == "PASS"
    assert evaluate_check("aws.rds.backups", {"BackupRetentionPeriod": 0})[0] == "FAIL"
    assert evaluate_check("aws.rds.backups", {"BackupRetentionPeriod": 0,
        "ReadReplicaSourceDBInstanceIdentifier": "primary"})[0] == "NOT_APPLICABLE"
    row = stage(cacheClusterEnabled=False);row.pop("cacheClusterStatus")
    assert evaluate(CACHE_ID, row)[0] == "NOT_APPLICABLE"
    assert evaluate(CACHE_ID, stage())[0] == "PASS"


def test_confirmed_empty_omitted_native_fields_keep_documented_behavior():
    for days,wanted in [(7,"PASS"),(0,"FAIL")]:
        item = {"BackupRetentionPeriod": days, "_coverage": {
            "ReadReplicaSourceDBInstanceIdentifier": {"status": "empty"}}}
        assert evaluate_check("aws.rds.backups", item)[0] == wanted
    row = stage(cacheClusterEnabled=False, _coverage={"cacheClusterStatus": {"status": "empty"}})
    row.pop("cacheClusterStatus")
    assert evaluate(CACHE_ID, row)[0] == "NOT_APPLICABLE"

@pytest.mark.parametrize("marker,wanted", [(None,"UNKNOWN"), ({"status":"denied"},"UNKNOWN"), ({"status":"collected"},"UNKNOWN"), ({"status":"empty"},"FAIL")])
def test_log_group_retention_missing_fact_authority(marker, wanted):
    item = {"logGroupName":"audit", "_coverage":{"retentionInDays":marker}}
    assert evaluate_check("aws.logs.retention", item)[0] == wanted


def test_log_group_known_native_retention_results():
    assert evaluate_check("aws.logs.retention", {"logGroupName":"audit"})[0] == "FAIL"
    assert evaluate_check("aws.logs.retention", {"logGroupName":"audit", "retentionInDays":90})[0] == "PASS"
