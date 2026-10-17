"""RDS parameter strings and feature scope observed by the native checks."""
import copy

import pytest

from peaso.checks import CHECKS


CHECK_BY_ID = {check.id: check for check in CHECKS}
INSTANCE = "aws.cb.rds.instance_tls_parameters"
MARIADB = "aws.cb.rds.mariadb_require_secure_transport"
AURORA_AUDIT = "aws.cb.rds.aurora_mysql_server_audit_logging"


def evaluate(check_id, item):
    original = copy.deepcopy(item)
    status, _evidence = CHECK_BY_ID[check_id].evaluate(item, {})
    assert item == original
    return status


@pytest.mark.parametrize("check_id,engine,version", [
    (INSTANCE, "mysql", "8.0.40"),
    (INSTANCE, "mariadb", "10.11.8"),
    (MARIADB, "mariadb", "10.11.8"),
])
@pytest.mark.parametrize("value,expected", [
    ("1", "PASS"), ("ON", "PASS"),
    ("0", "FAIL"), ("OFF", "FAIL"),
    ("TRUE", "UNKNOWN"), ("", "UNKNOWN"), ("on", "UNKNOWN"),
    (1, "UNKNOWN"), (True, "UNKNOWN"), (None, "UNKNOWN"),
])
def test_secure_transport_documented_strings_only(check_id, engine, version, value, expected):
    item = {"DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:db1", "Engine": engine,
            "EngineVersion": version, "ParameterGroupValues": {"require_secure_transport": value}}
    assert evaluate(check_id, item) == expected


@pytest.mark.parametrize("check_id", [INSTANCE, MARIADB])
def test_missing_or_denied_parameter_is_unknown(check_id):
    item = {"DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:db1", "Engine": "mariadb",
            "EngineVersion": "11.8.1", "ParameterGroupValues": {}}
    assert evaluate(check_id, item) == "UNKNOWN"
    item["_coverage"] = {"ParameterGroupValues": {"status": "denied"}}
    assert evaluate(check_id, item) == "UNKNOWN"


@pytest.mark.parametrize("check_id", [INSTANCE, MARIADB])
def test_mariadb_version_scope(check_id):
    item = {"DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:db1", "Engine": "mariadb",
            "EngineVersion": "10.4.34", "ParameterGroupValues": {"require_secure_transport": "OFF"}}
    assert evaluate(check_id, item) == "NOT_APPLICABLE"
    item["EngineVersion"] = "unknown"
    assert evaluate(check_id, item) == "UNKNOWN"
    del item["EngineVersion"]
    assert evaluate(check_id, item) == "UNKNOWN"


def test_instance_scope_and_pg_parameter_remain_distinct():
    base = {"DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:db1", "Engine": "mysql",
            "ParameterGroupValues": {"require_secure_transport": "ON"}}
    assert evaluate(INSTANCE, base) == "PASS"
    assert evaluate(INSTANCE, {**base, "DBClusterIdentifier": "cluster-1"}) == "NOT_APPLICABLE"
    assert evaluate(INSTANCE, {**base, "Engine": "oracle-ee"}) == "NOT_APPLICABLE"
    assert evaluate(INSTANCE, {**base, "Engine": "mysql-fake"}) == "NOT_APPLICABLE"
    pg = {**base, "Engine": "postgres", "ParameterGroupValues": {"rds.force_ssl": "1"}}
    assert evaluate(INSTANCE, pg) == "PASS"
    assert evaluate(INSTANCE, {**pg, "ParameterGroupValues": {"rds.force_ssl": "0"}}) == "FAIL"
    assert evaluate(INSTANCE, {**pg, "ParameterGroupValues": {"rds.force_ssl": "ON"}}) == "UNKNOWN"


@pytest.mark.parametrize("setting,events,expected", [
    ("1", "CONNECT", "PASS"), ("ON", "CONNECT,QUERY_DDL", "PASS"),
    ("0", "CONNECT", "FAIL"), ("OFF", "CONNECT", "FAIL"),
    ("ON", "", "FAIL"), ("ON", " ", "FAIL"),
    ("ON", "CONNECT,UNKNOWN", "UNKNOWN"), ("ON", "CONNECT,", "UNKNOWN"),
    ("ON", "CONNECT, QUERY_DDL", "UNKNOWN"),
    ("ON", "connect", "UNKNOWN"), ("TRUE", "CONNECT", "UNKNOWN"),
])
def test_aurora_audit_selected_event_configuration(setting, events, expected):
    item = {"DBClusterArn": "arn:aws:rds:us-east-1:111111111111:cluster:c1", "Engine": "aurora-mysql",
            "ClusterParameterGroupValues": {"server_audit_logging": setting, "server_audit_events": events}}
    assert evaluate(AURORA_AUDIT, item) == expected


def test_aurora_audit_missing_or_denied_and_engine_scope():
    item = {"DBClusterArn": "arn:aws:rds:us-east-1:111111111111:cluster:c1", "Engine": "aurora-mysql",
            "ClusterParameterGroupValues": {"server_audit_logging": "ON"}}
    assert evaluate(AURORA_AUDIT, item) == "UNKNOWN"
    item["_coverage"] = {"ClusterParameterGroupValues": {"status": "denied"}}
    assert evaluate(AURORA_AUDIT, item) == "UNKNOWN"
    assert evaluate(AURORA_AUDIT, {**item, "Engine": "aurora-postgresql"}) == "NOT_APPLICABLE"
