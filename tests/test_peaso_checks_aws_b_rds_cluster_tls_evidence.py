"""Cluster TLS evidence must match the engine's actual parameter family."""
import copy

import pytest

from peaso.checks import CHECKS


CHECK = next(check for check in CHECKS if check.id == "aws.cb.rds.cluster_tls_parameters")
ARN = "arn:aws:rds:us-east-1:111111111111:cluster:c1"


def cluster(engine, values, version=None):
    item = {"DBClusterArn": ARN, "Engine": engine, "ClusterParameterGroupValues": values}
    if version is not None:
        item["EngineVersion"] = version
    return item


def status(item):
    original = copy.deepcopy(item)
    outcome, _evidence = CHECK.evaluate(item, {})
    assert item == original
    return outcome


@pytest.mark.parametrize("engine,version", [
    ("aurora-postgresql", None), ("postgres", "13.4"),
    ("postgres", "13.7"), ("postgres", "14.5"), ("postgres", "18.0"),
])
@pytest.mark.parametrize("value,expected", [
    ("1", "PASS"), ("0", "FAIL"), ("ON", "UNKNOWN"),
    ("OFF", "UNKNOWN"), ("true", "UNKNOWN"), (1, "UNKNOWN"),
])
def test_postgresql_cluster_force_ssl_only(engine, version, value, expected):
    item = cluster(engine, {"rds.force_ssl": value, "require_secure_transport": "ON"}, version)
    assert status(item) == expected


@pytest.mark.parametrize("engine,version", [
    ("aurora-mysql", None), ("mysql", "8.0.40"), ("mysql", "8.4.6"),
])
@pytest.mark.parametrize("value,expected", [
    ("ON", "PASS"), ("1", "PASS"), ("OFF", "FAIL"),
    ("0", "FAIL"), ("on", "UNKNOWN"), ("TRUE", "UNKNOWN"),
    ("", "UNKNOWN"), (True, "UNKNOWN"),
])
def test_mysql_cluster_secure_transport_only(engine, version, value, expected):
    item = cluster(engine, {"require_secure_transport": value, "rds.force_ssl": "1"}, version)
    assert status(item) == expected


@pytest.mark.parametrize("item", [
    cluster("aurora-postgresql", {}),
    cluster("aurora-mysql", {"rds.force_ssl": "1"}),
    cluster("postgres", {"require_secure_transport": "ON"}, "15.4"),
    cluster("mysql", {"rds.force_ssl": "1"}, "8.0.40"),
    cluster("aurora-mysql", {"require_secure_transport": None}),
    cluster("aurora-mysql", []),
    cluster("postgres", {"rds.force_ssl": "1"}),
    cluster("mysql", {"require_secure_transport": "ON"}),
    cluster("mysql", {"require_secure_transport": "ON"}, "unparsed"),
    cluster("mysql", {"require_secure_transport": "ON"}, "8.2.0"),
    cluster("mysql", {"require_secure_transport": "ON"}, "9.0.0"),
    cluster("postgres", {"rds.force_ssl": "1"}, "19.0"),
])
def test_missing_malformed_or_unparsed_evidence_is_unknown(item):
    assert status(item) == "UNKNOWN"


def test_denied_cluster_parameter_coverage_is_unknown():
    item = cluster("aurora-mysql", {"require_secure_transport": "ON"})
    item["_coverage"] = {"ClusterParameterGroupValues": {"status": "denied"}}
    assert status(item) == "UNKNOWN"
    item = cluster("aurora-postgresql", {"rds.force_ssl": "1",
                                         "_coverage": {"rds.force_ssl": {"status": "denied"}}})
    assert status(item) == "UNKNOWN"


@pytest.mark.parametrize("engine,version", [
    ("docdb", None), ("neptune", None), ("aurora", None),
    ("mariadb", "11.8"), ("mysql", "5.7.44"),
    ("postgres", "12.20"),
    ("postgres", "13.6"), ("postgres", "14.4"),
])
def test_unsupported_cluster_engine_or_version_is_not_applicable(engine, version):
    assert status(cluster(engine, {}, version)) == "NOT_APPLICABLE"
