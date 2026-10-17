"""Observed backup defaults and Aurora Backtrack applicability, without cloud calls."""
from __future__ import annotations

import pytest

from peaso.checks import CHECKS


REGISTRY = {check.id: check for check in CHECKS}
RETENTION = REGISTRY["aws.c2b.elasticache.rg_backup_retention_15"]
BACKTRACK = REGISTRY["aws.cb.rds.aurora_backtracking_configured"]
PROWLER_BACKTRACK = REGISTRY["aws.cb.rds.cluster_backtrack_window_positive"]
GROUP_ARN = "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:rg1"
CLUSTER_ARN = "arn:aws:rds:us-east-1:123456789012:cluster:db1"
FULL_GROUP = {"operation": "elasticache:DescribeReplicationGroups", "native_response_complete": True}


@pytest.mark.parametrize("value,expected", [(15, "PASS"), (20, "PASS"), (14, "FAIL"), (0, "FAIL")])
def test_observed_retention_boundary(value, expected):
    assert RETENTION.evaluate({"ARN": GROUP_ARN, "SnapshotRetentionLimit": value}, {})[0] == expected


def test_omitted_retention_requires_complete_describe_response():
    full = {"ARN": GROUP_ARN, "_provenance": FULL_GROUP}
    assert RETENTION.evaluate(full, {}) == ("FAIL", {"snapshot_retention_limit": 0})
    for item in (
        {"ARN": GROUP_ARN},
        {"ARN": GROUP_ARN, "_provenance": {"operation": "elasticache:DescribeReplicationGroups"}},
        {"ARN": GROUP_ARN, "_provenance": {"operation": "other", "native_response_complete": True}},
        {"ARN": GROUP_ARN, "_coverage": {"SnapshotRetentionLimit": {"status": "denied"}}},
        {"ARN": GROUP_ARN, "SnapshotRetentionLimit": None},
        {"ARN": GROUP_ARN, "SnapshotRetentionLimit": "15"},
        {"ARN": GROUP_ARN, "SnapshotRetentionLimit": -1},
        {"ARN": GROUP_ARN, "collection_status": "denied", "_provenance": FULL_GROUP},
    ):
        assert RETENTION.evaluate(item, {})[0] == "UNKNOWN", item


def cluster(version="8.0.mysql_aurora.3.08.2", region="us-east-1", window=86400, engine="aurora-mysql"):
    return {"DBClusterArn": CLUSTER_ARN.replace("us-east-1", region), "Engine": engine,
            "EngineVersion": version, "BacktrackWindow": window}


@pytest.mark.parametrize("window,expected", [(86400, "PASS"), (1, "PASS"), (0, "FAIL")])
def test_backtrack_window_boundary(window, expected):
    assert BACKTRACK.evaluate(cluster(window=window), {})[0] == expected


@pytest.mark.parametrize("version", ["5.7.mysql_aurora.2.12.3", "8.0.mysql_aurora.3.08.2", "8.4.mysql_aurora.8.4.7"])
def test_documented_supported_aurora_versions(version):
    assert BACKTRACK.evaluate(cluster(version=version), {})[0] == "PASS"


@pytest.mark.parametrize("item,expected", [
    (cluster(engine="aurora-postgresql"), "NOT_APPLICABLE"),
    (cluster(engine="postgres"), "NOT_APPLICABLE"),
    (cluster(version="5.6.mysql_aurora.1.22.5"), "NOT_APPLICABLE"),
    (cluster(region="eu-south-2"), "NOT_APPLICABLE"),
    (cluster(version="5.7.mysql_aurora.2.07.2", region="ap-northeast-3"), "NOT_APPLICABLE"),
    (cluster(version="5.7.mysql_aurora.2.07.3", region="ap-northeast-3"), "PASS"),
    (cluster(version="8.4.mysql_aurora.8.4.7", region="ap-northeast-3"), "PASS"),
    (cluster(version="8.4.mysql_aurora.9.0.0"), "UNKNOWN"),
    (cluster(region="ap-south-2"), "UNKNOWN"),
    ({"DBClusterArn": CLUSTER_ARN, "Engine": "aurora-mysql", "BacktrackWindow": 0}, "UNKNOWN"),
    ({"DBClusterArn": CLUSTER_ARN, "Engine": "aurora-mysql", "EngineVersion": "8.0.mysql_aurora.3.08.2"}, "UNKNOWN"),
    ({**cluster(window=0), "collection_status": "denied"}, "UNKNOWN"),
    ({**cluster(), "BacktrackWindow": "86400"}, "UNKNOWN"),
    (cluster(window=-1), "UNKNOWN"),
])
def test_backtrack_engine_version_region_and_evidence(item, expected):
    assert BACKTRACK.evaluate(item, {})[0] == expected


@pytest.mark.parametrize("item", [
    cluster(window=86400), cluster(window=0), cluster(version="5.7.mysql_aurora.2.07.3", region="ap-northeast-3"),
    cluster(version="5.7.mysql_aurora.2.07.2", region="ap-northeast-3"), cluster(region="eu-south-2"),
    cluster(region="ap-south-2"), cluster(version="8.4.mysql_aurora.9.0.0"),
    cluster(engine="aurora-postgresql"), {"DBClusterArn": CLUSTER_ARN, "Engine": "aurora-mysql"},
    {**cluster(), "collection_status": "denied"},
])
def test_backtrack_predicates_share_exact_applicability_and_evidence(item):
    assert PROWLER_BACKTRACK.evaluate(item, {}) == BACKTRACK.evaluate(item, {})


def test_replication_group_collector_marks_only_complete_responses(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber
    from peaso.collectors import aws

    account, region = "123456789012", "us-east-1"
    identity = {"Account": account, "Arn": f"arn:aws:iam::{account}:user/reviewer", "UserId": "AIDAREVIEWER"}
    session = boto3.Session(aws_access_key_id="fixture-key", aws_secret_access_key="fixture-secret", region_name=region)
    sts = session.client("sts", region_name=region)
    elasticache = session.client("elasticache", region_name=region)
    stubs = [Stubber(sts), Stubber(elasticache)]
    for stub in stubs:
        stub.activate()
    clients = {("sts", region): sts, ("elasticache", region): elasticache}
    monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, selected_region: clients[(service, selected_region)])
    monkeypatch.setattr(aws, "_session", lambda auth, selected_region: (session, "fixture"))

    def collect_once():
        stubs[0].add_response("get_caller_identity", identity, {})
        snapshot = aws.collect({"provider": "aws", "scopes": [account], "auth": {"profile": "fixture"},
                                "options": {"regions": [region], "service_concurrency": 1}}, ["elasticache_replication_group"])
        return next(c for c in snapshot["collections"] if c["type"] == "elasticache_replication_group")

    row = {"ReplicationGroupId": "rg1", "Description": "fixture", "Status": "available", "ARN": GROUP_ARN}
    try:
        stubs[1].add_response("describe_replication_groups", {"ReplicationGroups": [row]}, {})
        complete = collect_once()
        assert complete["status"] == "collected"
        assert complete["items"][0]["_provenance"] == FULL_GROUP
        assert RETENTION.evaluate(complete["items"][0], {})[0] == "FAIL"

        stubs[1].add_response("describe_replication_groups", {"ReplicationGroups": [row], "Marker": "page-2"}, {})
        stubs[1].add_client_error("describe_replication_groups", "AccessDenied", expected_params={"Marker": "page-2"})
        partial = collect_once()
        assert partial["status"] == "partial"
        assert "_provenance" not in partial["items"][0]
        assert RETENTION.evaluate(partial["items"][0], {})[0] == "UNKNOWN"

        stubs[1].add_client_error("describe_replication_groups", "AccessDenied", expected_params={})
        denied = collect_once()
        assert denied["status"] == "denied" and not denied["items"]
        for stub in stubs:
            stub.assert_no_pending_responses()
    finally:
        for stub in stubs:
            stub.deactivate()
