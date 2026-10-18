"""Helper tests for the claude2_aws_b data group (behaviour fixtures run in test_peaso_checks_claude2_aws_b)."""
import json

import pytest

from peaso.checks import claude2_aws_b_data as data
from peaso.checks.claude2_aws_b_common import Unavailable, IDS


def test_world_open_matches_prowler_all_ports_semantics():
    world = [{"CidrIp": "0.0.0.0/0"}]
    assert data.world_open({"IpProtocol": "-1", "IpRanges": world})
    assert data.world_open({"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": world})
    assert data.world_open({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]})
    assert not data.world_open({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]})
    assert not data.world_open({"IpProtocol": "tcp", "IpRanges": world})


def test_engine_version_parse():
    assert data.engine_version("5.0.6") < (6, 0) <= data.engine_version("6.0") < data.engine_version("6.2.6")
    with pytest.raises(Unavailable):
        data.engine_version("6.x")
    with pytest.raises(Unavailable):
        data.engine_version(None)


def test_task_logging_parse():
    settings = {"Logging": {"EnableLogging": True, "LogComponents": [{"Id": "SOURCE_CAPTURE", "Severity": "LOGGER_SEVERITY_DEBUG"}]}}
    enabled, components = data.task_logging({"ReplicationTaskArn": "a", "ReplicationTaskSettings": json.dumps(settings)})
    assert enabled and components == {"SOURCE_CAPTURE": ["LOGGER_SEVERITY_DEBUG"]}
    assert data.task_logging({"ReplicationTaskArn": "a", "ReplicationTaskSettings": "{}"}) == (False, {})
    with pytest.raises(Unavailable):
        data.task_logging({"ReplicationTaskArn": "a", "ReplicationTaskSettings": "not json"})


def test_collector_facts_reference_registered_checks():
    for fact in data.COLLECTOR_FACTS:
        assert fact["kind"] and fact["api"] and fact["fields"]
        assert all(cid in IDS for cid in fact["checks"]), fact["kind"]
