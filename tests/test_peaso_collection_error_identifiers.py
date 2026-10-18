"""Denied native reads retain vetted diagnostics without exposing provider text."""
import json

import pytest
from botocore.exceptions import ClientError

from peaso.collectors.base import Collector
from peaso.engine import evaluate_snapshot


@pytest.mark.parametrize("code,retained", [
    ("UnauthorizedOperation", "UnauthorizedOperation"),
    ("AccessDenied", "AccessDenied"),
    ("AccessDenied:PRIVATE_SENTINEL", None),
])
def test_native_denial_survives_report_with_only_known_error_identifiers(code, retained):
    collector = Collector("aws", ["fixture/us-east-1"], {"inventories": ["instance"]})

    def pages():
        raise ClientError({"Error": {"Code": code, "Message": "PRIVATE_SDK_MESSAGE"}}, "DescribeInstances")
        yield []

    collector.collect("instance", "fixture/us-east-1", "ec2", pages)
    snapshot = collector.finish()
    assert snapshot["collections"][0]["status"] == "denied"
    assert snapshot["collections"][0]["error"]["code"] == code
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=["aws.ec2.imdsv2"])
    row = next(value for value in report["coverage"] if value["level"] == "collection")
    assert row["status"] == "denied"
    assert row.get("error_code") == retained
    assert {finding["status"] for finding in report["findings"]} == {"DENIED"}
    assert report["stats"]["inventory_complete"] is False
    assert report["stats"]["coverage_complete"] is False
    assert "PRIVATE" not in json.dumps(row)
    assert "PRIVATE_SDK_MESSAGE" not in json.dumps(report)
