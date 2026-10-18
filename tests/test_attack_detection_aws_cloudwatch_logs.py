"""CloudWatch Logs disruption signals are exact accepted management writes."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events
from peaso.attack_detection.aws_cloudwatch_logs import normalize_aws_cloudwatch_logs


def record(name: str, params: dict) -> dict:
    return {
        "eventSource": "logs.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "eventID": "c419749b-1fe5-424b-9e7d-c6d66609fe9c",
        "eventTime": "2026-10-19T01:00:00Z", "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser", "accountId": "123456789012",
                         "arn": "arn:aws:iam::123456789012:user/tester"},
        "requestParameters": {"logGroupName": "/peasso/test", **params},
        "responseElements": None,
    }


@pytest.mark.parametrize("name,params,field", [
    ("PutRetentionPolicy", {"retentionInDays": 1}, "request.retention_one_day"),
    ("DeleteMetricFilter", {"filterName": "synthetic"}, "request.metric_filter_deleted"),
    ("DeleteLogStream", {"logStreamName": "synthetic"}, "request.log_stream_deleted"),
    ("DeleteLogGroup", {}, "request.log_group_deleted"),
])
def test_signal_and_denied_negative(name, params, field):
    event = record(name, params)
    rule = Rule("unit", "Logs unit", "medium", "Accepted write", "unit", "aws",
                {"event.source": "logs.amazonaws.com", "event.name": name,
                 "event.outcome": "success", field: True})
    assert len(detect_aws_events([event], [rule])) == 1
    denied = deepcopy(event)
    denied["errorCode"] = "AccessDeniedException"
    assert detect_aws_events([denied], [rule]) == []


@pytest.mark.parametrize("name,params", [
    ("PutRetentionPolicy", {"retentionInDays": 14}),
    ("PutRetentionPolicy", {"retentionInDays": True}),
    ("DeleteRetentionPolicy", {}),
    ("PutMetricFilter", {"filterName": "synthetic"}),
    ("DeleteMetricFilter", {}),
    ("DeleteLogStream", {}),
    ("CreateLogGroup", {}),
])
def test_no_restoration_or_incomplete_signal(name, params):
    assert normalize_aws_cloudwatch_logs(record(name, params)) is None


def test_wrong_account_and_missing_response_rejected():
    wrong = record("DeleteLogGroup", {})
    wrong["recipientAccountId"] = "999999999999"
    assert normalize_aws_cloudwatch_logs(wrong) is None
    missing = record("DeleteLogGroup", {})
    del missing["responseElements"]
    assert normalize_aws_cloudwatch_logs(missing) is None
