"""SQS management detections separate accepted writes from missing context."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events
from peaso.attack_detection.aws_sqs_queue import normalize_aws_sqs_queue


QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/123456789012/disposable-queue"


def record(name: str, params: dict | None = None) -> dict:
    return {
        "eventSource": "sqs.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "eventID": "3ee38436-6f3d-421c-a4c6-38ef7f903ae9",
        "eventTime": "2026-10-19T01:00:00Z", "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser", "accountId": "123456789012",
                         "arn": "arn:aws:iam::123456789012:user/tester"},
        "requestParameters": {"queueUrl": QUEUE_URL, **(params or {})},
        "responseElements": None,
    }


@pytest.mark.parametrize("name,params,field", [
    ("RemovePermission", {"label": "approved-service"}, "request.permission_removed"),
    ("SetQueueAttributes", {"attributes": {"MessageRetentionPeriod": "60"}},
     "request.retention_60_seconds"),
    ("PurgeQueue", {}, "request.purge_queue_observed"),
    ("DeleteQueue", {}, "request.delete_queue_observed"),
])
def test_completed_sqs_write_matches_precise_signal(name, params, field):
    event = record(name, params)
    rule = Rule("unit", "SQS unit", "medium", "Exact request", "unit", "aws",
                {"event.source": "sqs.amazonaws.com", "event.name": name,
                 "event.outcome": "success", field: True})
    assert len(detect_aws_events([event], [rule])) == 1
    assert normalize_aws_sqs_queue(event)["target.id"] == "arn:aws:sqs:us-east-1:123456789012:disposable-queue"
    denied = deepcopy(event)
    denied["errorCode"] = "AccessDenied"
    assert detect_aws_events([denied], [rule]) == []


def test_retention_requires_exact_minimum_and_policy_change_is_not_its_signal():
    for params in [
        {"attributes": {"MessageRetentionPeriod": "120"}},
        {"attributes": {"Policy": "{}"}},
        {"attributes": {"MessageRetentionPeriod": 60}},
    ]:
        assert normalize_aws_sqs_queue(record("SetQueueAttributes", params)) is None


def test_remove_permission_requires_label():
    assert normalize_aws_sqs_queue(record("RemovePermission")) is None
    assert normalize_aws_sqs_queue(record("RemovePermission", {"label": ""})) is None


@pytest.mark.parametrize("url", [
    "http://sqs.us-east-1.amazonaws.com/123456789012/disposable-queue",
    "https://sqs.us-west-2.amazonaws.com/123456789012/disposable-queue",
    "https://sqs.us-east-1.amazonaws.com/999999999999/disposable-queue",
    "https://sqs.us-east-1.amazonaws.com/123456789012/../disposable-queue",
])
def test_queue_url_must_match_account_and_region(url):
    event = record("PurgeQueue")
    event["requestParameters"]["queueUrl"] = url
    assert normalize_aws_sqs_queue(event) is None
