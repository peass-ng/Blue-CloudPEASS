"""SNS topic changes require accepted management events and exact ARNs."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events
from peaso.attack_detection.aws_sns_topic import normalize_aws_sns_topic


TOPIC = "arn:aws:sns:us-east-1:123456789012:disposable-topic"
SUBSCRIPTION = TOPIC + ":be16ee70-e83f-4264-938e-26a2ea4fa258"


def record(name: str, params: dict) -> dict:
    return {
        "eventSource": "sns.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "eventID": "e612e6f2-5738-44cf-ae25-dc7a8a1f600b",
        "eventTime": "2026-10-19T01:00:00Z", "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser", "accountId": "123456789012",
                         "arn": "arn:aws:iam::123456789012:user/tester"},
        "requestParameters": params, "responseElements": None,
    }


@pytest.mark.parametrize("name,params,field", [
    ("RemovePermission", {"topicArn": TOPIC, "label": "legacy-grant"},
     "request.permission_removed"),
    ("Unsubscribe", {"subscriptionArn": SUBSCRIPTION}, "request.unsubscribe_observed"),
    ("DeleteTopic", {"topicArn": TOPIC}, "request.delete_topic_observed"),
])
def test_sns_operation_signal_and_denied_negative(name, params, field):
    event = record(name, params)
    rule = Rule("unit", "SNS unit", "medium", "Accepted operation", "unit", "aws",
                {"event.source": "sns.amazonaws.com", "event.name": name,
                 "event.outcome": "success", field: True})
    assert len(detect_aws_events([event], [rule])) == 1
    denied = deepcopy(event)
    denied["errorCode"] = "AuthorizationError"
    assert detect_aws_events([denied], [rule]) == []


def test_remove_permission_needs_label_and_exact_account():
    assert normalize_aws_sns_topic(record("RemovePermission", {"topicArn": TOPIC})) is None
    wrong = record("RemovePermission", {"topicArn": TOPIC, "label": "grant"})
    wrong["recipientAccountId"] = "999999999999"
    assert normalize_aws_sns_topic(wrong) is None


def test_unsubscribe_requires_subscription_arn():
    assert normalize_aws_sns_topic(record("Unsubscribe", {"subscriptionArn": TOPIC})) is None
    assert normalize_aws_sns_topic(record("Unsubscribe", {
        "subscriptionArn": TOPIC + ":not-a-uuid"})) is None


def test_subscribe_and_policy_change_are_not_generic_disruption_signals():
    assert normalize_aws_sns_topic(record("Subscribe", {"topicArn": TOPIC})) is None
    assert normalize_aws_sns_topic(record("SetTopicAttributes", {"topicArn": TOPIC})) is None
