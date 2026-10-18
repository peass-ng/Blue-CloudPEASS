"""CloudWatch monitoring writes require exact accepted values and target names."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events
from peaso.attack_detection.aws_cloudwatch_monitoring import normalize_aws_cloudwatch_monitoring


def record(name: str, params: dict) -> dict:
    return {
        "eventSource": "monitoring.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "eventID": "92530149-0ca0-40df-81f3-2d3881eff042",
        "eventTime": "2026-10-19T01:00:00Z", "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser", "accountId": "123456789012",
                         "arn": "arn:aws:iam::123456789012:user/tester"},
        "requestParameters": params, "responseElements": None,
    }


@pytest.mark.parametrize("name,params,field", [
    ("PutMetricAlarm", {"alarmName": "disposable", "actionsEnabled": False},
     "request.alarm_actions_explicitly_disabled"),
    ("DisableAlarmActions", {"alarmNames": ["disposable"]},
     "request.disable_alarm_actions_observed"),
    ("DeleteAlarms", {"alarmNames": ["disposable"]}, "request.delete_alarm_observed"),
    ("DeleteDashboards", {"dashboardNames": ["disposable"]},
     "request.delete_dashboard_observed"),
])
def test_exact_write_matches_and_denied_does_not(name, params, field):
    event = record(name, params)
    rule = Rule("unit", "CloudWatch unit", "medium", "Accepted write", "unit", "aws",
                {"event.source": "monitoring.amazonaws.com", "event.name": name,
                 "event.outcome": "success", field: True})
    assert len(detect_aws_events([event], [rule])) == 1
    denied = deepcopy(event)
    denied["errorCode"] = "AccessDenied"
    assert detect_aws_events([denied], [rule]) == []


def test_multi_target_alarm_event_produces_separate_findings():
    event = record("DeleteAlarms", {"alarmNames": ["one", "two"]})
    rule = Rule("unit", "CloudWatch unit", "high", "Deletion", "unit", "aws",
                {"event.source": "monitoring.amazonaws.com", "event.name": "DeleteAlarms",
                 "request.delete_alarm_observed": True})
    hits = detect_aws_events([event], [rule])
    assert [hit.target_id for hit in hits] == [
        "arn:aws:cloudwatch:us-east-1:123456789012:alarm:one",
        "arn:aws:cloudwatch:us-east-1:123456789012:alarm:two",
    ]


@pytest.mark.parametrize("name,params", [
    ("PutMetricAlarm", {"alarmName": "disposable", "actionsEnabled": True}),
    ("PutMetricAlarm", {"alarmName": "disposable", "actionsEnabled": 0}),
    ("EnableAlarmActions", {"alarmNames": ["disposable"]}),
    ("SetAlarmState", {"alarmName": "disposable", "stateValue": "OK"}),
    ("DeleteDashboards", {"dashboardNames": []}),
    ("DeleteAlarms", {"alarmNames": ["\ninvalid"]}),
])
def test_no_restoration_or_incomplete_signal(name, params):
    assert normalize_aws_cloudwatch_monitoring(record(name, params)) == []


def test_wrong_account_and_missing_response_rejected():
    wrong = record("DisableAlarmActions", {"alarmNames": ["one"]})
    wrong["recipientAccountId"] = "999999999999"
    assert normalize_aws_cloudwatch_monitoring(wrong) == []
    missing = record("DisableAlarmActions", {"alarmNames": ["one"]})
    del missing["responseElements"]
    assert normalize_aws_cloudwatch_monitoring(missing) == []
