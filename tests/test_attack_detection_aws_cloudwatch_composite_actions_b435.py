"""Synthetic derivative of an owned PutCompositeAlarm CloudTrail event."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(
    id="synthetic-composite-actions", title="Composite actions disabled",
    level="medium", description="synthetic", product="aws",
    technique_id="aws-cloudwatch-composite-alarm-actions-disabled",
    selection={
        "event.source": "monitoring.amazonaws.com",
        "event.name": "PutCompositeAlarm",
        "event.outcome": "success",
        "request.alarm_actions_explicitly_disabled": True,
    },
)


def _event():
    return {
        "eventSource": "monitoring.amazonaws.com",
        "eventName": "PutCompositeAlarm",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "requestParameters": {
            "alarmName": "synthetic-composite", "alarmRule": "FALSE",
            "actionsEnabled": False,
            "alarmActions": ["arn:aws:sns:us-east-1:999999999999:synthetic-topic"],
        },
        "responseElements": None,
    }


def _hits(event):
    return [hit.technique_id for hit in detect_aws_events([event], [RULE])]


def test_accepted_explicit_disable_matches():
    assert _hits(_event()) == [RULE.technique_id]


def test_enabled_failed_and_other_apis_do_not_match():
    for change in (
        lambda e: e["requestParameters"].update(actionsEnabled=True),
        lambda e: e["requestParameters"].pop("actionsEnabled"),
        lambda e: e.update(errorCode="AccessDenied"),
        lambda e: e.update(eventName="PutMetricAlarm"),
        lambda e: e.update(readOnly=True),
    ):
        event = deepcopy(_event())
        change(event)
        assert _hits(event) == []
