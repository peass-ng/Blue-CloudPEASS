"""Manual alarm state changes are review signals, not action proof."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(id="alarm-state", title="Alarm state", level="low", description="state",
            technique_id="aws-cloudwatch-alarm-state-manually-forced", product="aws",
            selection={"event.source": "monitoring.amazonaws.com", "event.name": "SetAlarmState",
                       "event.outcome": "success", "request.alarm_state_manually_forced": True})


def _hits(event: dict) -> list[str]:
    return [d.technique_id for d in detect_aws_events([event], [RULE])]


def test_manual_alarm_state_values_and_error() -> None:
    event = {"eventSource": "monitoring.amazonaws.com", "eventName": "SetAlarmState",
             "eventCategory": "Management", "eventType": "AwsApiCall",
             "managementEvent": True, "readOnly": False,
             "requestParameters": {"alarmName": "synthetic", "stateValue": "ALARM",
                                   "stateReason": "synthetic test"},
             "responseElements": None}
    assert _hits(event) == [RULE.technique_id]
    event["requestParameters"]["stateValue"] = "OK"
    assert _hits(event) == [RULE.technique_id]
    for variant in ("insufficient", "failed", "other_api"):
        item = deepcopy(event)
        if variant == "insufficient": item["requestParameters"]["stateValue"] = "INSUFFICIENT_DATA"
        if variant == "failed": item["errorCode"] = "ResourceNotFound"
        if variant == "other_api": item["eventName"] = "EnableAlarmActions"
        assert _hits(item) == [], variant
