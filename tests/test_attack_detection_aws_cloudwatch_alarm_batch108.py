"""Synthetic derivatives of owned CloudWatch alarm management events."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "eu-west-1"
ALARM = "synthetic-metric-alarm"
TOPIC_A = f"arn:aws:sns:{REGION}:{ACCOUNT}:synthetic-topic-a"
TOPIC_B = f"arn:aws:sns:{REGION}:{ACCOUNT}:synthetic-topic-b"
IDS = {
    "aws-cloudwatch-metric-alarm-sensitivity-reduced",
    "aws-cloudwatch-metric-alarm-actions-redirected",
    "aws-cloudwatch-metric-alarm-actions-cleared",
    "aws-cloudwatch-alarm-actions-enabled",
    "aws-cloudwatch-composite-mutual-cycle-requested",
    "aws-cloudwatch-forced-alarm-with-sns-action",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 6
    return selected


def event(name, second, request, *, error=None, account=ACCOUNT):
    result = {
        "eventSource": "monitoring.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": account, "awsRegion": REGION,
        "eventID": f"88888888-8888-4888-8888-{second:012d}",
        "eventTime": f"2026-10-21T04:00:{second:02d}Z",
        "userIdentity": {"type": "AssumedRole", "accountId": account,
                         "arn": f"arn:aws:sts::{account}:assumed-role/synthetic-role/session"},
        "requestParameters": request, "responseElements": None,
    }
    if error:
        result["errorCode"] = error
    return result


def metric(second, *, threshold, periods, actions, enabled=False):
    return event("PutMetricAlarm", second, {
        "alarmName": ALARM, "namespace": "PeassoSynthetic/Batch108",
        "metricName": "SyntheticSignal", "statistic": "Average", "period": 300,
        "evaluationPeriods": periods, "datapointsToAlarm": periods,
        "comparisonOperator": "GreaterThanThreshold", "threshold": threshold,
        "treatMissingData": "notBreaching", "actionsEnabled": enabled,
        "alarmActions": actions,
    })


def sample():
    return [
        metric(1, threshold=1, periods=1, actions=[TOPIC_A]),
        metric(3, threshold=999, periods=12, actions=[TOPIC_A]),
        metric(5, threshold=999, periods=12, actions=[TOPIC_B]),
        metric(7, threshold=999, periods=12, actions=[]),
        metric(9, threshold=999, periods=12, actions=[TOPIC_B], enabled=True),
        event("EnableAlarmActions", 10, {"alarmNames": [ALARM]}),
        event("SetAlarmState", 11, {"alarmName": ALARM, "stateValue": "ALARM",
                                    "stateReason": "synthetic test"}),
        event("PutCompositeAlarm", 13, {"alarmName": "synthetic-composite-a",
                                          "alarmRule": "FALSE", "actionsEnabled": False}),
        event("PutCompositeAlarm", 15, {"alarmName": "synthetic-composite-b",
                                          "alarmRule": 'ALARM("synthetic-composite-a")',
                                          "actionsEnabled": False}),
        event("PutCompositeAlarm", 17, {"alarmName": "synthetic-composite-a",
                                          "alarmRule": 'ALARM("synthetic-composite-b")',
                                          "actionsEnabled": False}),
    ]


def test_six_routes_match_ordered_synthetic_derivatives():
    hits = detect_aws_events(sample(), rules())
    assert len(hits) == 6
    assert {hit.technique_id for hit in hits} == IDS
    assert TOPIC_A not in str(hits) and TOPIC_B not in str(hits)
    assert all(hit.evidence.get("correlation") for hit in hits
               if hit.technique_id != "aws-cloudwatch-alarm-actions-enabled")


def test_same_second_writes_do_not_fabricate_change_order():
    records = sample()
    for index in (1, 2, 3):
        records[index]["eventTime"] = records[0]["eventTime"]
    hits = detect_aws_events(records, rules())
    ids = {hit.technique_id for hit in hits}
    assert "aws-cloudwatch-metric-alarm-sensitivity-reduced" not in ids
    assert "aws-cloudwatch-metric-alarm-actions-redirected" not in ids
    assert "aws-cloudwatch-metric-alarm-actions-cleared" not in ids


def test_account_errors_and_missing_action_context_exclude_matches():
    records = sample()
    foreign = deepcopy(records[0])
    foreign["recipientAccountId"] = "111111111111"
    assert not any(hit.technique_id == "aws-cloudwatch-metric-alarm-sensitivity-reduced"
                   for hit in detect_aws_events([foreign, records[1]], rules()))
    failed = deepcopy(records[1])
    failed["errorCode"] = "AccessDenied"
    assert detect_aws_events([records[0], failed], rules()) == []
    response_failed = deepcopy(records[1])
    response_failed["responseElements"] = {"errorCode": "ValidationException"}
    assert detect_aws_events([records[0], response_failed], rules()) == []
    no_action = deepcopy(records[4])
    no_action["requestParameters"]["alarmActions"] = []
    assert not any(hit.technique_id == "aws-cloudwatch-forced-alarm-with-sns-action"
                   for hit in detect_aws_events([no_action, records[5], records[6]], rules()))
    assert not any(hit.technique_id == "aws-cloudwatch-composite-mutual-cycle-requested"
                   for hit in detect_aws_events(records[7:9], rules()))
    unordered_cycle = deepcopy(records[8:10])
    unordered_cycle[1]["eventTime"] = unordered_cycle[0]["eventTime"]
    assert not any(hit.technique_id == "aws-cloudwatch-composite-mutual-cycle-requested"
                   for hit in detect_aws_events(unordered_cycle, rules()))


def test_malformed_event_name_does_not_abort_following_event():
    malformed = deepcopy(sample()[5])
    malformed["eventName"] = ["EnableAlarmActions"]
    hits = detect_aws_events([malformed, sample()[5]], rules())
    assert [hit.technique_id for hit in hits] == ["aws-cloudwatch-alarm-actions-enabled"]
