"""Synthetic derivatives of isolated AppFlow limited-authority labs."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
FLOW = "synthetic-flow"
ARN = f"arn:aws:appflow:us-east-1:{ACCOUNT}:flow/{FLOW}"
IDS = {"aws-appflow-flow-updated", "aws-appflow-scheduled-update-and-activation"}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 2
    return selected


def event(name, index, second, request, response, actor):
    return {
        "eventSource": "appflow.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T08:20:{second:02d}Z",
        "userIdentity": {"arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{actor}/synthetic-session"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    return [
        event("UpdateFlow", 1, 1, {
            "flowName": FLOW,
            "triggerConfig": {"triggerType": "Scheduled", "triggerProperties": {
                "Scheduled": {"scheduleExpression": "rate(1minutes)"}}},
            "sourceFlowConfig": "***", "destinationFlowConfigList": "***", "tasks": "***",
        }, {"flowStatus": "Draft"}, "synthetic-updater"),
        event("StartFlow", 2, 1, {"flowName": FLOW},
              {"flowArn": ARN, "flowStatus": "Active"}, "synthetic-starter"),
    ]


def hits(rows):
    return detect_aws_events(rows, rules())


def test_update_and_activation_match_with_two_limited_actors():
    findings = hits(sample())
    assert len(findings) == 2
    assert {f.technique_id for f in findings} == IDS
    assert {f.target_id for f in findings} == {ARN}
    correlated = next(f for f in findings if f.technique_id.endswith("scheduled-update-and-activation"))
    assert correlated.evidence["correlation"]["scheduled_update_event_id"] == sample()[0]["eventID"]


def test_failed_foreign_and_unsupported_evidence_does_not_match():
    rows = deepcopy(sample())
    rows[0]["errorCode"] = "ValidationException"
    assert hits(rows) == []
    rows = deepcopy(sample())
    rows[0]["requestParameters"].pop("tasks")
    assert hits(rows) == []
    rows = deepcopy(sample())
    rows[1]["requestParameters"]["flowName"] = "other-flow"
    rows[1]["responseElements"]["flowArn"] = f"arn:aws:appflow:us-east-1:{ACCOUNT}:flow/other-flow"
    assert {f.technique_id for f in hits(rows)} == {"aws-appflow-flow-updated"}
    rows = deepcopy(sample())
    rows[1]["responseElements"]["executionId"] = "on-demand-execution"
    assert {f.technique_id for f in hits(rows)} == {"aws-appflow-flow-updated"}


def test_unrelated_scheduled_activation_outside_window_does_not_correlate():
    rows = sample()
    rows[1]["eventTime"] = "2026-10-21T08:40:01Z"
    assert {f.technique_id for f in hits(rows)} == {"aws-appflow-flow-updated"}
