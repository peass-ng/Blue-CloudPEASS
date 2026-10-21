"""Synthetic derivatives of an isolated AppFlow S3-to-S3 lab."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
FLOW = "synthetic-flow"
ARN = f"arn:aws:appflow:{REGION}:{ACCOUNT}:flow/{FLOW}"
IDS = {
    "aws-appflow-flow-created", "aws-appflow-flow-described",
    "aws-appflow-flows-listed", "aws-appflow-flow-execution-records-read",
    "aws-appflow-flow-started-on-demand", "aws-appflow-flow-activated",
    "aws-appflow-flow-scheduled", "aws-appflow-flow-stopped",
    "aws-appflow-flow-deleted",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 9
    return selected


def event(name, index, request, response=None, *, read=False):
    return {
        "eventSource": "appflow.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T07:57:{index:02d}Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    named = {"flowName": FLOW}
    return [
        event("CreateFlow", 1, {**named, "triggerConfig": {"triggerType": "OnDemand"}},
              {"flowArn": ARN, "flowStatus": "Active"}),
        event("DescribeFlow", 2, named, read=True),
        event("ListFlows", 3, None, read=True),
        event("DescribeFlowExecutionRecords", 4, {**named, "maxResults": 100}, read=True),
        event("StartFlow", 5, named, {"flowArn": ARN, "flowStatus": "Active", "executionId": "synthetic-execution"}),
        event("UpdateFlow", 6, {**named, "triggerConfig": {"triggerType": "Scheduled", "triggerProperties": {
            "Scheduled": {"scheduleExpression": "rate(1minutes)"}}}}, {"flowStatus": "Draft"}),
        event("StartFlow", 7, named, {"flowArn": ARN, "flowStatus": "Active"}),
        event("StopFlow", 8, named, {"flowArn": ARN, "flowStatus": "Suspended"}),
        event("DeleteFlow", 9, {**named, "forceDelete": True}),
    ]


def hits(rows):
    return detect_aws_events(rows, rules())


def test_nine_observed_appflow_routes_match():
    findings = hits(sample())
    assert len(findings) == 9
    assert {finding.technique_id for finding in findings} == IDS
    assert [finding.target_id for finding in findings] == [ARN, ARN, None, ARN, ARN, ARN, ARN, ARN, ARN]


def test_failures_wrong_source_and_missing_schedule_fail_closed():
    rows = deepcopy(sample())
    rows[0]["errorCode"] = "ConnectorServerException"
    rows[1]["readOnly"] = False
    rows[2]["requestParameters"] = {"flowName": FLOW}
    rows[3]["eventSource"] = "other.amazonaws.com"
    rows[4]["responseElements"]["flowArn"] = "foreign"
    rows[5]["requestParameters"]["triggerConfig"]["triggerProperties"] = {}
    rows[6]["responseElements"]["executionId"] = None
    rows[7]["responseElements"]["flowStatus"] = "Active"
    rows[8]["errorCode"] = "ResourceNotFoundException"
    assert hits(rows) == []


def test_no_recurring_execution_or_data_content_claimed():
    findings = hits(sample())
    assert not any("Recurring" in finding.technique_id or "DataTransferred" in finding.technique_id for finding in findings)
