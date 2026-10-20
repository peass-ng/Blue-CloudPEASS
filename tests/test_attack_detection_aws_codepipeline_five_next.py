"""Synthetic derivatives of an owned CodePipeline live route; no lab identifiers."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
PIPELINE = "synthetic-pipeline"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-service-role"
TOKEN = "11111111-1111-4111-8111-111111111111"
EXECUTION = "22222222-2222-4222-8222-222222222222"


def event(name, request, response):
    return {"eventSource": "codepipeline.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
            "eventID": "33333333-3333-4333-8333-333333333333",
            "eventTime": "2026-01-01T00:00:00Z",
            "userIdentity": {"arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-actor/run"},
            "requestParameters": request, "responseElements": response}


def records():
    return [
        event("CreatePipeline", {"pipeline": {"name": PIPELINE, "roleArn": ROLE}},
              {"pipeline": {"name": PIPELINE, "roleArn": ROLE}}),
        event("StartPipelineExecution", {"name": PIPELINE, "variables": [{"name": "marker", "value": "synthetic-private-value"}]},
              {"pipelineExecutionId": EXECUTION}),
        event("EnableStageTransition", {"pipelineName": PIPELINE, "stageName": "Approval", "transitionType": "Inbound"}, None),
        event("PutApprovalResult", {"pipelineName": PIPELINE, "stageName": "Approval", "actionName": "Approve",
                                    "token": TOKEN, "result": {"status": "Approved", "summary": "synthetic-private-summary"}},
              {"approvedAt": "2026-01-01T00:00:00Z"}),
        event("RetryStageExecution", {"pipelineName": PIPELINE, "stageName": "Build", "pipelineExecutionId": EXECUTION,
                                      "retryMode": "FAILED_ACTIONS"}, {"pipelineExecutionId": EXECUTION}),
    ]


def rules():
    names = {"CreatePipeline", "StartPipelineExecution", "EnableStageTransition",
             "PutApprovalResult", "RetryStageExecution"}
    return [r for r in load_rules(product="aws")
            if isinstance(r.selection.get("event.name"), str)
            and r.selection.get("event.source") == "codepipeline.amazonaws.com"
            and r.selection["event.name"] in names]


def test_five_codepipeline_routes_match_without_emitting_values_or_token():
    found = detect_aws_events(records(), rules())
    assert {x.rule_id for x in found} == {r.id for r in rules()}
    rendered = str(found)
    assert "synthetic-private-value" not in rendered
    assert "synthetic-private-summary" not in rendered
    assert TOKEN not in rendered


def test_codepipeline_routes_reject_denied_or_malformed_variants():
    for index, change in (
        (0, {"requestParameters": {"pipeline": {"name": PIPELINE, "roleArn": "arn:aws:iam::888888888888:role/other"}}}),
        (1, {"requestParameters": {"name": PIPELINE, "variables": []}}),
        (2, {"requestParameters": {"pipelineName": PIPELINE, "stageName": "Approval", "transitionType": "Outbound"}}),
        (3, {"requestParameters": {"pipelineName": PIPELINE, "stageName": "Approval", "actionName": "Approve", "token": TOKEN, "result": {"status": "Rejected"}}}),
        (4, {"requestParameters": {"pipelineName": PIPELINE, "stageName": "Build", "pipelineExecutionId": EXECUTION, "retryMode": "UNKNOWN"}}),
    ):
        changed = deepcopy(records()[index]);changed.update(change)
        assert not detect_aws_events([changed], rules())
    for item in records():
        changed = deepcopy(item);changed["errorCode"] = "AccessDeniedException"
        assert not detect_aws_events([changed], rules())
