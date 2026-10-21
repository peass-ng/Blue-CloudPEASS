"""Synthetic derivatives of owned REST API configuration changes."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
API = "abcdefghij"
RESOURCE = "abc1234"
BASE = datetime(2026, 10, 21, tzinfo=timezone.utc)


def event(name, request, response, minute):
    return {
        "eventSource": "apigateway.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "eu-west-1",
        "eventID": f"11111111-1111-4111-8111-{minute+1:012d}",
        "eventTime": (BASE + timedelta(minutes=minute)).isoformat(),
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def fixtures():
    return [
        event("UpdateStage", {"restApiId": API, "stageName": "lab", "updateStageInput": {
            "patchOperations": [{"op": "replace", "path": "/canarySettings/percentTraffic", "value": "25.0"}]}},
            {"stageName": "lab", "deploymentId": "main001", "canarySettings": {
                "deploymentId": "canary002", "percentTraffic": 25.0}}, 0),
        event("UpdateGatewayResponse", {"restApiId": API, "responseType": "UNAUTHORIZED",
            "updateGatewayResponseInput": {"patchOperations": [{"op": "replace", "path": "/statusCode",
                                                             "value": "403"}]}},
            {"responseType": "UNAUTHORIZED", "statusCode": "403"}, 1),
        event("CreateDeployment", {"restApiId": API, "createDeploymentInput": {"stageName": "lab"}},
            {"id": "deploy0001"}, 2),
        event("PutIntegration", {"restApiId": API, "resourceId": RESOURCE, "httpMethod": "GET",
            "putIntegrationInput": {"type": "HTTP_PROXY", "httpMethod": "GET",
                                    "uri": "https://synthetic.example.invalid/backend"}},
            {"type": "HTTP_PROXY", "uri": "https://synthetic.example.invalid/backend"}, 3),
        event("CreateDeployment", {"restApiId": API, "createDeploymentInput": {"stageName": "lab"}},
            {"id": "deploy0002"}, 4),
    ]


def rules():
    ids = {"b90fdf4f-e786-45ae-82c3-19169bed996c",
           "fd8041ca-8d58-54b9-a7f3-ab3ec5a5a18c",
           "32c2e937-41d1-4d3c-870e-4b86d4cb6dbb"}
    return [rule for rule in load_rules(product="aws") if rule.id in ids]


def test_canary_percent_status_change_and_published_proxy_match():
    found = detect_aws_events(fixtures(), rules())
    assert len(found) == 3
    assert {hit.rule_id for hit in found} == {rule.id for rule in rules()}
    assert "synthetic.example.invalid" not in str(found)


def test_canary_requires_distinct_deployment_and_response_match():
    source = fixtures()[0]
    for change in (
        lambda x: x["responseElements"].update(deploymentId="canary002"),
        lambda x: x["responseElements"]["canarySettings"].update(percentTraffic=0),
        lambda x: x.update(errorCode="BadRequestException"),
    ):
        bad = deepcopy(source)
        change(bad)
        assert detect_aws_events([bad], rules()) == []


def test_published_changes_require_effect_and_successful_deployment():
    original = fixtures()
    for index, change in (
        (1, lambda x: x["responseElements"].update(statusCode="401")),
        (3, lambda x: x["responseElements"].update(uri="https://other.example.invalid")),
        (3, lambda x: x["requestParameters"]["putIntegrationInput"].update(type="MOCK")),
        (3, lambda x: x.update(errorCode="BadRequestException")),
        (4, lambda x: x.update(errorCode="BadRequestException")),
    ):
        records = deepcopy(original)
        change(records[index])
        hits = detect_aws_events(records, rules())
        assert len(hits) == 2
