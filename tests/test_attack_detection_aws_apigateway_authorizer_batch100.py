"""Synthetic derivatives of an owned API Gateway and Lambda authorizer lab."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "eu-west-1"
API = "abcdefghij"
RESOURCE = "abc1234"
AUTHORIZER = "auth1234"
BASE = datetime(2026, 10, 21, tzinfo=timezone.utc)


def uri(name):
    return (f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/"
            f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:synthetic-{name}/invocations")


def event(name, request, response, minute):
    return {
        "eventSource": "apigateway.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"11111111-1111-4111-8111-{minute+1:012d}",
        "eventTime": (BASE + timedelta(minutes=minute)).isoformat(),
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def deployment(minute):
    return event("CreateDeployment", {"restApiId": API,
                 "createDeploymentInput": {"stageName": "lab"}},
                 {"id": f"deployment{minute:02d}"}, minute)


def fixtures():
    return [
        event("UpdateAuthorizer", {"restApiId": API, "authorizerId": AUTHORIZER,
              "updateAuthorizerInput": {"patchOperations": [{"op": "replace",
                  "path": "/authorizerUri", "value": uri("allow") }]}},
              {"id": AUTHORIZER, "authorizerUri": uri("allow")}, 0),
        deployment(1),
        event("PutIntegration", {"restApiId": API, "resourceId": RESOURCE,
              "httpMethod": "GET", "putIntegrationInput": {"type": "AWS_PROXY",
                  "httpMethod": "POST", "uri": uri("backend")}},
              {"type": "AWS_PROXY", "uri": uri("backend")}, 2),
        deployment(3),
        event("UpdateMethod", {"restApiId": API, "resourceId": RESOURCE,
              "httpMethod": "GET", "updateMethodInput": {"patchOperations": [
                  {"op": "replace", "path": "/authorizationType", "value": "NONE"}]}},
              {"authorizationType": "NONE"}, 4),
        deployment(5),
    ]


def rules():
    ids = {"aws-apigateway-rest-authorizer-repoint-published",
           "aws-apigateway-rest-lambda-integration-published",
           "aws-apigateway-rest-method-authorizer-removed-published"}
    return [rule for rule in load_rules(product="aws") if rule.technique_id in ids]


def test_three_published_mutations_match_synthetic_derivatives():
    assert len(rules()) == 3
    hits = detect_aws_events(fixtures(), rules())
    assert len(hits) == 3
    assert {hit.technique_id for hit in hits} == {rule.technique_id for rule in rules()}
    assert "synthetic-backend" not in str(hits)


def test_rejected_or_unpublished_mutations_do_not_match():
    for source_index, deploy_index in ((0, 1), (2, 3), (4, 5)):
        for index in (0, 1):
            records = deepcopy([fixtures()[source_index], fixtures()[deploy_index]])
            records[index]["errorCode"] = "BadRequestException"
            assert detect_aws_events(records, rules()) == []
    mismatches = [
        (0, lambda x: x["responseElements"].update(authorizerUri=uri("other"))),
        (2, lambda x: x["requestParameters"]["putIntegrationInput"].update(type="MOCK")),
        (2, lambda x: x["requestParameters"]["putIntegrationInput"].update(uri="https://synthetic.example.invalid")),
        (4, lambda x: x["responseElements"].update(authorizationType="CUSTOM")),
    ]
    for index, change in mismatches:
        records = deepcopy([fixtures()[index], fixtures()[index + 1]])
        change(records[0])
        assert detect_aws_events(records, rules()) == []


def test_deployment_by_different_principal_does_not_publish_mutation():
    records = deepcopy(fixtures()[:2])
    records[1]["userIdentity"]["arn"] = f"arn:aws:iam::{ACCOUNT}:user/synthetic-other"
    assert detect_aws_events(records, rules()) == []
