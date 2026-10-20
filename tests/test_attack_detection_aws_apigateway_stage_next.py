"""Synthetic derivative of a disposable five-route REST stage lab."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
API_ID = "abcdefghij"
FIRST = "first1"
SECOND = "second2"
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
IDS = {
    "49486d22-b1bc-4fa4-ab83-4039ea857c3a",
    "b90fdf4f-e786-45ae-82c3-19169bed996c",
    "59250b47-faf8-4d7f-a58b-4e84b9d7f30d",
    "ea4229b9-d6a2-4d7b-8af9-12948c08321a",
    "0b477796-dc77-4d58-b687-7722c8fac51c",
}


def event(name, patches, response, minute):
    request = {"restApiId": API_ID}
    if name == "UpdateStage":
        request.update({"stageName": "lab", "updateStageInput": {"patchOperations": patches}})
        response = {"stageName": "lab", **response}
    else:
        request["updateRestApiInput"] = {"patchOperations": patches}
        response = {"id": API_ID, **response}
    return {"eventSource": "apigateway.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
            "eventID": f"11111111-1111-4111-8111-{minute+1:012d}",
            "eventTime": (BASE + timedelta(minutes=minute)).isoformat(),
            "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                             "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
            "requestParameters": request, "responseElements": response}


def fixtures():
    return [
        event("UpdateRestApi", [{"op": "replace", "path": "/disableExecuteApiEndpoint",
                                 "value": "false"}], {"disableExecuteApiEndpoint": False}, 0),
        event("UpdateStage", [{"op": "replace", "path": "/variables/backend",
                               "value": "*"}], {"deploymentId": FIRST,
                                               "variables": {"backend": "*"}}, 1),
        event("UpdateStage", [{"op": "replace", "path": "/canarySettings/deploymentId",
                               "value": FIRST}, {"op": "replace",
                                                "path": "/canarySettings/percentTraffic",
                                                "value": "100"}],
              {"deploymentId": SECOND,
               "canarySettings": {"deploymentId": FIRST, "percentTraffic": 100.0}}, 2),
        event("UpdateStage", [{"op": "replace", "path": "/deploymentId",
                               "value": FIRST}], {"deploymentId": FIRST}, 3),
        event("UpdateStage", [{"op": "replace", "path": "/tracingEnabled",
                               "value": "false"}], {"deploymentId": FIRST,
                                                   "tracingEnabled": False}, 4),
    ]


def stage_rules():
    rules = load_rules(product="aws")
    return [rule for rule in rules if rule.id in IDS]


def test_five_stage_routes_match_without_stage_values_or_real_identity():
    found = detect_aws_events(fixtures(), stage_rules())
    assert len(found) == 5
    assert {item.rule_id for item in found} == IDS
    assert "synthetic-one" not in str(found)


def test_failed_or_mismatched_rollback_does_not_match():
    source = fixtures()[3]
    rule = [rule for rule in stage_rules() if rule.id == "0b477796-dc77-4d58-b687-7722c8fac51c"]
    assert len(detect_aws_events([source], rule)) == 1
    for altered in (
        {"errorCode": "BadRequestException"},
        {"responseElements": {"stageName": "lab", "deploymentId": SECOND}},
        {"requestParameters": {"restApiId": API_ID, "stageName": "lab",
                               "updateStageInput": {"patchOperations": [{"op": "remove",
                                                                    "path": "/deploymentId"}]}}},
    ):
        record = deepcopy(source)
        record.update(altered)
        assert not detect_aws_events([record], rule)
