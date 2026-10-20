"""Synthetic derivatives of owned CloudFormation and API Gateway route labs."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "us-east-1"
STACK = "synthetic-stack"
STACK_ARN = f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{STACK}/11111111-1111-4111-8111-111111111111"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-cfn-service"
CHANGE_PREPARED = f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:changeSet/synthetic-prepared/11111111-1111-4111-8111-222222222222"
CHANGE_ACTOR = f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:changeSet/synthetic-actor/11111111-1111-4111-8111-333333333333"
ADMIN = f"arn:aws:iam::{ACCOUNT}:user/synthetic-admin"
SIGNAL = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-signal/run"
EXECUTOR = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-executor/run"
CHANGER = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-changer/run"
UPDATER = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-updater/run"
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
IDS = {
    "6443e5c3-871d-40a0-9f65-27ab5966eea3",
    "5c18c6d3-d5ab-4a21-8c0c-5ce2fc9cadc0",
    "95e54535-fe56-497c-846c-e59a9b6afb7f",
    "ae94cad5-cf37-4240-ba5f-d98539bfcc2c",
    "8a27daa1-584c-4787-beb2-ff74b9884a33",
}


def event(name, actor, request, response, minute, source="cloudformation.amazonaws.com"):
    return {"eventSource": source, "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": REGION,
            "eventID": f"11111111-1111-4111-8111-{minute + 1:012d}",
            "eventTime": (BASE + timedelta(minutes=minute)).isoformat(),
            "userIdentity": {"accountId": ACCOUNT, "arn": actor},
            "requestParameters": request, "responseElements": response}


def records():
    return [
        event("CreateStack", ADMIN, {"stackName": STACK, "roleARN": ROLE},
              {"stackId": STACK_ARN}, 0),
        event("SignalResource", SIGNAL, {"stackName": STACK, "logicalResourceId": "Gate",
                                          "uniqueId": "synthetic-signal", "status": "SUCCESS"}, None, 1),
        event("CreateChangeSet", ADMIN, {"stackName": STACK, "changeSetName": "synthetic-prepared"},
              {"id": CHANGE_PREPARED}, 2),
        event("ExecuteChangeSet", EXECUTOR, {"changeSetName": CHANGE_PREPARED}, None, 3),
        event("CreateChangeSet", CHANGER, {"stackName": STACK, "changeSetName": "synthetic-actor"},
              {"id": CHANGE_ACTOR}, 4),
        event("ExecuteChangeSet", CHANGER, {"changeSetName": CHANGE_ACTOR}, None, 5),
        event("UpdateStack", UPDATER, {"stackName": STACK, "roleARN": ROLE},
              {"stackId": STACK_ARN}, 6),
        event("UpdateApi", ADMIN, {"apiId": "abcdefghij", "corsConfiguration": {
            "allowOrigins": ["https://synthetic-attacker.example.invalid"],
            "allowCredentials": True, "allowMethods": ["GET"],
            "allowHeaders": ["Authorization"], "maxAge": 86400}},
              {"apiId": "abcdefghij", "corsConfiguration": {
                  "allowOrigins": ["https://synthetic-attacker.example.invalid"],
                  "allowCredentials": True}}, 7, source="apigateway.amazonaws.com"),
    ]


def rules():
    return [rule for rule in load_rules(product="aws") if rule.id in IDS]


def test_five_live_route_derivatives_match_without_template_or_origin():
    found = detect_aws_events(records(), rules())
    assert len(found) == 5
    assert {item.rule_id for item in found} == IDS
    assert "synthetic-attacker.example.invalid" not in str(found)


def test_cross_actor_change_set_links_require_exact_id_order_and_distinct_actor():
    source = records()
    correlation = [rule for rule in rules() if rule.id in {
        "5c18c6d3-d5ab-4a21-8c0c-5ce2fc9cadc0",
        "95e54535-fe56-497c-846c-e59a9b6afb7f"}]
    for edit in (
        (3, {"requestParameters": {"changeSetName": CHANGE_ACTOR}}),
        (3, {"userIdentity": {"accountId": ACCOUNT, "arn": ADMIN}}),
        (3, {"eventTime": (BASE + timedelta(hours=2)).isoformat()}),
        (3, {"errorCode": "AccessDenied"}),
    ):
        changed = deepcopy(source)
        changed[edit[0]].update(edit[1])
        assert not any(item.rule_id == "5c18c6d3-d5ab-4a21-8c0c-5ce2fc9cadc0"
                       for item in detect_aws_events(changed, correlation))
    changed = deepcopy(source)
    changed[4]["userIdentity"]["arn"] = ADMIN
    assert not any(item.rule_id == "95e54535-fe56-497c-846c-e59a9b6afb7f"
                   for item in detect_aws_events(changed, correlation))
    changed = deepcopy(source)
    changed[0]["requestParameters"].pop("roleARN")
    assert not any(item.rule_id == "95e54535-fe56-497c-846c-e59a9b6afb7f"
                   for item in detect_aws_events(changed, correlation))


def test_signal_role_update_and_cors_require_successful_matching_inputs():
    source = records()
    for index, edit, rule_id in (
        (1, {"requestParameters": {"stackName": STACK, "logicalResourceId": "Gate",
                                   "uniqueId": "synthetic-signal", "status": "FAILURE"}},
         "6443e5c3-871d-40a0-9f65-27ab5966eea3"),
        (6, {"responseElements": {"stackId": STACK_ARN.replace(STACK, "other-stack")}},
         "ae94cad5-cf37-4240-ba5f-d98539bfcc2c"),
        (7, {"errorCode": "BadRequestException"},
         "8a27daa1-584c-4787-beb2-ff74b9884a33"),
    ):
        changed = deepcopy(source)
        changed[index].update(edit)
        assert not any(item.rule_id == rule_id for item in detect_aws_events(changed, rules()))
