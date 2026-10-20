"""Synthetic derivatives of owned SSM, nested template, and StackSet route labs."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "us-east-1"
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
ADMIN = f"arn:aws:iam::{ACCOUNT}:user/synthetic-admin"
SSM_ACTOR = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-ssm-writer/run"
S3_ACTOR = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-s3-writer/run"
STACKSET_ACTOR = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-stackset-actor/run"
IDS = {"95ddc524-4221-40e0-b43b-75db5e24c1f0",
       "40b943bd-e28b-4181-b006-af54d27413de",
       "29227b0f-f66b-48c5-9fd2-c0c6d64f142b",
       "96f2eda5-8828-4ea1-93d2-18f93289463b",
       "6c159389-62e2-4b7c-8812-e67ca1ad898b"}


def event(source, name, actor, request, response, minute, category="Management"):
    return {"eventSource": source, "eventName": name, "eventCategory": category,
            "eventType": "AwsApiCall", "managementEvent": category == "Management",
            "readOnly": False, "recipientAccountId": ACCOUNT, "awsRegion": REGION,
            "eventID": f"11111111-1111-4111-8111-{minute + 1:012d}",
            "eventTime": (BASE + timedelta(minutes=minute)).isoformat(),
            "userIdentity": {"accountId": ACCOUNT, "arn": actor},
            "requestParameters": request, "responseElements": response}


def records():
    return [
        event("ssm.amazonaws.com", "PutParameter", SSM_ACTOR,
              {"name": "/synthetic/input", "overwrite": True,
               "type": "String", "value": "private-synthetic-value"}, {}, 0),
        event("s3.amazonaws.com", "PutObject", S3_ACTOR,
              {"bucketName": "synthetic-bucket", "key": "nested/template.json"}, {}, 1, "Data"),
        event("cloudformation.amazonaws.com", "UpdateStack", ADMIN,
              {"stackName": "synthetic-stack", "usePreviousTemplate": True,
               "parameters": [{"parameterKey": "Input"}]},
              {"stackId": f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/synthetic-stack/11111111-1111-4111-8111-111111111111"}, 2),
        event("cloudformation.amazonaws.com", "CreateStackSet", STACKSET_ACTOR,
              {"stackSetName": "synthetic-stackset", "permissionModel": "SELF_MANAGED",
               "administrationRoleARN": f"arn:aws:iam::{ACCOUNT}:role/synthetic-admin-role",
               "executionRoleName": "synthetic-execution-role"},
              {"stackSetId": "synthetic-stackset:11111111-1111-4111-8111-222222222222"}, 3),
        event("cloudformation.amazonaws.com", "CreateStackInstances", STACKSET_ACTOR,
              {"stackSetName": "synthetic-stackset", "regions": [REGION]},
              {"operationId": "11111111-1111-4111-8111-333333333333"}, 4),
        event("cloudformation.amazonaws.com", "UpdateStackSet", STACKSET_ACTOR,
              {"stackSetName": "synthetic-stackset", "administrationRoleARN": f"arn:aws:iam::{ACCOUNT}:role/synthetic-admin-role"},
              {"operationId": "11111111-1111-4111-8111-444444444444"}, 5),
    ]


def rules():
    return [rule for rule in load_rules(product="aws") if rule.id in IDS]


def test_five_route_derivatives_match_and_never_emit_parameter_value():
    found = detect_aws_events(records(), rules())
    assert {x.rule_id for x in found} == IDS
    assert "private-synthetic-value" not in str(found)


def test_correlations_require_order_distinct_actors_and_right_input_shape():
    for index, edit, absent in (
        (0, {"errorCode": "AccessDenied"}, "95ddc524-4221-40e0-b43b-75db5e24c1f0"),
        (0, {"userIdentity": {"arn": SSM_ACTOR, "invokedBy": "cloudformation.amazonaws.com"}}, "95ddc524-4221-40e0-b43b-75db5e24c1f0"),
        (0, {"userIdentity": {"arn": ADMIN}}, "95ddc524-4221-40e0-b43b-75db5e24c1f0"),
        (1, {"eventCategory": "Management"}, "40b943bd-e28b-4181-b006-af54d27413de"),
        (1, {"requestParameters": {"bucketName": "synthetic-bucket", "key": "unrelated.bin"}}, "40b943bd-e28b-4181-b006-af54d27413de"),
        (2, {"errorCode": "ValidationError"}, "95ddc524-4221-40e0-b43b-75db5e24c1f0"),
        (2, {"requestParameters": {"stackName": "synthetic-stack", "usePreviousTemplate": True}}, "95ddc524-4221-40e0-b43b-75db5e24c1f0"),
        (2, {"eventTime": (BASE + timedelta(hours=2)).isoformat()}, "95ddc524-4221-40e0-b43b-75db5e24c1f0"),
    ):
        changed = deepcopy(records())
        changed[index].update(edit)
        assert absent not in {x.rule_id for x in detect_aws_events(changed, rules())}


def test_stackset_rules_require_same_account_and_successful_role_selection():
    for index, edit, absent in (
        (3, {"requestParameters": {"stackSetName": "synthetic-stackset", "permissionModel": "SERVICE_MANAGED"}}, "29227b0f-f66b-48c5-9fd2-c0c6d64f142b"),
        (4, {"requestParameters": {"stackSetName": "synthetic-stackset", "regions": ["eu-west-1"]}}, "96f2eda5-8828-4ea1-93d2-18f93289463b"),
        (5, {"errorCode": "AccessDenied"}, "6c159389-62e2-4b7c-8812-e67ca1ad898b"),
    ):
        changed = deepcopy(records())
        changed[index].update(edit)
        assert absent not in {x.rule_id for x in detect_aws_events(changed, rules())}
