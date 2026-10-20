"""Enhanced EventBridge bus policy external grant and bounded negatives."""

from copy import deepcopy
import json

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "222233334444"
BUS = f"arn:aws:events:us-east-1:{ACCOUNT}:event-busv2/example-v2-policy-cad35e7ea0/87sadn00gqtww2jkq01po6muq"
RULE = Rule(id="bus-grant", title="External bus grant", level="high",
            description="External bus grant",
            technique_id="aws-eventsv2-external-bus-policy-grant",
            product="aws", selection={"event.source": "eventsv2.amazonaws.com",
                                      "event.outcome": "success",
                                      "request.eventsv2_external_bus_grant": True})


def hits(event: dict) -> list[str]:
    return [x.technique_id for x in detect_aws_events([event], [RULE])]


def test_external_policy_grant_and_negative_variants() -> None:
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
              "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
              "Action": ["events:PutEvents", "events:CreateSubscriber"],
              "Resource": BUS}]}
    event = {"eventSource": "eventsv2.amazonaws.com", "eventName": "PutResourcePolicy",
             "eventCategory": "Management", "eventType": "AwsApiCall",
             "managementEvent": True, "readOnly": False, "awsRegion": "us-east-1",
             "recipientAccountId": ACCOUNT,
             "requestParameters": {"resourceArn": BUS, "policyName": "default",
                                   "policyDocument": json.dumps(policy)},
             "responseElements": {"resourceArn": BUS, "policyName": "default",
                                  "revisionId": "revision-test"},
             "resources": [{"accountId": ACCOUNT, "ARN": BUS}]}
    assert hits(event) == [RULE.technique_id]
    for variant in ("error", "same_account", "condition", "read_only", "wrong_response",
                    "wrong_resource", "no_resource", "non_sensitive", "deny"):
        item = deepcopy(event);p = deepcopy(policy);statement = p["Statement"][0]
        if variant == "error": item["errorCode"] = "AccessDeniedException"
        if variant == "same_account": statement["Principal"]["AWS"] = f"arn:aws:iam::{ACCOUNT}:root"
        if variant == "condition": statement["Condition"] = {"StringEquals": {"aws:PrincipalOrgID": "o-example"}}
        if variant == "read_only": item["readOnly"] = True
        if variant == "wrong_response": item["responseElements"]["resourceArn"] += "-other"
        if variant == "wrong_resource": statement["Resource"] += "-other"
        if variant == "no_resource": item["resources"] = []
        if variant == "non_sensitive": statement["Action"] = ["events:DescribeEventBus"]
        if variant == "deny": statement["Effect"] = "Deny"
        item["requestParameters"]["policyDocument"] = json.dumps(p)
        assert hits(item) == [], variant
