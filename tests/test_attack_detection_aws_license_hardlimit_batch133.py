"""Synthetic derivative of the isolated hard-limit EC2 launch lab."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
IMAGE = "ami-0123456789abcdef0"
TARGET = f"arn:aws:ec2:{REGION}:{ACCOUNT}:image/{IMAGE}"
TECHNIQUE = "aws-license-manager-hard-limit-blocked-ec2-launch"


def rule():
    selected = [r for r in load_rules(product="aws") if r.technique_id == TECHNIQUE]
    assert len(selected) == 1
    return selected


def event(*, denied=True):
    row = {
        "eventSource": "ec2.amazonaws.com", "eventName": "RunInstances",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": "99999999-9999-4999-8999-000000000001",
        "eventTime": "2026-10-21T11:20:01Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": {"instancesSet": {"items": [{"imageId": IMAGE, "minCount": 1, "maxCount": 1}]}},
        "responseElements": None,
    }
    if denied:
        row["errorCode"] = "Client.InvalidState"
        row["errorMessage"] = "The license count for the synthetic license configuration was exceeded."
    else:
        row["responseElements"] = {"instancesSet": {"items": [{"instanceId": "i-synthetic00000001"}]}}
    return row


def hits(rows):
    return detect_aws_events(rows, rule())


def test_observed_license_limit_denial_matches():
    findings = hits([event()])
    assert len(findings) == 1
    assert findings[0].technique_id == TECHNIQUE
    assert findings[0].target_id == TARGET
    assert "synthetic license configuration" not in str(findings[0])


def test_success_wrong_reason_and_foreign_image_do_not_match():
    rows = [event(denied=False), event(), event(), event(), event()]
    rows[1]["errorMessage"] = "The instance is in an invalid state."
    rows[2]["errorCode"] = "Client.InsufficientInstanceCapacity"
    rows[3]["requestParameters"]["instancesSet"]["items"][0]["imageId"] = "foreign"
    rows[4]["eventSource"] = "other.amazonaws.com"
    assert hits(rows) == []


def test_malformed_failed_response_and_naive_timestamp_fail_closed():
    rows = [deepcopy(event()), deepcopy(event()), deepcopy(event())]
    rows[0]["responseElements"] = {"instancesSet": {"items": []}}
    rows[1]["eventTime"] = "2026-10-21T11:20:01"
    rows[2]["readOnly"] = True
    assert hits(rows) == []
