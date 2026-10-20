"""Synthetic derivatives of five owned CloudFormation configuration reads."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "us-east-1"
STACK = "synthetic-cfn-stack"
CHANGE_SET = "synthetic-change-set"
ACTOR = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-reader/test"
RULE_IDS = {
    "25a79f10-9777-43f9-90b4-c681a40c42d7",
    "3b3b984c-b001-4c24-b2c8-844f453721fa",
    "2c534779-717e-475c-8e06-4a1a653a57d9",
    "0542a656-d588-4e3d-b2f0-d94709c1eb06",
    "a2916f4a-7558-4ee0-9a29-c456e503f6b4",
}
NAMES = ("DescribeStacks", "GetTemplate", "GetTemplateSummary",
         "ListExports", "DescribeChangeSet")


def event(name, ordinal):
    request = (None if name == "ListExports" else {"stackName": STACK})
    if name == "DescribeChangeSet":
        request["changeSetName"] = CHANGE_SET
    return {
        "eventSource": "cloudformation.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": True,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"11111111-1111-4111-8111-{ordinal:012d}",
        "eventTime": f"2026-01-01T00:00:{ordinal:02d}+00:00",
        "userIdentity": {"type": "AssumedRole", "accountId": ACCOUNT, "arn": ACTOR},
        "requestParameters": request, "responseElements": None,
    }


def rules():
    return [rule for rule in load_rules(product="aws") if rule.id in RULE_IDS]


def test_five_cloudformation_read_routes_match_without_values():
    found = detect_aws_events([event(name, i + 1) for i, name in enumerate(NAMES)], rules())
    assert len(found) == 5
    assert {item.rule_id for item in found} == RULE_IDS
    assert "synthetic-default-value" not in str(found)


def test_cloudformation_reads_reject_failed_or_unscoped_calls():
    for name in NAMES:
        source = event(name, 1)
        for edit in ({"errorCode": "AccessDenied"}, {"readOnly": False},
                     {"eventCategory": "Data"}):
            changed = deepcopy(source)
            changed.update(edit)
            assert not detect_aws_events([changed], rules())
    for name in ("DescribeStacks", "GetTemplate", "GetTemplateSummary", "DescribeChangeSet"):
        changed = event(name, 1)
        changed["requestParameters"].pop("stackName")
        assert not detect_aws_events([changed], rules())
    changed = event("DescribeChangeSet", 1)
    changed["requestParameters"].pop("changeSetName")
    assert not detect_aws_events([changed], rules())


def test_cloudformation_reads_do_not_emit_response_content():
    source = event("DescribeStacks", 1)
    source["responseElements"] = {"stackOutput": "synthetic-default-value"}
    found = detect_aws_events([source], rules())
    assert len(found) == 1
    assert "synthetic-default-value" not in str(found)
