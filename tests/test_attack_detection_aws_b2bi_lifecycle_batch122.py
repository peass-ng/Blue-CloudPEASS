"""Synthetic derivatives of a disposable B2BI transformer and tag lab."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
PROFILE = "p-syntheticprofile"
TRANSFORMER = "tr-synthetictransformer"
CAPABILITY = "ca-syntheticcapability"
PARTNERSHIP = "ps-syntheticpartnership"
CAP_ARN = f"arn:aws:b2bi:{REGION}:{ACCOUNT}:capability/{CAPABILITY}"
IDS = {
    "aws-b2bi-transformer-created", "aws-b2bi-transformer-activated",
    "aws-b2bi-capability-created", "aws-b2bi-partnership-created",
    "aws-b2bi-resource-tags-read", "aws-b2bi-resource-tagged",
    "aws-b2bi-resource-untagged",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 7
    return selected


def event(name, index, request, *, read=False, response=None):
    return {
        "eventSource": "b2bi.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T18:18:{index:02d}Z",
        "userIdentity": {"type": "AssumedRole", "accountId": ACCOUNT,
                         "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-lab/worker"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    return [
        event("CreateTransformer", 1, {"name": "synthetictransformer"},
              response={"transformerId": TRANSFORMER, "status": "inactive"}),
        event("UpdateTransformer", 2,
              {"transformerId": TRANSFORMER, "status": "active"},
              response={"transformerId": TRANSFORMER, "status": "active"}),
        event("CreateCapability", 3,
              {"name": "syntheticcapability", "type": "edi",
               "configuration": {"edi": {"transformerId": "HIDDEN_DUE_TO_SECURITY_REASONS"}}},
              response={"capabilityId": CAPABILITY}),
        event("CreatePartnership", 4,
              {"name": "syntheticpartnership", "profileId": PROFILE,
               "capabilities": [CAPABILITY]},
              response={"partnershipId": PARTNERSHIP, "profileId": PROFILE}),
        event("ListTagsForResource", 5, {"resourceARN": CAP_ARN}, read=True),
        event("TagResource", 6, {"resourceARN": CAP_ARN,
                                 "tags": [{"key": "lab-phase", "value": "tagged"}]}),
        event("UntagResource", 7, {"resourceARN": CAP_ARN,
                                   "tagKeys": ["lab-phase"]}),
    ]


def hits(rows):
    return [finding.technique_id for finding in detect_aws_events(rows, rules())]


def test_seven_lifecycle_and_tag_routes_match():
    assert set(hits(sample())) == IDS
    assert len(hits(sample())) == 7


def test_failed_foreign_and_malformed_calls_fail_closed():
    rows = deepcopy(sample())
    rows[0]["responseElements"]["transformerId"] = "bad"
    rows[1]["responseElements"]["status"] = "inactive"
    rows[2]["requestParameters"]["configuration"] = None
    rows[3]["responseElements"]["profileId"] = "p-other"
    rows[4]["requestParameters"]["resourceARN"] = CAP_ARN.replace(ACCOUNT, "111111111111")
    rows[5]["requestParameters"]["tags"] = []
    rows[6]["errorCode"] = "ResourceNotFoundException"
    assert hits(rows) == []


def test_tag_payloads_are_not_exposed_in_findings():
    rows = sample()[4:]
    findings = detect_aws_events(rows, rules())
    assert len(findings) == 3
    assert all("lab-phase" not in str(finding.evidence) for finding in findings)
    assert all(finding.target_id == CAP_ARN for finding in findings)
