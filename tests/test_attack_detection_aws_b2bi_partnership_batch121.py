"""Synthetic derivatives of disposable B2BI capability and partnership tests."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
PROFILE = "p-syntheticprofile"
CAPABILITY = "ca-syntheticcapability"
PARTNERSHIP = "ps-syntheticpartnership"
TRANSFORMER = "tr-synthetictransformer"
IDS = {
    "aws-b2bi-capabilities-listed", "aws-b2bi-capability-read",
    "aws-b2bi-capability-updated", "aws-b2bi-capability-deleted",
    "aws-b2bi-partnerships-listed", "aws-b2bi-partnership-read",
    "aws-b2bi-partnership-updated", "aws-b2bi-partnership-deleted",
    "aws-b2bi-capability-transformer-selected",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 9
    return selected


def event(name, index, request, *, read=False, response=None):
    return {
        "eventSource": "b2bi.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T17:17:{index:02d}Z",
        "userIdentity": {"type": "AssumedRole", "accountId": ACCOUNT,
                         "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-lab/worker"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    return [
        event("ListCapabilities", 1, {"maxResults": 50}, read=True),
        event("GetCapability", 2, {"capabilityId": CAPABILITY}, read=True),
        event("UpdateCapability", 3, {"capabilityId": CAPABILITY, "name": "synthetic-capability"},
              response={"capabilityId": CAPABILITY}),
        event("DeleteCapability", 4, {"capabilityId": CAPABILITY}),
        event("ListPartnerships", 5, {"profileId": PROFILE, "maxResults": 50}, read=True),
        event("GetPartnership", 6, {"partnershipId": PARTNERSHIP}, read=True),
        event("UpdatePartnership", 7, {"partnershipId": PARTNERSHIP,
                                       "name": "synthetic-partnership"},
              response={"partnershipId": PARTNERSHIP}),
        event("DeletePartnership", 8, {"partnershipId": PARTNERSHIP}),
    ]


def rewire():
    return event("UpdateCapability", 9,
                 {"capabilityId": CAPABILITY, "configuration":
                  {"edi": {"transformerId": "***Sensitive Data Redacted***"}}},
                 response={"capabilityId": CAPABILITY,
                           "configuration": {"edi": {"transformerId": TRANSFORMER}}})


def hits(rows):
    return [finding.technique_id for finding in detect_aws_events(rows, rules())]


def test_eight_capability_and_partnership_routes_and_rewire_match():
    assert set(hits(sample() + [rewire()])) == IDS
    assert len(hits(sample() + [rewire()])) == 10  # Rewire also matches general UpdateCapability.


def test_failed_foreign_and_malformed_calls_fail_closed():
    rows = deepcopy(sample())
    rows[0]["readOnly"] = False
    rows[1]["requestParameters"]["capabilityId"] = "bad"
    rows[2]["requestParameters"] = {"capabilityId": CAPABILITY}
    rows[3]["errorCode"] = "ResourceNotFoundException"
    rows[4]["requestParameters"]["profileId"] = "bad"
    rows[5]["eventSource"] = "other.amazonaws.com"
    rows[6]["responseElements"] = {"errorCode": "AccessDeniedException"}
    rows[7]["requestParameters"]["partnershipId"] = "bad"
    assert hits(rows) == []


def test_rewire_requires_confirmed_transformer_in_response():
    row = rewire()
    assert set(hits([row])) == {"aws-b2bi-capability-updated",
                                "aws-b2bi-capability-transformer-selected"}
    row["responseElements"]["capabilityId"] = "ca-other"
    assert hits([row]) == ["aws-b2bi-capability-updated"]
    row["errorCode"] = "AccessDeniedException"
    assert hits([row]) == []
