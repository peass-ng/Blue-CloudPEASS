"""Synthetic derivatives of disposable B2BI profile and transformer tests."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
PROFILE = "p-syntheticprofile"
TRANSFORMER = "tr-synthetictransformer"
IDS = {
    "aws-b2bi-profiles-listed", "aws-b2bi-profile-read",
    "aws-b2bi-profile-updated", "aws-b2bi-profile-deleted",
    "aws-b2bi-transformers-listed", "aws-b2bi-transformer-read",
    "aws-b2bi-transformer-updated", "aws-b2bi-transformer-deleted",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 8
    return selected


def event(name, index, request, *, read=False, response=None):
    return {
        "eventSource": "b2bi.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T16:16:{index:02d}Z",
        "userIdentity": {"type": "AssumedRole", "accountId": ACCOUNT,
                         "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-lab/worker"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    return [
        event("ListProfiles", 1, {"maxResults": 50}, read=True),
        event("GetProfile", 2, {"profileId": PROFILE}, read=True),
        event("UpdateProfile", 3, {"profileId": PROFILE,
                                   "businessName": "Synthetic Lab Business"},
              response={"profileId": PROFILE}),
        event("DeleteProfile", 4, {"profileId": PROFILE}),
        event("ListTransformers", 5, {"maxResults": 50}, read=True),
        event("GetTransformer", 6, {"transformerId": TRANSFORMER}, read=True),
        event("UpdateTransformer", 7, {"transformerId": TRANSFORMER,
                                       "name": "synthetic-transformer"},
              response={"transformerId": TRANSFORMER}),
        event("DeleteTransformer", 8, {"transformerId": TRANSFORMER}),
    ]


def hits(rows):
    return [finding.technique_id for finding in detect_aws_events(rows, rules())]


def test_eight_discovery_update_and_delete_routes_match():
    assert set(hits(sample())) == IDS
    assert len(hits(sample())) == 8


def test_failed_foreign_and_malformed_calls_fail_closed():
    rows = deepcopy(sample())
    rows[0]["readOnly"] = False
    rows[1]["requestParameters"]["profileId"] = "bad"
    rows[2]["requestParameters"] = {"profileId": PROFILE}
    rows[3]["errorCode"] = "ResourceNotFoundException"
    rows[4]["eventSource"] = "other.amazonaws.com"
    rows[5]["recipientAccountId"] = "not-an-account"
    rows[6]["responseElements"] = {"errorCode": "AccessDeniedException"}
    rows[7]["requestParameters"]["transformerId"] = "bad"
    assert hits(rows) == []


def test_read_response_can_be_redacted_and_updates_do_not_claim_permission_gap():
    rows = sample()
    for i in (0, 1, 4, 5):
        rows[i]["responseElements"] = None
    findings = detect_aws_events(rows, rules())
    assert len(findings) == 8
    for finding in findings:
        assert "get_denied" not in finding.evidence
        assert "businessName" not in finding.evidence
