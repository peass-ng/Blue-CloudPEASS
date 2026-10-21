"""Synthetic derivatives of an isolated pending CodeConnections host lab."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
HOST = "h-synthetic00000001"
ARN = f"arn:aws:codeconnections:{REGION}:{ACCOUNT}:host/{HOST}"
IDS = {
    "aws-codeconnections-host-created", "aws-codeconnections-host-read",
    "aws-codeconnections-host-tags-read", "aws-codeconnections-host-tagged",
    "aws-codeconnections-host-untagged", "aws-codeconnections-host-deleted",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 6
    return selected


def event(name, index, request, response=None, *, read=False):
    return {
        "eventSource": "codeconnections.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T08:45:{index:02d}Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    return [
        event("CreateHost", 1, {"name": "synthetic-host", "providerType": "GitHubEnterpriseServer",
                                "providerEndpoint": "https://git.example.invalid"}, {"hostArn": ARN}),
        event("GetHost", 2, {"hostArn": ARN}, read=True),
        event("ListTagsForResource", 3, {"resourceArn": ARN}, read=True),
        event("TagResource", 4, {"resourceArn": ARN, "tags": [{"key": "Environment", "value": "approved"}]}),
        event("UntagResource", 5, {"resourceArn": ARN, "tagKeys": ["Environment"]}),
        event("DeleteHost", 6, {"hostArn": ARN}),
    ]


def hits(rows):
    return detect_aws_events(rows, rules())


def test_six_pending_host_routes_match():
    findings = hits(sample())
    assert len(findings) == 6
    assert {finding.technique_id for finding in findings} == IDS
    assert {finding.target_id for finding in findings} == {ARN}


def test_failed_foreign_and_malformed_host_events_fail_closed():
    rows = deepcopy(sample())
    rows[0]["responseElements"]["hostArn"] = "foreign"
    rows[1]["errorCode"] = "ResourceNotFoundException"
    rows[2]["requestParameters"]["resourceArn"] = "invalid"
    rows[3]["requestParameters"]["tags"] = []
    rows[4]["requestParameters"]["tagKeys"] = []
    rows[5]["eventSource"] = "other.amazonaws.com"
    assert hits(rows) == []


def test_pending_host_does_not_imply_external_access():
    findings = hits(sample())
    assert len(findings) == 6
    assert not any("ProviderAvailable" in finding.technique_id or "RepositoryRead" in finding.technique_id
                   for finding in findings)
