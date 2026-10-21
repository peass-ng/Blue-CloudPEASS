"""Synthetic derivatives of an isolated pending CodeConnections lab."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
CONNECTION = "11111111-1111-4111-8111-111111111111"
ARN = f"arn:aws:codeconnections:{REGION}:{ACCOUNT}:connection/{CONNECTION}"
IDS = {
    "aws-codeconnections-connection-created", "aws-codeconnections-connection-read",
    "aws-codeconnections-connections-listed", "aws-codeconnections-hosts-listed",
    "aws-codeconnections-repository-links-listed", "aws-codeconnections-connection-tags-read",
    "aws-codeconnections-connection-tagged", "aws-codeconnections-connection-untagged",
    "aws-codeconnections-connection-deleted",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 9
    return selected


def event(name, index, request, response=None, *, read=False):
    return {
        "eventSource": "codeconnections.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T08:30:{index:02d}Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    return [
        event("CreateConnection", 1, {"connectionName": "synthetic-connection", "providerType": "GitHub", "tags": []},
              {"connectionArn": ARN}),
        event("GetConnection", 2, {"connectionArn": ARN}, read=True),
        event("ListConnections", 3, {"providerTypeFilter": "GitHub", "maxResults": 100}, read=True),
        event("ListHosts", 4, {"maxResults": 1}, read=True),
        event("ListRepositoryLinks", 5, {"maxResults": 1}, read=True),
        event("ListTagsForResource", 6, {"resourceArn": ARN}, read=True),
        event("TagResource", 7, {"resourceArn": ARN, "tags": [{"key": "Environment", "value": "approved"}]}),
        event("UntagResource", 8, {"resourceArn": ARN, "tagKeys": ["Environment"]}),
        event("DeleteConnection", 9, {"connectionArn": ARN}),
    ]


def hits(rows):
    return detect_aws_events(rows, rules())


def test_nine_observed_connection_routes_match():
    findings = hits(sample())
    assert len(findings) == 9
    assert {finding.technique_id for finding in findings} == IDS
    assert [finding.target_id for finding in findings] == [ARN, ARN, None, None, None, ARN, ARN, ARN, ARN]


def test_failed_foreign_and_malformed_connection_events_fail_closed():
    rows = deepcopy(sample())
    rows[0]["responseElements"]["connectionArn"] = "foreign"
    rows[1]["errorCode"] = "ResourceNotFoundException"
    rows[2]["requestParameters"]["maxResults"] = -1
    rows[3]["eventSource"] = "other.amazonaws.com"
    rows[4]["readOnly"] = False
    rows[5]["requestParameters"]["resourceArn"] = "invalid"
    rows[6]["requestParameters"]["tags"] = []
    rows[7]["requestParameters"]["tagKeys"] = []
    rows[8]["errorCode"] = "AccessDeniedException"
    assert hits(rows) == []


def test_pending_connection_does_not_imply_provider_access_or_abac_bypass():
    findings = hits(sample())
    assert len(findings) == 9
    assert not any("InstallationUpdated" in finding.technique_id or "ProviderAccess" in finding.technique_id
                   for finding in findings)
