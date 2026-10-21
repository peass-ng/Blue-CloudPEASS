"""Synthetic derivatives of isolated License Manager configuration labs."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
ARN = f"arn:aws:license-manager:{REGION}:{ACCOUNT}:license-configuration:lic-synthetic00000001"
IDS = {
    "aws-license-manager-configuration-created", "aws-license-manager-configuration-read",
    "aws-license-manager-configurations-listed", "aws-license-manager-configuration-usage-read",
    "aws-license-manager-configuration-associations-read",
    "aws-license-manager-configuration-hard-limit-set", "aws-license-manager-configuration-soft-limit-set",
    "aws-license-manager-configuration-tagged", "aws-license-manager-configuration-untagged",
    "aws-license-manager-configuration-deleted",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 10
    return selected


def event(name, index, request, response=None, *, read=False):
    return {
        "eventSource": "license-manager.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T08:55:{index:02d}Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    return [
        event("CreateLicenseConfiguration", 1, {"name": "synthetic-config", "licenseCountingType": "Instance",
                                                "licenseCount": 5, "licenseCountHardLimit": False},
              {"licenseConfigurationArn": ARN}),
        event("GetLicenseConfiguration", 2, {"licenseConfigurationArn": ARN}, read=True),
        event("ListLicenseConfigurations", 3, {"licenseConfigurationArns": [ARN]}, read=True),
        event("ListUsageForLicenseConfiguration", 4, {"licenseConfigurationArn": ARN}, read=True),
        event("ListAssociationsForLicenseConfiguration", 5, {"licenseConfigurationArn": ARN}, read=True),
        event("UpdateLicenseConfiguration", 6, {"licenseConfigurationArn": ARN,
                                                 "licenseCount": 1, "licenseCountHardLimit": True}),
        event("UpdateLicenseConfiguration", 7, {"licenseConfigurationArn": ARN,
                                                 "licenseCount": 5, "licenseCountHardLimit": False}),
        event("TagResource", 8, {"resourceArn": ARN, "tags": [{"key": "Environment", "value": "approved"}]}),
        event("UntagResource", 9, {"resourceArn": ARN, "tagKeys": ["Environment"]}),
        event("DeleteLicenseConfiguration", 10, {"licenseConfigurationArn": ARN}),
    ]


def hits(rows):
    return detect_aws_events(rows, rules())


def test_ten_observed_configuration_routes_match():
    findings = hits(sample())
    assert len(findings) == 10
    assert {finding.technique_id for finding in findings} == IDS
    assert {finding.target_id for finding in findings} == {ARN}


def test_failed_foreign_and_malformed_configuration_events_fail_closed():
    rows = deepcopy(sample())
    rows[0]["responseElements"]["licenseConfigurationArn"] = "foreign"
    rows[1]["errorCode"] = "InvalidParameterValueException"
    rows[2]["requestParameters"]["licenseConfigurationArns"] = ["bad"]
    rows[3]["eventSource"] = "other.amazonaws.com"
    rows[4]["readOnly"] = False
    rows[5]["requestParameters"]["licenseCountHardLimit"] = "true"
    rows[6]["requestParameters"]["licenseCount"] = True
    rows[7]["requestParameters"]["tags"] = []
    rows[8]["requestParameters"]["tagKeys"] = []
    rows[9]["errorCode"] = "AccessDeniedException"
    assert hits(rows) == []


def test_hard_limit_event_does_not_claim_blocked_ec2_launch():
    findings = hits(sample())
    hard = next(f for f in findings if f.technique_id.endswith("hard-limit-set"))
    assert "does not prove EC2 launches were blocked" in hard.description
