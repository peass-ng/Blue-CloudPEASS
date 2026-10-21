"""Synthetic derivatives of an isolated License Manager instance association lab."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
INSTANCE = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0123456789abcdef0"
CONFIG = f"arn:aws:license-manager:{REGION}:{ACCOUNT}:license-configuration:lic-synthetic00000001"
IDS = {
    "aws-license-manager-instance-license-specification-added",
    "aws-license-manager-instance-license-specification-removed",
    "aws-license-manager-instance-license-specifications-read",
}


def rules():
    selected = [r for r in load_rules(product="aws") if r.technique_id in IDS]
    assert len(selected) == 3
    return selected


def event(name, number, request, read=False):
    return {
        "eventSource": "license-manager.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{number:012d}",
        "eventTime": f"2026-10-21T10:20:{number:02d}Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": None,
    }


def sample():
    spec = [{"licenseConfigurationArn": CONFIG}]
    return [
        event("UpdateLicenseSpecificationsForResource", 1,
              {"resourceArn": INSTANCE, "addLicenseSpecifications": spec}),
        event("ListLicenseSpecificationsForResource", 2, {"resourceArn": INSTANCE}, read=True),
        event("UpdateLicenseSpecificationsForResource", 3,
              {"resourceArn": INSTANCE, "removeLicenseSpecifications": spec}),
    ]


def hits(rows):
    return detect_aws_events(rows, rules())


def test_observed_instance_association_routes_match():
    findings = hits(sample())
    assert len(findings) == 3
    assert {f.technique_id for f in findings} == IDS
    assert {f.target_id for f in findings} == {INSTANCE}


def test_errors_foreign_instance_and_invalid_specs_fail_closed():
    rows = deepcopy(sample())
    rows[0]["requestParameters"]["resourceArn"] = "foreign"
    rows[1]["errorCode"] = "AccessDeniedException"
    rows[2]["requestParameters"]["removeLicenseSpecifications"] = [{"licenseConfigurationArn": "foreign"}]
    assert hits(rows) == []


def test_addition_does_not_claim_termination():
    finding = next(f for f in hits(sample()) if f.technique_id.endswith("specification-added"))
    assert "can change license consumption without terminating the instance" in finding.description
