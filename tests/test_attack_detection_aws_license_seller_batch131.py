"""Synthetic derivatives of the isolated seller-issued License Manager labs."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
ARN = f"arn:aws:license-manager::{ACCOUNT}:license:l-synthetic00000001"
ENTITLEMENTS = [{"name": "Seats", "unit": "Count", "value": "1"}]
IDS = {
    "aws-license-manager-seller-license-created",
    "aws-license-manager-seller-license-read",
    "aws-license-manager-seller-licenses-listed",
    "aws-license-manager-seller-license-versions-listed",
    "aws-license-manager-seller-license-usage-read",
    "aws-license-manager-seller-license-borrowed",
    "aws-license-manager-seller-license-checked-out",
    "aws-license-manager-seller-license-checked-in",
    "aws-license-manager-seller-license-tagged",
    "aws-license-manager-seller-license-tags-read",
    "aws-license-manager-seller-license-untagged",
    "aws-license-manager-seller-license-deleted",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 12
    return selected


def event(name, index, request, response=None, *, read=False):
    return {
        "eventSource": "license-manager.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T09:20:{index:02d}Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    return [
        event("CreateLicense", 1, {"licenseName": "synthetic-license", "productSKU": "synthetic-sku",
                                    "beneficiary": ACCOUNT, "issuer": {"signKey": "synthetic-signing-key"}},
              {"licenseArn": ARN, "status": "AVAILABLE", "version": "1"}),
        event("GetLicense", 2, {"licenseArn": ARN}, read=True),
        event("ListLicenses", 3, {"licenseArns": [ARN]}, read=True),
        event("ListLicenseVersions", 4, {"licenseArn": ARN}, read=True),
        event("GetLicenseUsage", 5, {"licenseArn": ARN}, read=True),
        event("CheckoutBorrowLicense", 6, {"licenseArn": ARN, "entitlements": ENTITLEMENTS,
                                          "digitalSignatureMethod": "JWT_PS384"},
              {"licenseArn": ARN, "licenseConsumptionToken": "synthetic-borrow-token",
               "signedToken": "synthetic-offline-artifact"}),
        event("CheckoutLicense", 7, {"productSKU": "synthetic-sku", "keyFingerprint": "synthetic-fingerprint",
                                    "checkoutType": "PROVISIONAL", "entitlements": ENTITLEMENTS},
              {"licenseArn": ARN, "licenseConsumptionToken": "synthetic-provisional-token"}),
        event("CheckInLicense", 8, {"licenseConsumptionToken": "synthetic-provisional-token"}),
        event("TagResource", 9, {"resourceArn": ARN, "tags": [{"key": "LabStage", "value": "reviewed"}]}),
        event("ListTagsForResource", 10, {"resourceArn": ARN}, read=True),
        event("UntagResource", 11, {"resourceArn": ARN, "tagKeys": ["LabStage"]}),
        event("DeleteLicense", 12, {"licenseArn": ARN, "sourceVersion": "1"},
              {"status": "PENDING_DELETE"}),
    ]


def hits(rows):
    return detect_aws_events(rows, rules())


def test_twelve_observed_seller_license_routes_match():
    findings = hits(sample())
    assert len(findings) == 12
    assert {finding.technique_id for finding in findings} == IDS
    assert {finding.target_id for finding in findings} == {ARN, None}


def test_errors_foreign_response_and_malformed_events_fail_closed():
    rows = deepcopy(sample())
    rows[0]["responseElements"]["licenseArn"] = "foreign"
    rows[1]["errorCode"] = "AccessDeniedException"
    rows[2]["requestParameters"]["licenseArns"] = ["foreign"]
    rows[3]["eventSource"] = "other.amazonaws.com"
    rows[4]["readOnly"] = False
    rows[5]["responseElements"]["signedToken"] = ""
    rows[6]["responseElements"]["licenseConsumptionToken"] = ""
    rows[7]["requestParameters"]["licenseConsumptionToken"] = ""
    rows[8]["requestParameters"]["tags"] = []
    rows[9]["requestParameters"]["resourceArn"] = "foreign"
    rows[10]["requestParameters"]["tagKeys"] = []
    rows[11]["responseElements"]["status"] = "AVAILABLE"
    assert hits(rows) == []


def test_provisional_checkout_does_not_require_signed_token_or_expose_consumption_token():
    rows = [sample()[6]]
    finding = hits(rows)[0]
    assert finding.target_id == ARN
    assert "synthetic-provisional-token" not in str(finding)
    assert "signed token is not required" in finding.description.lower()
