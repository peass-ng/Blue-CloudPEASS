"""Synthetic derivatives of Marketplace dashboard CloudTrail failures."""

from copy import deepcopy

from peaso.attack_detection.aws_marketplace_dashboard_batch198 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
BASE = f"arn:aws:aws-marketplace::{ACCOUNT}:AWSMarketplace/ReportingData/"


def event():
    return {
        "eventSource": "reporting-marketplace.amazonaws.com",
        "eventName": "GetBuyerDashboard", "eventType": "AwsApiCall",
        "eventCategory": "Management", "managementEvent": True, "readOnly": True,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventID": "synthetic-event", "eventTime": "2026-10-22T00:00:00Z",
        "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
        "requestParameters": {
            "dashboardIdentifier": BASE + "Agreement_V1/Dashboard/AgreementSummary_V1",
            "embeddingDomains": ["https://example.invalid"],
        },
        "resources": [{"ARN": BASE + "Agreement_V1/Dashboard/AgreementSummary_V1",
                       "accountId": ACCOUNT, "type": None}],
        "responseElements": {"embedUrl": "https://example.invalid/?token=synthetic-sensitive"},
    }


def rule():
    return Rule(
        id="19800000-0000-4000-8000-000000000004",
        title="Marketplace buyer dashboard URL requested", level="medium",
        description="Accepted dashboard URL request", technique_id="aws-marketplace-buyer-dashboard-url-requested",
        product="aws", selection={
            "event.source": "reporting-marketplace.amazonaws.com",
            "event.name": "GetBuyerDashboard", "event.outcome": "success",
            "request.marketplace_buyer_dashboard_url_requested": True,
        },
    )


def test_dashboard_signal_survives_untyped_resource_without_exposing_url():
    row = event()
    signals = normalize(row)
    assert len(signals) == 1
    assert signals[0]["request.marketplace_buyer_dashboard_url_requested"] is True
    assert signals[0]["target.id"].startswith("sha256:")
    assert "synthetic-sensitive" not in str(signals)
    assert "example.invalid" not in str(signals)
    found = detect_aws_events([row], (rule(),))
    assert len(found) == 1
    assert "synthetic-sensitive" not in str(found)
    localhost = deepcopy(row)
    localhost["requestParameters"]["embeddingDomains"] = ["http://localhost:8080"]
    assert normalize(localhost)[0]["request.marketplace_buyer_dashboard_url_requested"] is True


def test_dashboard_requires_success_and_supported_own_account_target():
    row = event()
    for key, value in (("errorCode", "UnauthorizedException"),
                       ("readOnly", False), ("eventCategory", "Data"),
                       ("eventSource", "other.amazonaws.com")):
        altered = deepcopy(row)
        altered[key] = value
        assert normalize(altered) == []
    for key, value in (
        ("dashboardIdentifier", BASE.replace(ACCOUNT, "888888888888") + "Agreement_V1/Dashboard/AgreementSummary_V1"),
        ("dashboardIdentifier", BASE + "Unknown/Dashboard/Other"),
        ("embeddingDomains", []),
    ):
        altered = deepcopy(row)
        altered["requestParameters"][key] = value
        assert normalize(altered) == []
    service = deepcopy(row)
    service["userIdentity"]["invokedBy"] = "reporting-marketplace.amazonaws.com"
    assert normalize(service) == []
