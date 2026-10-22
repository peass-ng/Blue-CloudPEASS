"""CloudTrail signal for Marketplace buyer dashboard URL requests."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_DASHBOARDS = {
    "Agreement_V1/Dashboard/AgreementSummary_V1",
    "BillingEvent_V1/Dashboard/CostAnalysis_V1",
}


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Identify accepted URL requests without reading or emitting bearer URLs."""
    if (record.get("eventSource") != "reporting-marketplace.amazonaws.com"
            or record.get("eventName") != "GetBuyerDashboard"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not True
            or record.get("errorCode") or record.get("errorMessage")):
        return []
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    event_id, stamp = record.get("eventID"), record.get("eventTime")
    request, identity = record.get("requestParameters"), record.get("userIdentity")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(event_id, str) or not 0 < len(event_id) <= 128
            or not isinstance(stamp, str)
            or not isinstance(request, Mapping) or not isinstance(identity, Mapping)
            or identity.get("invokedBy") or identity.get("type") == "AWSService"):
        return []
    try:
        if datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
            return []
    except ValueError:
        return []
    arn = request.get("dashboardIdentifier")
    prefix = f"arn:aws:aws-marketplace::{account}:AWSMarketplace/ReportingData/"
    if not isinstance(arn, str) or not arn.startswith(prefix) or arn[len(prefix):] not in _DASHBOARDS:
        return []
    domains = request.get("embeddingDomains")
    if (not isinstance(domains, list) or not 1 <= len(domains) <= 2
            or any(not isinstance(value, str) or not 1 <= len(value) <= 2000
                   for value in domains)):
        return []
    actor = identity.get("arn")
    if actor is not None and (not isinstance(actor, str) or len(actor) > 2048):
        return []
    return [{
        "cloud.provider": "aws", "event.source": "reporting-marketplace.amazonaws.com",
        "event.name": "GetBuyerDashboard", "event.outcome": "success",
        "event.id": event_id, "event.time": stamp, "account.id": account,
        "actor.id": actor,
        "target.id": "sha256:" + hashlib.sha256(arn.encode()).hexdigest()[:24],
        "request.marketplace_buyer_dashboard_url_requested": True,
    }]
