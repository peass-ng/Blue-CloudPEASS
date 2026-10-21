"""License Manager seller-issued license management and consumption signals."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_LICENSE = re.compile(r"arn:aws:license-manager::[0-9]{12}:license:l-[A-Za-z0-9-]+\Z")
_ROUTES = {
    "CreateLicense": ("SellerLicenseCreated", "request.seller_license_created", False),
    "GetLicense": ("SellerLicenseRead", "request.seller_license_read", True),
    "ListLicenses": ("SellerLicensesListed", "request.seller_licenses_listed", True),
    "ListLicenseVersions": ("SellerLicenseVersionsListed", "request.seller_license_versions_listed", True),
    "GetLicenseUsage": ("SellerLicenseUsageRead", "request.seller_license_usage_read", True),
    "CheckoutBorrowLicense": ("SellerLicenseBorrowed", "request.seller_license_borrowed", False),
    "CheckoutLicense": ("SellerLicenseCheckedOut", "request.seller_license_checked_out", False),
    "CheckInLicense": ("SellerLicenseCheckedIn", "request.seller_license_checked_in", False),
    "TagResource": ("SellerLicenseTagged", "request.seller_license_tagged", False),
    "ListTagsForResource": ("SellerLicenseTagsRead", "request.seller_license_tags_read", True),
    "UntagResource": ("SellerLicenseUntagged", "request.seller_license_untagged", False),
    "DeleteLicense": ("SellerLicenseDeleted", "request.seller_license_deleted", False),
}


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _entitlements(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(
        isinstance(v, Mapping) and _text(v.get("name")) and _text(v.get("unit"))
        and _text(v.get("value")) for v in value
    )


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name = record.get("eventName")
    route = _ROUTES.get(name) if isinstance(name, str) else None
    request, response = record.get("requestParameters"), record.get("responseElements")
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if (route is None or record.get("eventSource") != "license-manager.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not route[2]
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not _text(record.get("eventID")) or not _text(record.get("eventTime"))
            or not isinstance(request, Mapping)):
        return []
    if isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")):
        return []
    try:
        stamp = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return []
    except ValueError:
        return []

    target: str | None = None
    if name == "CreateLicense":
        if (not _text(request.get("licenseName")) or not _text(request.get("productSKU"))
                or not _text(request.get("beneficiary")) or not isinstance(request.get("issuer"), Mapping)
                or not _text(request["issuer"].get("signKey")) or not isinstance(response, Mapping)):
            return []
        target = response.get("licenseArn")
        if not isinstance(target, str) or not target.startswith(f"arn:aws:license-manager::{account}:license:"):
            return []
    elif name == "ListLicenses":
        arns = request.get("licenseArns")
        if arns is not None:
            if not isinstance(arns, list) or not arns or not all(isinstance(v, str) and _LICENSE.fullmatch(v) for v in arns):
                return []
            if len(arns) == 1:
                target = arns[0]
        filters = request.get("filters")
        if filters is not None and (not isinstance(filters, list) or not all(
                isinstance(v, Mapping) and _text(v.get("name")) and isinstance(v.get("values"), list)
                for v in filters)):
            return []
    elif name == "CheckoutLicense":
        if (request.get("checkoutType") not in ("PROVISIONAL", "PERPETUAL")
                or not _text(request.get("productSKU")) or not _text(request.get("keyFingerprint"))
                or not _entitlements(request.get("entitlements"))
                or not isinstance(response, Mapping) or not _text(response.get("licenseConsumptionToken"))):
            return []
        target = response.get("licenseArn")
    elif name == "CheckoutBorrowLicense":
        if (request.get("digitalSignatureMethod") != "JWT_PS384"
                or not _entitlements(request.get("entitlements"))
                or not isinstance(response, Mapping)
                or not _text(response.get("licenseConsumptionToken"))
                or not _text(response.get("signedToken"))):
            return []
        target = request.get("licenseArn")
        if response.get("licenseArn") != target:
            return []
    elif name == "CheckInLicense":
        if not _text(request.get("licenseConsumptionToken")):
            return []
    else:
        target = request.get("resourceArn") if name in ("TagResource", "ListTagsForResource", "UntagResource") else request.get("licenseArn")

    if target is not None and (not isinstance(target, str) or not _LICENSE.fullmatch(target)):
        return []
    if target is None and name not in ("ListLicenses", "CheckInLicense"):
        return []
    if name == "TagResource" and (not isinstance(request.get("tags"), list) or not request["tags"]
                                  or not all(isinstance(v, Mapping) and _text(v.get("key"))
                                                 and isinstance(v.get("value"), str) for v in request["tags"])):
        return []
    if name == "UntagResource" and (not isinstance(request.get("tagKeys"), list) or not request["tagKeys"]
                                    or not all(_text(v) for v in request["tagKeys"])):
        return []
    if name == "DeleteLicense" and (not _text(request.get("sourceVersion"))
                                    or not isinstance(response, Mapping)
                                    or response.get("status") not in ("PENDING_DELETE", "DELETED")):
        return []

    actor = record.get("userIdentity")
    synthetic, flag, _ = route
    return [{
        "cloud.provider": "aws", "event.source": "license-manager.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account,
        "actor.id": actor.get("arn") if isinstance(actor, Mapping) else None,
        "target.id": target, flag: True,
    }]
