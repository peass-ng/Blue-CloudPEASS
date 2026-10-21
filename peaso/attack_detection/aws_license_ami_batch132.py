"""License Manager association changes on an EC2 AMI."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_CONFIG = re.compile(r"arn:aws:license-manager:[a-z0-9-]+:[0-9]{12}:license-configuration:[A-Za-z0-9-]+\Z")


def _specs(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(
        isinstance(spec, Mapping) and isinstance(spec.get("licenseConfigurationArn"), str)
        and _CONFIG.fullmatch(spec["licenseConfigurationArn"]) for spec in value
    )


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name = record.get("eventName")
    if name not in ("UpdateLicenseSpecificationsForResource", "ListLicenseSpecificationsForResource"):
        return []
    request, response = record.get("requestParameters"), record.get("responseElements")
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if (record.get("eventSource") != "license-manager.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name == "ListLicenseSpecificationsForResource")
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str)
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
    target = request.get("resourceArn")
    if not isinstance(target, str) or not re.fullmatch(
            rf"arn:aws:ec2:{re.escape(region)}:{re.escape(account)}:image/ami-[0-9a-f]+", target):
        return []

    signals: list[tuple[str, str]] = []
    if name == "ListLicenseSpecificationsForResource":
        signals.append(("AmiLicenseSpecificationsRead", "request.ami_license_specifications_read"))
    else:
        if _specs(request.get("addLicenseSpecifications")):
            signals.append(("AmiLicenseSpecificationAdded", "request.ami_license_specification_added"))
        if _specs(request.get("removeLicenseSpecifications")):
            signals.append(("AmiLicenseSpecificationRemoved", "request.ami_license_specification_removed"))
    actor = record.get("userIdentity")
    base = {
        "cloud.provider": "aws", "event.source": "license-manager.amazonaws.com",
        "event.outcome": "success", "event.id": record["eventID"],
        "event.time": record["eventTime"], "account.id": account,
        "actor.id": actor.get("arn") if isinstance(actor, Mapping) else None,
        "target.id": target,
    }
    return [{**base, "event.name": event, flag: True} for event, flag in signals]
