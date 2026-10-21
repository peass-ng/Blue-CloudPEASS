"""License Manager self-managed configuration control-plane signals."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_CONFIG_ID = re.compile(r"[A-Za-z0-9-]{3,64}\Z")
_ROUTES = {
    "CreateLicenseConfiguration": ("LicenseConfigurationCreated", "request.license_configuration_created", False),
    "GetLicenseConfiguration": ("LicenseConfigurationRead", "request.license_configuration_read", True),
    "ListLicenseConfigurations": ("LicenseConfigurationsListed", "request.license_configurations_listed", True),
    "ListUsageForLicenseConfiguration": ("LicenseConfigurationUsageRead", "request.license_configuration_usage_read", True),
    "ListAssociationsForLicenseConfiguration": ("LicenseConfigurationAssociationsRead", "request.license_configuration_associations_read", True),
    "TagResource": ("LicenseConfigurationTagged", "request.license_configuration_tagged", False),
    "UntagResource": ("LicenseConfigurationUntagged", "request.license_configuration_untagged", False),
    "DeleteLicenseConfiguration": ("LicenseConfigurationDeleted", "request.license_configuration_deleted", False),
}


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name = record.get("eventName")
    route = _ROUTES.get(name) if isinstance(name, str) else None
    if name == "UpdateLicenseConfiguration":
        route = ("LicenseConfigurationHardLimitSet", "request.license_configuration_hard_limit_set", False)
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (route is None or record.get("eventSource") != "license-manager.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not route[2]
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

    if name == "CreateLicenseConfiguration":
        if (not isinstance(request.get("name"), str) or not request["name"]
                or request.get("licenseCountingType") not in ("Instance", "vCPU", "Core", "Socket")
                or not isinstance(response, Mapping)):
            return []
        target = response.get("licenseConfigurationArn")
    elif name == "ListLicenseConfigurations":
        arns = request.get("licenseConfigurationArns")
        if arns is not None and (not isinstance(arns, list) or not all(isinstance(v, str) for v in arns)):
            return []
        if arns and len(arns) == 1:
            target = arns[0]
        else:
            target = None
    else:
        target = request.get("resourceArn") if name in ("TagResource", "UntagResource") else request.get("licenseConfigurationArn")

    prefix = f"arn:aws:license-manager:{region}:{account}:license-configuration:"
    if target is not None:
        if not isinstance(target, str) or not target.startswith(prefix) or not _CONFIG_ID.fullmatch(target[len(prefix):]):
            return []
    elif name != "ListLicenseConfigurations":
        return []
    if name == "ListLicenseConfigurations" and request.get("licenseConfigurationArns"):
        if not all(v.startswith(prefix) and _CONFIG_ID.fullmatch(v[len(prefix):]) for v in request["licenseConfigurationArns"]):
            return []
    if name == "UpdateLicenseConfiguration":
        hard = request.get("licenseCountHardLimit")
        count = request.get("licenseCount")
        if not isinstance(hard, bool) or not isinstance(count, int) or isinstance(count, bool) or count < 0:
            return []
        if hard is False:
            route = ("LicenseConfigurationSoftLimitSet", "request.license_configuration_soft_limit_set", False)
    if name == "TagResource":
        tags = request.get("tags")
        if not isinstance(tags, list) or not tags or not all(
                isinstance(tag, Mapping) and isinstance(tag.get("key"), str)
                and tag["key"] and isinstance(tag.get("value"), str) for tag in tags):
            return []
    if name == "UntagResource":
        keys = request.get("tagKeys")
        if not isinstance(keys, list) or not keys or not all(isinstance(key, str) and key for key in keys):
            return []

    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    synthetic, flag, _ = route
    return [{
        "cloud.provider": "aws", "event.source": "license-manager.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": actor,
        "target.id": target, flag: True,
    }]
