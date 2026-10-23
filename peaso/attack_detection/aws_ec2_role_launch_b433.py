"""Accepted EC2 launch routes carrying an instance profile and user data."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_PROFILE = re.compile(r"arn:aws:iam::([0-9]{12}):instance-profile/.{1,512}\Z")
_TEMPLATE = re.compile(r"lt-[0-9a-f]{8,17}\Z")
_SPOT = re.compile(r"sir-[a-z0-9]{8,32}\Z")
_FLAGS = {
    "CreateLaunchTemplate": "request.ec2_role_user_data_template_created",
    "RequestSpotInstances": "request.ec2_role_user_data_spot_requested",
}


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """User data is redacted by EC2 CloudTrail and is never copied to alerts."""
    name = record.get("eventName")
    if (record.get("eventSource") != "ec2.amazonaws.com"
            or name not in _FLAGS
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request, response = record.get("userIdentity"), record.get("requestParameters"), record.get("responseElements")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or identity.get("type") == "AWSService"
            or not isinstance(identity.get("arn"), str) or not identity["arn"]
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    if name == "CreateLaunchTemplate":
        req = _map(request.get("CreateLaunchTemplateRequest"))
        data = _map(req.get("LaunchTemplateData"))
        profile = _map(data.get("IamInstanceProfile")).get("Arn")
        user_data = data.get("UserData")
        template = _map(_map(response.get("CreateLaunchTemplateResponse")).get("launchTemplate"))
        resource = template.get("launchTemplateId")
        if (not isinstance(resource, str) or not _TEMPLATE.fullmatch(resource)
                or template.get("launchTemplateName") != req.get("LaunchTemplateName")):
            return None
    else:
        data = _map(request.get("launchSpecification"))
        profile = _map(data.get("iamInstanceProfile")).get("arn")
        user_data = data.get("userData")
        items = _map(response.get("spotInstanceRequestSet")).get("items")
        if not isinstance(items, list) or not items or not isinstance(items[0], Mapping):
            return None
        resource = items[0].get("spotInstanceRequestId")
        if not isinstance(resource, str) or not _SPOT.fullmatch(resource):
            return None
    if (not isinstance(profile, str) or not (match := _PROFILE.fullmatch(profile))
            or match.group(1) != account
            or not isinstance(user_data, str) or not user_data):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None
    target = "sha256:" + hashlib.sha256(
        ":".join((account, region, resource, profile)).encode()
    ).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "ec2.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": target,
        _FLAGS[name]: True,
    }
