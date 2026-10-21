"""EC2 launch denied because an associated License Manager count was exceeded."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_IMAGE = re.compile(r"ami-[0-9a-f]+\Z")


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request = record.get("requestParameters")
    reason = record.get("errorMessage")
    if (record.get("eventSource") != "ec2.amazonaws.com"
            or record.get("eventName") != "RunInstances"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") != "Client.InvalidState"
            or not isinstance(reason, str)
            or not ("license count" in reason.lower() and "exceeded" in reason.lower())
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str)
            or not isinstance(request, Mapping)
            or record.get("responseElements") not in (None, {})):
        return []
    try:
        stamp = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return []
    except ValueError:
        return []
    instances = request.get("instancesSet")
    items = instances.get("items") if isinstance(instances, Mapping) else None
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], Mapping):
        return []
    image = items[0].get("imageId")
    if not isinstance(image, str) or not _IMAGE.fullmatch(image):
        return []
    actor = record.get("userIdentity")
    return [{
        "cloud.provider": "aws", "event.source": "ec2.amazonaws.com",
        "event.name": "LicenseCountBlockedRunInstances", "event.outcome": "failure",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account,
        "actor.id": actor.get("arn") if isinstance(actor, Mapping) else None,
        "target.id": f"arn:aws:ec2:{region}:{account}:image/{image}",
        "request.license_count_blocked_run_instances": True,
    }]
