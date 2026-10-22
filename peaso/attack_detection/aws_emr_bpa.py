"""Classify accepted EMR regional Block Public Access changes."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")


def normalize_aws_emr_bpa(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Emit only fixed indicators for accepted weakening of regional EMR BPA."""
    if (record.get("eventSource") != "elasticmapreduce.amazonaws.com"
            or record.get("eventName") != "PutBlockPublicAccessConfiguration"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request = record.get("userIdentity"), record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or not isinstance(identity.get("arn"), str)
            or not isinstance(request, Mapping)
            or not isinstance(request.get("blockPublicAccessConfiguration"), Mapping)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    config = request["blockPublicAccessConfiguration"]
    block = config.get("blockPublicSecurityGroupRules")
    if type(block) is not bool:
        return None
    ranges = config.get("permittedPublicSecurityGroupRuleRanges")
    all_ports = bool(
        block is True and isinstance(ranges, list)
        and any(isinstance(item, Mapping) and type(item.get("minRange")) is int
                and type(item.get("maxRange")) is int
                and item["minRange"] == 0 and item["maxRange"] == 65535
                for item in ranges)
    )
    disabled = block is False
    if not (disabled or all_ports):
        return None
    stamp = record.get("eventTime")
    if not isinstance(stamp, str):
        return None
    try:
        if datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
            return None
    except ValueError:
        return None
    target = hashlib.sha256(f"emr-bpa:{account}:{region}".encode("utf-8")).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "elasticmapreduce.amazonaws.com",
        "event.name": "PutBlockPublicAccessConfiguration", "event.outcome": "success",
        "event.id": record["eventID"], "event.time": stamp,
        "account.id": account, "actor.id": identity["arn"],
        "target.id": "sha256:" + target,
        "request.emr_bpa_disabled": disabled,
        "request.emr_bpa_all_ports_exception": all_ports,
    }
