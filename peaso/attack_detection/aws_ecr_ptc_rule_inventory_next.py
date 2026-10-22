"""Normalize the observed ECR pull through cache rule inventory event."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import re
from typing import Any


def normalize_aws_ecr_ptc_rule_inventory(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "ecr.amazonaws.com"
            or record.get("eventName") != "DescribePullThroughCacheRules"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not True
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account = record.get("recipientAccountId")
    region = record.get("awsRegion")
    event_id = record.get("eventID")
    if (not isinstance(account, str) or len(account) != 12 or not account.isdigit()
            or not isinstance(region, str)
            or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", region)
            or not isinstance(event_id, str) or not event_id):
        return None
    request = record.get("requestParameters")
    resources = record.get("resources")
    response = record.get("responseElements")
    if (not isinstance(request, Mapping)
            or not isinstance(resources, list) or len(resources) != 1
            or not isinstance(resources[0], Mapping)
            or resources[0].get("ARN") != "*"
            or resources[0].get("accountId") != account
            or resources[0].get("type") is not None
            or response is not None and not isinstance(response, Mapping)
            or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage"))):
        return None
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    target = "sha256:" + hashlib.sha256(
        f"{account}:{region}:{event_id}".encode("utf-8")
    ).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "ecr.amazonaws.com",
        "event.name": "DescribePullThroughCacheRules", "event.outcome": "success",
        "event.id": event_id, "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": target, "request.ecr_pullthrough_cache_rules_listed": True,
    }
