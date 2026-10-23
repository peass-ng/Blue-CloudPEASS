"""WAF IP set tag removal without exporting tag keys or resource ARN."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_ARN = re.compile(
    r"arn:aws:wafv2:([a-z]{2}(?:-[a-z]+)+-[0-9]):([0-9]{12}):"
    r"(regional|global)/ipset/[A-Za-z0-9_-]{1,128}/[0-9a-f-]{36}\Z"
)


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "wafv2.amazonaws.com"
            or record.get("eventName") != "UntagResource"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request = record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not isinstance(request, Mapping)
            or not isinstance(request.get("resourceARN"), str)):
        return None
    arn = request["resourceARN"]
    match = _ARN.fullmatch(arn)
    keys = request.get("tagKeys")
    if (match is None or match.group(1) != region or match.group(2) != account
            or not isinstance(keys, list) or not keys
            or any(not isinstance(key, str) or not key for key in keys)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    identity = record.get("userIdentity")
    if (not isinstance(identity, Mapping) or identity.get("type") == "AWSService"
            or identity.get("invokedBy") or identity.get("accountId") != account):
        return None
    return {
        "cloud.provider": "aws", "event.source": "wafv2.amazonaws.com",
        "event.name": "UntagResource", "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": "sha256:" + hashlib.sha256(arn.encode()).hexdigest()[:24],
        "request.waf_ipset_tags_removed": True,
    }
