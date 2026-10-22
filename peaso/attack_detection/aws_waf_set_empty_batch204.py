"""Detect accepted WAF IP and regex pattern set updates to empty lists."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_NAMES = {
    "UpdateIPSet": ("addresses", "request.waf_ip_set_emptied"),
    "UpdateRegexPatternSet": ("regularExpressionList", "request.waf_regex_pattern_set_emptied"),
}


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "wafv2.amazonaws.com" or name not in _NAMES
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    account = record.get("recipientAccountId")
    field, flag = _NAMES[name]
    if (not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or request.get(field) != [] or request.get("scope") not in {"REGIONAL", "CLOUDFRONT"}
            or not isinstance(request.get("name"), str) or not request["name"]
            or not isinstance(request.get("id"), str) or not request["id"]
            or not isinstance(response.get("nextLockToken"), str) or not response["nextLockToken"]
            or not isinstance(record.get("eventID"), str)):
        return None
    identity = record.get("userIdentity")
    if not isinstance(identity, Mapping) or identity.get("type") == "AWSService" or identity.get("invokedBy"):
        return None
    target = "sha256:" + hashlib.sha256(
        f"{account}:{request['scope']}:{request['name']}:{request['id']}".encode()
    ).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "wafv2.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": target,
        flag: True,
    }
