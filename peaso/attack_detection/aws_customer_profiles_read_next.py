"""Isolated Customer Profiles read observations; never retain PII or pagination tokens."""

from collections.abc import Mapping
import re
from typing import Any


NAMES = {"SearchProfiles", "BatchGetProfile", "ListProfileObjects",
         "ListProfileHistoryRecords", "ListCalculatedAttributesForProfile"}
DOMAIN = re.compile(r"[A-Za-z0-9_-]{1,64}")
PROFILE_ID = re.compile(r"[a-f0-9]{32}")
OBJECT_TYPE = re.compile(r"[A-Za-z_][A-Za-z_0-9-]{0,254}")


def field(value: Mapping[str, Any], name: str) -> Any:
    """Customer Profiles CloudTrail serializes parameters with initial caps."""
    return value.get(name, value.get(name[0].upper() + name[1:]))


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "profile.amazonaws.com" or name not in NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not True
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account):
        return None
    if not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", region):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    domain = field(request, "domainName")
    if not isinstance(domain, str) or not DOMAIN.fullmatch(domain):
        return None
    target = f"arn:aws:profile:{region}:{account}:domains/{domain}"
    if name == "SearchProfiles":
        key = field(request, "keyName")
        if not isinstance(key, str) or not DOMAIN.fullmatch(key):
            return None
        # Key values may be redacted by CloudTrail; neither require nor emit them.
    elif name == "BatchGetProfile":
        ids = field(request, "profileIds")
        if (not isinstance(ids, list) or not 1 <= len(ids) <= 20
                or any(not isinstance(pid, str) or not PROFILE_ID.fullmatch(pid) for pid in ids)):
            return None
    else:
        pid = field(request, "profileId")
        if not isinstance(pid, str) or not PROFILE_ID.fullmatch(pid):
            return None
        target += "/profiles/" + pid
        if name == "ListProfileObjects":
            obj = field(request, "objectTypeName")
            if not isinstance(obj, str) or not OBJECT_TYPE.fullmatch(obj):
                return None
    actor = record.get("userIdentity")
    actor = actor if isinstance(actor, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": "profile.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": actor.get("arn"), "target.id": target,
            "request.customer_profiles_read_observed": True}
