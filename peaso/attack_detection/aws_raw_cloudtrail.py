"""Safe opt-in CloudTrail envelope for catalog-only API event rules."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_SOURCE = re.compile(r"[a-z0-9-]+\.amazonaws\.com\Z")
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9]{0,127}\Z")
_TYPE = re.compile(r"AWS::[A-Za-z][A-Za-z0-9]*::[A-Za-z][A-Za-z0-9]*\Z")
_ARN = re.compile(r"arn:(aws(?:-[a-z-]+)?):[a-z0-9-]+:([a-z0-9-]*):([0-9]{12}):([^\s]+)\Z")


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Emit resource-scoped envelopes; never copy request or response content."""
    source, name = record.get("eventSource"), record.get("eventName")
    category, read_only = record.get("eventCategory"), record.get("readOnly")
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    stamp, event_id = record.get("eventTime"), record.get("eventID")
    resources = record.get("resources")
    if (not isinstance(source, str) or not _SOURCE.fullmatch(source)
            or not isinstance(name, str) or not _NAME.fullmatch(name)
            or category not in {"Management", "Data"}
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not (category == "Management")
            or not isinstance(read_only, bool)
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(stamp, str) or not isinstance(event_id, str) or not event_id
            or not isinstance(resources, list) or len(resources) > 100):
        return []
    try:
        if datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
            return []
    except ValueError:
        return []
    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    result = []
    seen = set()
    for item in resources:
        if not isinstance(item, Mapping):
            continue
        kind, arn = item.get("type"), item.get("ARN")
        if (not isinstance(kind, str) or not _TYPE.fullmatch(kind)
                or not isinstance(arn, str) or len(arn) > 2048):
            continue
        match = _ARN.fullmatch(arn)
        if not match or match.group(3) != account or match.group(2) not in {"", region}:
            continue
        key = (kind, arn)
        if key in seen:
            continue
        seen.add(key)
        target = "sha256:" + hashlib.sha256(arn.encode("utf-8")).hexdigest()[:24]
        result.append({
            "cloud.provider": "aws", "event.source": source,
            "event.name": name, "event.category": category,
            "event.read_only": read_only, "event.outcome": "success",
            "resource.type": kind, "event.id": event_id,
            "event.time": stamp, "account.id": account,
            "actor.id": actor, "target.id": target,
            "__raw_cloudtrail": True,
        })
    return result
