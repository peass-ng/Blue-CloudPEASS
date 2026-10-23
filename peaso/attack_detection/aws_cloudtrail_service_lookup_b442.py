"""Service-filtered CloudTrail history reads without copying returned events."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
import hashlib
import re
from typing import Any, Iterable


_SERVICE = re.compile(r"[a-z0-9-]+\.amazonaws\.com\Z")


def normalize_aws_cloudtrail_service_lookup_b442(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "cloudtrail.amazonaws.com"
            or record.get("eventName") != "LookupEvents"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not True
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request = record.get("requestParameters")
    attributes = request.get("lookupAttributes") if isinstance(request, Mapping) else None
    if not isinstance(attributes, list) or len(attributes) != 1:
        return None
    attribute = attributes[0]
    if not isinstance(attribute, Mapping) or attribute.get("attributeKey") != "EventSource":
        return None
    service = attribute.get("attributeValue")
    if not isinstance(service, str) or not _SERVICE.fullmatch(service):
        return None
    account = record.get("recipientAccountId")
    if not isinstance(account, str) or len(account) != 12 or not account.isdigit():
        return None
    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    digest = lambda value: "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "cloudtrail.amazonaws.com",
        "event.name": "LookupEvents", "event.outcome": "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account,
        "actor.id": digest(actor) if isinstance(actor, str) else None,
        "target.id": digest(service),
        "request.cloudtrail_service_history_lookup": True,
    }


def correlate_aws_cloudtrail_denied_list_lookup_b442(
    records: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    denied: dict[tuple[str, str, str], list[datetime]] = {}
    reads: list[tuple[datetime, str, str, str, Mapping[str, Any]]] = []
    for record in records:
        account = record.get("recipientAccountId")
        identity = record.get("userIdentity")
        actor = identity.get("arn") if isinstance(identity, Mapping) else None
        stamp = record.get("eventTime")
        if (not isinstance(account, str) or len(account) != 12 or not account.isdigit()
                or not isinstance(actor, str) or not isinstance(stamp, str)):
            continue
        try:
            when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            if when.tzinfo is None:
                continue
        except ValueError:
            continue
        source, name = record.get("eventSource"), record.get("eventName")
        if (isinstance(source, str) and _SERVICE.fullmatch(source)
                and isinstance(name, str) and name.startswith(("List", "Describe"))
                and record.get("eventCategory") == "Management"
                and record.get("readOnly") is True
                and record.get("errorCode") in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}):
            denied.setdefault((account, actor, source), []).append(when)
        normalized = normalize_aws_cloudtrail_service_lookup_b442(record)
        if normalized is None:
            continue
        service = (record["requestParameters"]["lookupAttributes"][0]["attributeValue"])
        reads.append((when, account, actor, service, record))
    result = []
    for when, account, actor, service, record in reads:
        if not any(prior <= when <= prior + timedelta(minutes=15)
                   for prior in denied.get((account, actor, service), [])):
            continue
        normalized = normalize_aws_cloudtrail_service_lookup_b442(record)
        if normalized is not None:
            normalized.pop("request.cloudtrail_service_history_lookup", None)
            normalized["request.cloudtrail_after_denied_service_list"] = True
            result.append(normalized)
    return result
