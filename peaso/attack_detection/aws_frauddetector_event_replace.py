"""Find repeated Fraud Detector writes to one stored event without copying values."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_NAME = re.compile(r"[0-9a-z_-]{1,64}\Z")


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _send(record: Mapping[str, Any]) -> tuple[tuple[str, str, str, str], datetime, datetime, datetime] | None:
    if (record.get("eventSource") != "frauddetector.amazonaws.com"
            or record.get("eventName") != "SendEvent"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request = record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping)):
        return None
    event_type, event_id = request.get("eventTypeName"), request.get("eventId")
    if (not isinstance(event_type, str) or not _NAME.fullmatch(event_type)
            or not isinstance(event_id, str) or not _NAME.fullmatch(event_id)):
        return None
    sent = _timestamp(record.get("eventTime"))
    occurred = _timestamp(request.get("eventTimestamp"))
    labeled = _timestamp(request.get("labelTimestamp"))
    if sent is None or occurred is None or labeled is None:
        return None
    return (account, region, event_type, event_id), sent, occurred, labeled


def correlate_aws_frauddetector_event_replacement(
    records: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Identify a later label timestamp on another accepted write to the same event."""
    parsed = []
    for record in records:
        item = _send(record)
        if item is not None:
            key, sent, occurred, labeled = item
            parsed.append((sent, labeled, key, occurred, record))
    parsed.sort(key=lambda row: (row[0], row[1]))

    previous: dict[tuple[str, str, str, str, datetime], tuple[datetime, datetime, str]] = {}
    seen: set[str] = set()
    results = []
    for sent, labeled, key, occurred, record in parsed:
        event_id = record.get("eventID")
        if not isinstance(event_id, str) or not event_id or event_id in seen:
            continue
        seen.add(event_id)
        full_key = (*key, occurred)
        earlier = previous.get(full_key)
        if earlier is not None and sent > earlier[0] and labeled > earlier[1]:
            account, region, event_type, stored_id = key
            identity = record.get("userIdentity")
            actor = identity.get("arn") if isinstance(identity, Mapping) else None
            target = "sha256:" + hashlib.sha256(
                f"{account}:{region}:{event_type}:{stored_id}".encode("utf-8")
            ).hexdigest()[:24]
            results.append({
                "cloud.provider": "aws",
                "event.source": "frauddetector.amazonaws.com",
                "event.name": "SendEvent",
                "event.outcome": "success",
                "event.id": event_id,
                "event.time": record.get("eventTime"),
                "account.id": account,
                "actor.id": actor,
                "target.id": target,
                "request.fraud_event_resubmitted_with_new_label_time": True,
                "correlation_evidence": {
                    "prior_cloudtrail_event_id": earlier[2],
                    "same_stored_event_and_timestamp": True,
                    "newer_label_timestamp": True,
                },
            })
        if earlier is None or (sent > earlier[0] and labeled > earlier[1]):
            previous[full_key] = (sent, labeled, event_id)
    return results
