"""Correlate accepted EBS volume attachments to distinct EC2 instances."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any


_ACCOUNT = re.compile(r"\d{12}\Z")
_VOLUME = re.compile(r"vol-[0-9a-f]+\Z")
_INSTANCE = re.compile(r"i-[0-9a-f]+\Z")


def _event(record: Mapping[str, Any]) -> tuple[str, str, str, str, datetime] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "ec2.amazonaws.com"
            or name not in {"AttachVolume", "DetachVolume"}
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not region
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)):
        return None
    volume, instance = request.get("volumeId"), request.get("instanceId")
    if (not isinstance(volume, str) or not _VOLUME.fullmatch(volume)
            or not isinstance(instance, str) or not _INSTANCE.fullmatch(instance)
            or response.get("volumeId") != volume or response.get("instanceId") != instance):
        return None
    if name == "AttachVolume" and response.get("status") not in {"attaching", "attached"}:
        return None
    if name == "DetachVolume" and response.get("status") not in {"detaching", "detached"}:
        return None
    raw_time = record.get("eventTime")
    try:
        when = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    if when.tzinfo is None:
        return None
    return name, account, region, volume, when


def correlate_aws_ebs_multiattach(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Report a second accepted attachment without an intervening detach."""
    parsed = []
    for record in records:
        item = _event(record)
        if item is not None:
            name, account, region, volume, when = item
            parsed.append((when, name, account, region, volume,
                           record["requestParameters"]["instanceId"], record))
    parsed.sort(key=lambda row: row[0])
    active: dict[tuple[str, str, str], dict[str, datetime]] = {}
    result = []
    window = timedelta(minutes=30)
    seen: set[str] = set()
    for when, name, account, region, volume, instance, record in parsed:
        key = account, region, volume
        attached = active.setdefault(key, {})
        for old_instance, old_time in list(attached.items()):
            if when - old_time > window:
                del attached[old_instance]
        if name == "DetachVolume":
            attached.pop(instance, None)
            continue
        event_id = record.get("eventID")
        if isinstance(event_id, str) and event_id in seen:
            continue
        if isinstance(event_id, str):
            seen.add(event_id)
        if instance not in attached and any(old_time < when for old_time in attached.values()):
            identity = record.get("userIdentity")
            actor = identity.get("arn") if isinstance(identity, Mapping) else None
            result.append({"cloud.provider": "aws", "event.source": "ec2.amazonaws.com",
                           "event.name": "AttachVolume", "event.outcome": "success",
                           "event.id": event_id, "event.time": record.get("eventTime"),
                           "account.id": account, "actor.id": actor, "target.id": volume,
                           "request.ebs_volume_attached_to_distinct_instances": True})
        attached[instance] = when
    return result
