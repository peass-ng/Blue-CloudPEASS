"""Normalize observed AWS security-control API writes without inferring intent or state."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from ipaddress import ip_address
from typing import Any


_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-\d+")
_ACCOUNT = re.compile(r"\d{12}")
_TRAIL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{1,126}[A-Za-z0-9]")


def _detector_id(value: Any) -> bool:
    # GuardDuty documents 1..300 characters but no tighter lexical pattern.
    return (isinstance(value, str) and 1 <= len(value) <= 300
            and value == value.strip() and all(ord(char) >= 32 for char in value))


def _trail_name(value: str) -> bool:
    if not _TRAIL_NAME.fullmatch(value) or re.search(r"[._-]{2}", value):
        return False
    try:
        ip_address(value)
    except ValueError:
        return True
    return False


def _arn(value: Any) -> list[str] | None:
    if not isinstance(value, str):
        return None
    parts = value.split(":", 5)
    if (len(parts) != 6 or parts[0] != "arn" or parts[1] not in {"aws", "aws-us-gov", "aws-cn"}
            or not _ACCOUNT.fullmatch(parts[4]) or not parts[5]):
        return None
    return parts


def _event_time(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if parsed.tzinfo is not None else None


def normalize_aws_security_control(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return a canonical event only when the targeted API request is evidenced.

    A successful API record proves the named request was accepted. It does not
    establish prior configuration, current service state, or actor intent.
    """
    source = record.get("eventSource")
    name = record.get("eventName")
    if (source, name) not in {
        ("cloudtrail.amazonaws.com", "StopLogging"),
        ("cloudtrail.amazonaws.com", "DeleteTrail"),
        ("guardduty.amazonaws.com", "UpdateDetector"),
        ("guardduty.amazonaws.com", "DeleteDetector"),
    }:
        return None
    request = record.get("requestParameters")
    response = record.get("responseElements")
    identity = record.get("userIdentity")
    if not isinstance(request, Mapping) or not isinstance(identity, Mapping) or "responseElements" not in record:
        return None
    if response is not None and not isinstance(response, Mapping):
        return None
    if (record.get("errorCode") or record.get("errorMessage")
            or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage"))):
        return None
    if (record.get("eventCategory") != "Management"
            or (record.get("managementEvent") is not None and record.get("managementEvent") is not True)
            or record.get("eventType") != "AwsApiCall"
            or (record.get("readOnly") is not None and record.get("readOnly") is not False)):
        return None
    account = record.get("recipientAccountId")
    region = record.get("awsRegion")
    event_id = record.get("eventID")
    event_time = _event_time(record.get("eventTime"))
    actor_arn = _arn(identity.get("arn"))
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(event_id, str) or not event_id
            or event_time is None or actor_arn is None
            or identity.get("accountId") != actor_arn[4] or actor_arn[4] != account
            or not isinstance(identity.get("type"), str) or not identity["type"]):
        return None

    result = {
        "cloud.provider": "aws", "cloud.region": region,
        "event.source": source, "event.name": name, "event.outcome": "success",
        "event.id": event_id, "event.time": event_time,
        "account.id": account, "actor.id": identity["arn"], "actor.kind": identity["type"],
    }
    if name in {"StopLogging", "DeleteTrail"}:
        trail_ref = request.get("name")
        if not isinstance(trail_ref, str):
            return None
        trail_arn = _arn(trail_ref) if trail_ref.startswith("arn:") else None
        if trail_arn is not None:
            if (trail_arn[1] != actor_arn[1] or trail_arn[2] != "cloudtrail"
                    or trail_arn[3] != region or trail_arn[4] != account
                    or not trail_arn[5].startswith("trail/")):
                return None
            trail_name = trail_arn[5][len("trail/"):]
        else:
            trail_name = trail_ref
        if not _trail_name(trail_name):
            return None
        result.update({"target.id": trail_ref, "request.trail_name": trail_name,
                       "request.stop_logging_observed": name == "StopLogging",
                       "request.delete_trail_observed": name == "DeleteTrail"})
    else:
        detector_id = request.get("detectorId")
        if not _detector_id(detector_id):
            return None
        if name == "UpdateDetector" and request.get("enable") is not False:
            return None
        result.update({"target.id": detector_id, "request.detector_id": detector_id,
                       "request.enable": False if name == "UpdateDetector" else None,
                       "request.detector_disable_requested": name == "UpdateDetector",
                       "request.detector_delete_observed": name == "DeleteDetector"})
    return result
