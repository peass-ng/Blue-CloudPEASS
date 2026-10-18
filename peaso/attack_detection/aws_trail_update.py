"""Normalize confirmed CloudTrail UpdateTrail configuration requests.

A response can confirm the settings returned by UpdateTrail. Without an older
trail snapshot it cannot prove that any setting changed, that the trail was
logging, or that the caller had malicious intent.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from .aws_security_controls import _arn, _event_time, _trail_reference


_ACCOUNT = re.compile(r"\d{12}")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-\d+")


def normalize_aws_trail_update(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return an observation of explicitly requested and returned weak settings."""
    if (record.get("eventSource") != "cloudtrail.amazonaws.com"
            or record.get("eventName") != "UpdateTrail"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") not in (None, True)
            or record.get("readOnly") not in (None, False)
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request = record.get("requestParameters")
    response = record.get("responseElements")
    identity = record.get("userIdentity")
    account = record.get("recipientAccountId")
    region = record.get("awsRegion")
    event_id = record.get("eventID")
    event_time = _event_time(record.get("eventTime"))
    if (not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or not isinstance(identity, Mapping) or not isinstance(account, str)
            or not _ACCOUNT.fullmatch(account) or not isinstance(region, str)
            or not _REGION.fullmatch(region) or not isinstance(event_id, str)
            or not event_id or event_time is None
            or response.get("errorCode") or response.get("errorMessage")):
        return None
    actor = _arn(identity.get("arn"))
    if (actor is None or actor[4] != account or identity.get("accountId") != account
            or not isinstance(identity.get("type"), str) or not identity["type"]):
        return None
    name = _trail_reference(request.get("name"), account, region, actor[1])
    trail_arn = response.get("trailARN")
    if (name is None or not isinstance(trail_arn, str)
            or not trail_arn.startswith("arn:")
            or _trail_reference(trail_arn, account, region, actor[1]) != name
            or response.get("name") != name):
        return None

    explicit = {
        "integrity_validation_disabled": (
            "enableLogFileValidation", "logFileValidationEnabled"),
        "multi_region_logging_disabled": (
            "isMultiRegionTrail", "isMultiRegionTrail"),
        "global_service_logging_disabled": (
            "includeGlobalServiceEvents", "includeGlobalServiceEvents"),
    }
    observed = {
        label: request.get(request_key) is False and response.get(response_key) is False
        for label, (request_key, response_key) in explicit.items()
    }
    if not any(observed.values()):
        return None
    return {
        "cloud.provider": "aws", "cloud.region": region,
        "event.source": "cloudtrail.amazonaws.com", "event.name": "UpdateTrail",
        "event.outcome": "success", "event.id": event_id, "event.time": event_time,
        "account.id": account, "actor.id": identity["arn"],
        "actor.kind": identity["type"], "target.id": trail_arn,
        "request.trail_name": name,
        **{f"request.{label}": value for label, value in observed.items()},
    }
