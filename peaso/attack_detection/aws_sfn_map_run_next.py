"""Recognize accepted Step Functions Map Run runtime control changes."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_MAP_RUN = re.compile(
    r"arn:aws:states:([a-z0-9-]+):(\d{12}):mapRun:"
    r"[A-Za-z0-9+!@_.-]+/[A-Za-z0-9+!@_.-]+:[0-9a-fA-F-]+\Z"
)


def _nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _percentage(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 100


def normalize_aws_sfn_map_run(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "states.amazonaws.com"
            or record.get("eventName") != "UpdateMapRun"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    target = request.get("mapRunArn")
    match = _MAP_RUN.fullmatch(target) if isinstance(target, str) else None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if not match or match.group(1) != region or match.group(2) != account:
        return None
    fields = {
        "maxConcurrency": _nonnegative_int,
        "toleratedFailureCount": _nonnegative_int,
        "toleratedFailurePercentage": _percentage,
    }
    if not any(field in request for field in fields):
        return None
    if any(field in request and not valid(request[field]) for field, valid in fields.items()):
        return None
    concurrency = request.get("maxConcurrency")
    failure_count = request.get("toleratedFailureCount")
    failure_percentage = request.get("toleratedFailurePercentage")
    identity = record.get("userIdentity")
    result = {
        "cloud.provider": "aws", "event.source": "states.amazonaws.com",
        "event.name": "UpdateMapRun", "event.outcome": "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account,
        "actor.id": identity.get("arn") if isinstance(identity, Mapping) else None,
        "target.id": target,
        "request.sfn_map_run_runtime_updated": True,
    }
    if concurrency == 0 and _nonnegative_int(concurrency):
        result["request.sfn_map_run_unbounded_concurrency"] = True
    if ((failure_count == 0 and _nonnegative_int(failure_count))
            or (failure_percentage == 0 and _percentage(failure_percentage))):
        result["request.sfn_map_run_zero_failure_tolerance"] = True
    if ((failure_count is not None and _nonnegative_int(failure_count) and failure_count > 0)
            or (failure_percentage is not None and _percentage(failure_percentage)
                and failure_percentage > 0)):
        result["request.sfn_map_run_nonzero_failure_tolerance"] = True
    return result
