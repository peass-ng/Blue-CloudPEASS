"""Normalize explicit CloudWatch Logs retention and deletion writes."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from .aws_security_controls import _arn, _event_time


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+\Z")
_NAMES = {"PutRetentionPolicy", "DeleteMetricFilter", "DeleteLogStream", "DeleteLogGroup"}


def _name(value: Any, maximum: int) -> str | None:
    return (value if isinstance(value, str) and 1 <= len(value) <= maximum
            and not any(ord(char) < 32 for char in value) else None)


def normalize_aws_cloudwatch_logs(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Report accepted writes without assuming logs existed or were lost."""
    name = record.get("eventName")
    if (record.get("eventSource") != "logs.amazonaws.com" or name not in _NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") not in (None, True)
            or record.get("readOnly") not in (None, False)
            or record.get("errorCode") or record.get("errorMessage")
            or "responseElements" not in record):
        return None
    request = record.get("requestParameters")
    response = record.get("responseElements")
    identity = record.get("userIdentity")
    if (not isinstance(request, Mapping) or not isinstance(identity, Mapping)
            or response is not None and not isinstance(response, Mapping)
            or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage"))):
        return None
    account = record.get("recipientAccountId")
    region = record.get("awsRegion")
    actor_arn = identity.get("arn")
    actor = _arn(actor_arn)
    event_id = record.get("eventID")
    event_time = _event_time(record.get("eventTime"))
    try:
        UUID(event_id)
    except (TypeError, ValueError, AttributeError):
        return None
    group = _name(request.get("logGroupName"), 512)
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or actor is None or actor[4] != account or identity.get("accountId") != account
            or not isinstance(identity.get("type"), str) or not identity["type"]
            or event_time is None or group is None):
        return None
    retention_one_day = (name == "PutRetentionPolicy"
                         and type(request.get("retentionInDays")) is int
                         and request["retentionInDays"] == 1)
    metric_filter_deleted = name == "DeleteMetricFilter" and _name(request.get("filterName"), 512) is not None
    stream_deleted = name == "DeleteLogStream" and _name(request.get("logStreamName"), 512) is not None
    group_deleted = name == "DeleteLogGroup"
    if not any((retention_one_day, metric_filter_deleted, stream_deleted, group_deleted)):
        return None
    group_arn = f"arn:{actor[1]}:logs:{region}:{account}:log-group:{group}"
    target = (f"{group_arn}:log-stream:{request['logStreamName']}" if stream_deleted
              else group_arn)
    return {
        "cloud.provider": "aws", "cloud.region": region,
        "event.source": "logs.amazonaws.com", "event.name": name,
        "event.outcome": "success", "event.id": event_id, "event.time": event_time,
        "account.id": account, "actor.id": actor_arn, "actor.kind": identity["type"],
        "target.id": target,
        "request.retention_one_day": retention_one_day,
        "request.metric_filter_deleted": metric_filter_deleted,
        "request.metric_filter_name": request.get("filterName") if metric_filter_deleted else None,
        "request.log_stream_deleted": stream_deleted,
        "request.log_group_deleted": group_deleted,
    }
