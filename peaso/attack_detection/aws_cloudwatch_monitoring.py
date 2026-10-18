"""Normalize accepted CloudWatch alarm and dashboard monitoring changes."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from .aws_security_controls import _arn, _event_time


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+\Z")
_NAMES = {"PutMetricAlarm", "DisableAlarmActions", "DeleteAlarms", "DeleteDashboards"}


def _target_names(value: Any) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 100:
        return []
    if any(not isinstance(item, str) or not 1 <= len(item) <= 255
           or any(ord(char) < 32 for char in item) for item in value):
        return []
    return list(dict.fromkeys(value))


def normalize_aws_cloudwatch_monitoring(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """One canonical signal per affected alarm/dashboard, without prior-state claims."""
    name = record.get("eventName")
    if (record.get("eventSource") != "monitoring.amazonaws.com" or name not in _NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") not in (None, True)
            or record.get("readOnly") not in (None, False)
            or record.get("errorCode") or record.get("errorMessage")
            or "responseElements" not in record):
        return []
    request = record.get("requestParameters")
    response = record.get("responseElements")
    identity = record.get("userIdentity")
    if (not isinstance(request, Mapping) or not isinstance(identity, Mapping)
            or response is not None and not isinstance(response, Mapping)
            or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage"))):
        return []
    account = record.get("recipientAccountId")
    region = record.get("awsRegion")
    actor_arn = identity.get("arn")
    actor = _arn(actor_arn)
    event_id = record.get("eventID")
    event_time = _event_time(record.get("eventTime"))
    try:
        UUID(event_id)
    except (TypeError, ValueError, AttributeError):
        return []
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or actor is None or actor[4] != account or identity.get("accountId") != account
            or not isinstance(identity.get("type"), str) or not identity["type"]
            or event_time is None):
        return []
    if name == "PutMetricAlarm":
        target_names = _target_names([request.get("alarmName")]) if request.get("actionsEnabled") is False else []
    elif name in {"DisableAlarmActions", "DeleteAlarms"}:
        target_names = _target_names(request.get("alarmNames"))
    else:
        target_names = _target_names(request.get("dashboardNames"))
    result = []
    for target_name in target_names:
        target_arn = (f"arn:{actor[1]}:cloudwatch::{account}:dashboard/{target_name}"
                      if name == "DeleteDashboards" else
                      f"arn:{actor[1]}:cloudwatch:{region}:{account}:alarm:{target_name}")
        result.append({
            "cloud.provider": "aws", "cloud.region": region,
            "event.source": "monitoring.amazonaws.com", "event.name": name,
            "event.outcome": "success", "event.id": event_id, "event.time": event_time,
            "account.id": account, "actor.id": actor_arn, "actor.kind": identity["type"],
            "target.id": target_arn,
            "request.alarm_actions_explicitly_disabled": name == "PutMetricAlarm",
            "request.disable_alarm_actions_observed": name == "DisableAlarmActions",
            "request.delete_alarm_observed": name == "DeleteAlarms",
            "request.delete_dashboard_observed": name == "DeleteDashboards",
        })
    return result
