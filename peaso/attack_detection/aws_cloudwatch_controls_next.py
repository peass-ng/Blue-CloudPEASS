"""CloudWatch monitoring and Logs destructive configuration writes."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any


def _names(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(n, str) and bool(n) for n in value)


def _wide_future_exclusion(configuration: Any, event_time: Any) -> bool:
    if not isinstance(configuration, Mapping) or not isinstance(event_time, str):
        return False
    ranges = configuration.get("excludedTimeRanges")
    if not isinstance(ranges, list):
        return False
    try:
        now = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
    except ValueError:
        return False
    for item in ranges:
        if not isinstance(item, Mapping):
            continue
        try:
            start = datetime.fromisoformat(item["startTime"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(item["endTime"].replace("Z", "+00:00"))
            if end - start >= timedelta(days=365 * 5) and end - now >= timedelta(days=365):
                return True
        except (KeyError, AttributeError, TypeError, ValueError):
            continue
    return False


def normalize_aws_cloudwatch_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    source, name = record.get("eventSource"), record.get("eventName")
    monitoring = {"DisableAlarmActions", "PutMetricAlarm", "PutCompositeAlarm", "DeleteAlarms", "DeleteDashboards",
                  "SetAlarmState", "PutAnomalyDetector", "DeleteAnomalyDetector"}
    logs = {"PutRetentionPolicy", "DeleteMetricFilter", "DeleteLogStream", "DeleteLogGroup"}
    if not ((source == "monitoring.amazonaws.com" and name in monitoring)
            or (source == "logs.amazonaws.com" and name in logs)):
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    response = record.get("responseElements")
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")))
    alarm = request.get("alarmName")
    group = request.get("logGroupName")
    namespace, metric = request.get("namespace"), request.get("metricName")
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": source, "event.name": name,
        "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId"), "actor.id": identity.get("arn"),
        "target.id": (alarm or group
                      or (f"{namespace}/{metric}" if isinstance(namespace, str) and isinstance(metric, str) else None)
                      or (request["alarmNames"][0] if _names(request.get("alarmNames")) else None)
                      or (request["dashboardNames"][0] if _names(request.get("dashboardNames")) else None)),
        "request.disable_alarm_actions_observed": (
            not failed and name == "DisableAlarmActions" and _names(request.get("alarmNames"))
        ),
        "request.alarm_actions_explicitly_disabled": (
            not failed and name in {"PutMetricAlarm", "PutCompositeAlarm"}
            and isinstance(alarm, str) and bool(alarm) and request.get("actionsEnabled") is False
        ),
        "request.delete_alarm_observed": not failed and name == "DeleteAlarms" and _names(request.get("alarmNames")),
        "request.delete_dashboard_observed": (
            not failed and name == "DeleteDashboards" and _names(request.get("dashboardNames"))
        ),
        "request.alarm_state_manually_forced": (
            not failed and name == "SetAlarmState" and isinstance(alarm, str) and bool(alarm)
            and request.get("stateValue") in {"ALARM", "OK"}
        ),
        "request.anomaly_detector_wide_future_exclusion": (
            not failed and name == "PutAnomalyDetector" and isinstance(namespace, str) and bool(namespace)
            and isinstance(metric, str) and bool(metric)
            and _wide_future_exclusion(request.get("configuration"), record.get("eventTime"))
        ),
        "request.anomaly_detector_deleted": (
            not failed and name == "DeleteAnomalyDetector" and isinstance(namespace, str) and bool(namespace)
            and isinstance(metric, str) and bool(metric) and isinstance(request.get("stat"), str)
        ),
        "request.retention_one_day": (
            not failed and name == "PutRetentionPolicy" and isinstance(group, str) and bool(group)
            and type(request.get("retentionInDays")) is int and request["retentionInDays"] == 1
        ),
        "request.metric_filter_deleted": (
            not failed and name == "DeleteMetricFilter" and isinstance(group, str) and bool(group)
            and isinstance(request.get("filterName"), str) and bool(request["filterName"])
        ),
        "request.log_stream_deleted": (
            not failed and name == "DeleteLogStream" and isinstance(group, str) and bool(group)
            and isinstance(request.get("logStreamName"), str) and bool(request["logStreamName"])
        ),
        "request.log_group_deleted": not failed and name == "DeleteLogGroup" and isinstance(group, str) and bool(group),
    }
