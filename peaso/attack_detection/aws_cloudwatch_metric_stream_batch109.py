"""CloudWatch Metric Stream management signals and ordered filter expansion."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_NAME = re.compile(r"[A-Za-z0-9_-]{1,255}\Z")
_NAMES = {"PutMetricStream", "StopMetricStreams", "StartMetricStreams",
          "DeleteMetricStream"}
_WINDOW = timedelta(hours=1)


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result.astimezone(timezone.utc) if result.tzinfo else None


def _base(record: Mapping[str, Any]) -> tuple[str, str, Mapping[str, Any]] | None:
    name = record.get("eventName")
    response = record.get("responseElements")
    if (record.get("eventSource") != "monitoring.amazonaws.com"
            or not isinstance(name, str) or name not in _NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")
            or (isinstance(response, Mapping)
                and (response.get("errorCode") or response.get("errorMessage")))
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request = record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping)):
        return None
    return account, region, request


def _targets(name: str, request: Mapping[str, Any]) -> list[str]:
    if name in {"StopMetricStreams", "StartMetricStreams"}:
        values = request.get("names")
        if not isinstance(values, list) or not values or len(values) > 100:
            return []
        if any(not isinstance(value, str) or not _NAME.fullmatch(value) for value in values):
            return []
        return sorted(set(values))
    value = request.get("name")
    return [value] if isinstance(value, str) and _NAME.fullmatch(value) else []


def _put_valid(request: Mapping[str, Any], response: Any,
               account: str, region: str, name: str) -> bool:
    firehose = request.get("firehoseArn")
    role = request.get("roleArn")
    expected_response = f"arn:aws:cloudwatch:{region}:{account}:metric-stream/{name}"
    return bool(
        isinstance(firehose, str)
        and re.fullmatch(r"arn:aws:firehose:" + re.escape(region) + ":" + account
                         + r":deliverystream/[A-Za-z0-9_-]{1,64}", firehose)
        and isinstance(role, str)
        and re.fullmatch(r"arn:aws:iam::" + account + r":role/[A-Za-z0-9_+=,.@/-]{1,512}", role)
        and request.get("outputFormat") in {"json", "opentelemetry0.7", "opentelemetry1.0"}
        and isinstance(response, Mapping) and response.get("arn") == expected_response)


def _finding(record: Mapping[str, Any], account: str, target: str,
             name: str, flag: str, prior: str | None = None) -> dict[str, Any]:
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    result = {
        "cloud.provider": "aws", "event.source": "monitoring.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": target,
        flag: True,
    }
    if prior:
        result["correlation_evidence"] = {"prior_event_id": prior}
    return result


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    base = _base(record)
    if base is None:
        return []
    account, region, request = base
    name = record["eventName"]
    targets = _targets(name, request)
    if name == "PutMetricStream":
        if not targets or not _put_valid(request, record.get("responseElements"),
                                          account, region, targets[0]):
            return []
        flag = "request.cloudwatch_metric_stream_firehose_configured"
        synthetic = "MetricStreamFirehoseConfigured"
    else:
        flag = {
            "StopMetricStreams": "request.cloudwatch_metric_stream_stopped",
            "StartMetricStreams": "request.cloudwatch_metric_stream_started",
            "DeleteMetricStream": "request.cloudwatch_metric_stream_deleted",
        }[name]
        synthetic = name
    return [_finding(record, account, target, synthetic, flag) for target in targets]


def _namespace_scope(request: Mapping[str, Any]) -> frozenset[str] | None:
    if "excludeFilters" in request:
        return None
    filters = request.get("includeFilters")
    if not isinstance(filters, list) or not filters or len(filters) > 1000:
        return None
    names = []
    for item in filters:
        if not isinstance(item, Mapping):
            return None
        namespace = item.get("namespace")
        if (not isinstance(namespace, str) or not namespace or len(namespace) > 255
                or "metricNames" in item):
            return None
        names.append(namespace)
    return frozenset(names)


def correlate_filter_expansion(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Compare namespace-only filters with the latest strictly earlier event."""
    by_time: dict[datetime, list[tuple[Mapping[str, Any], str, str, str, frozenset[str]]]] = defaultdict(list)
    for record in records:
        base = _base(record)
        if base is None or record.get("eventName") != "PutMetricStream":
            continue
        account, region, request = base
        targets = _targets("PutMetricStream", request)
        when = _when(record.get("eventTime"))
        scope = _namespace_scope(request)
        if (not targets or when is None or scope is None
                or not _put_valid(request, record.get("responseElements"), account, region, targets[0])):
            continue
        by_time[when].append((record, account, region, targets[0], scope))
    prior: dict[tuple[str, str, str], tuple[datetime, frozenset[str], str]] = {}
    findings = []
    for when in sorted(by_time):
        group = by_time[when]
        counts: dict[tuple[str, str, str], int] = defaultdict(int)
        for _record, account, region, name, _scope in group:
            counts[account, region, name] += 1
        for record, account, region, name, scope in group:
            key = account, region, name
            previous = prior.get(key)
            if (counts[key] == 1 and previous and when - previous[0] <= _WINDOW
                    and previous[1] < scope):
                findings.append(_finding(record, account, name,
                    "MetricStreamNamespaceScopeExpanded",
                    "request.cloudwatch_metric_stream_scope_expanded", previous[2]))
        for record, account, region, name, scope in group:
            key = account, region, name
            if counts[key] == 1:
                prior[key] = when, scope, record["eventID"]
            else:
                prior.pop(key, None)
    return findings
