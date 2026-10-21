"""CloudWatch metric data writes and ordered metric stream changes."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any

from .aws_cloudwatch_metric_stream_batch109 import (
    _base, _finding, _put_valid, _targets, _when,
)


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_WINDOW = timedelta(hours=1)
_BURST = timedelta(minutes=1)


def _data(record: Mapping[str, Any]) -> tuple[str, str, str, str, datetime] | None:
    if (record.get("eventSource") != "monitoring.amazonaws.com"
            or record.get("eventName") != "PutMetricData"
            or record.get("eventCategory") != "Data"
            or record.get("eventType") != "AwsApiCall"
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, identity = record.get("requestParameters"), record.get("userIdentity")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping) or not isinstance(identity, Mapping)):
        return None
    namespace = request.get("namespace")
    metric_data = request.get("metricData")
    actor = identity.get("arn")
    when = _when(record.get("eventTime"))
    if (not isinstance(namespace, str) or not namespace or len(namespace) > 255
            or not isinstance(metric_data, list) or not metric_data
            or not any(isinstance(metric, Mapping)
                       and isinstance(metric.get("metricName"), str)
                       and metric["metricName"] for metric in metric_data)
            or not isinstance(actor, str) or not actor or when is None):
        return None
    return account, region, namespace, actor, when


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    data = _data(record)
    if data is None:
        return []
    account, _region, namespace, _actor, _when_value = data
    return [_finding(record, account, namespace, "MetricDataPublished",
                     "request.cloudwatch_metric_data_published")]


def _stream_definition(record: Mapping[str, Any]) -> tuple[str, str, str, datetime,
        tuple[str, frozenset[str]] | None, str, str, str] | None:
    base = _base(record)
    if base is None or record.get("eventName") != "PutMetricStream":
        return None
    account, region, request = base
    targets = _targets("PutMetricStream", request)
    when = _when(record.get("eventTime"))
    if (not targets or when is None or not _put_valid(
            request, record.get("responseElements"), account, region, targets[0])):
        return None
    names = None
    filters = request.get("includeFilters")
    if "excludeFilters" not in request and isinstance(filters, list) and len(filters) == 1:
        item = filters[0]
        if isinstance(item, Mapping) and isinstance(item.get("namespace"), str):
            selected = item.get("metricNames")
            if (isinstance(selected, list) and selected and len(selected) <= 1000
                    and all(isinstance(name, str) and name for name in selected)):
                names = item["namespace"], frozenset(selected)
    return (account, region, targets[0], when, names,
            request["firehoseArn"], request["roleArn"], request["outputFormat"])


def correlate_stream_changes(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Compare accepted, strictly ordered definitions of the same live stream."""
    by_time: dict[datetime, list[tuple[Mapping[str, Any], tuple]]] = defaultdict(list)
    deletes: dict[datetime, list[tuple[str, str, str]]] = defaultdict(list)
    seen_event_ids: set[str] = set()
    for record in records:
        event_id = record.get("eventID")
        if isinstance(event_id, str) and event_id in seen_event_ids:
            continue
        definition = _stream_definition(record)
        if definition:
            seen_event_ids.add(record["eventID"])
            by_time[definition[3]].append((record, definition))
        elif record.get("eventName") == "DeleteMetricStream":
            base = _base(record)
            when = _when(record.get("eventTime"))
            if base and when:
                targets = _targets("DeleteMetricStream", base[2])
                if targets:
                    seen_event_ids.add(record["eventID"])
                    deletes[when].append((base[0], base[1], targets[0]))
    previous: dict[tuple[str, str, str], tuple[Mapping[str, Any], tuple]] = {}
    results = []
    for when in sorted(set(by_time) | set(deletes)):
        for key in deletes[when]:
            previous.pop(key, None)
        group = by_time[when]
        counts: dict[tuple[str, str, str], int] = defaultdict(int)
        for _record, definition in group:
            counts[definition[:3]] += 1
        for record, definition in group:
            account, region, name, _time, names, firehose, role, output = definition
            key = account, region, name
            prior = previous.get(key)
            if counts[key] != 1 or not prior:
                continue
            prior_record, old = prior
            if when - old[3] > _WINDOW:
                continue
            changes = (
                ("MetricStreamMetricNamesExpanded", "request.cloudwatch_metric_names_expanded",
                 old[4] is not None and names is not None
                 and old[4][0] == names[0] and old[4][1] < names[1]),
                ("MetricStreamDestinationChanged", "request.cloudwatch_metric_stream_destination_changed",
                 old[5] != firehose),
                ("MetricStreamRoleRebound", "request.cloudwatch_metric_stream_role_rebound",
                 old[6] != role),
                ("MetricStreamOutputFormatChanged", "request.cloudwatch_metric_stream_format_changed",
                 old[7] != output),
            )
            for event_name, flag, changed in changes:
                if changed:
                    results.append(_finding(record, account, name, event_name,
                                            flag, prior_record["eventID"]))
        for record, definition in group:
            key = definition[:3]
            if counts[key] == 1:
                previous[key] = record, definition
            else:
                previous.pop(key, None)
    return results


def correlate_data_burst(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Emit once when five accepted metric write calls occur in one minute."""
    rows = []
    seen_event_ids: set[str] = set()
    for record in records:
        data = _data(record)
        if data and record["eventID"] not in seen_event_ids:
            seen_event_ids.add(record["eventID"])
            rows.append((data[4], record, data))
    windows: dict[tuple[str, str, str, str], deque[tuple[datetime, str]]] = defaultdict(deque)
    results = []
    for when, record, data in sorted(rows, key=lambda row: row[0]):
        account, region, namespace, actor, _ = data
        window = windows[account, region, namespace, actor]
        while window and when - window[0][0] > _BURST:
            window.popleft()
        old_count = len(window)
        window.append((when, record["eventID"]))
        if old_count == 4:
            result = _finding(record, account, namespace,
                              "MetricDataWriteBurst", "request.cloudwatch_metric_data_burst")
            result["correlation_evidence"] = {
                "prior_event_ids": [event_id for _at, event_id in list(window)[:-1]]}
            results.append(result)
    return results
