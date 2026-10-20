"""Accepted CloudWatch Logs data reads and historical export requests.

Log messages, query results and opaque record pointers never enter normalized
detection evidence. Success records identify an accepted API read, while the
actual data returned must be verified separately.
"""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_SOURCE = "logs.amazonaws.com"
_NAMES = {
    "GetLogEvents": "request.cloudwatch_logs_stream_events_read",
    "FilterLogEvents": "request.cloudwatch_logs_group_events_filtered",
    "GetQueryResults": "request.cloudwatch_logs_known_query_results_read",
    "GetLogRecord": "request.cloudwatch_logs_known_record_read",
    "CreateExportTask": "request.cloudwatch_logs_history_export_started",
}
_GROUP = re.compile(r"[./#A-Za-z0-9_-]{1,512}\Z")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != _SOURCE:
        return None
    name = record.get("eventName")
    if not isinstance(name, str) or name not in _NAMES:
        return None
    account, region, identity = (record.get("recipientAccountId"), record.get("awsRegion"),
                                 record.get("userIdentity"))
    if (not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account)
            or not isinstance(region, str) or not region
            or not isinstance(identity, Mapping) or not isinstance(identity.get("arn"), str)
            or identity.get("accountId") not in (None, account)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str) or not record["eventTime"]
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name != "CreateExportTask")
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping):
        return None
    response = response if isinstance(response, Mapping) else {}
    target = None
    if name in {"GetLogEvents", "FilterLogEvents", "CreateExportTask"}:
        group = request.get("logGroupName")
        if not isinstance(group, str) or not _GROUP.fullmatch(group):
            return None
        target = group
        if name == "GetLogEvents":
            stream = request.get("logStreamName")
            if not isinstance(stream, str) or not stream or len(stream) > 512:
                return None
        elif name == "CreateExportTask":
            bucket, start, end = request.get("destination"), request.get("from"), request.get("to")
            if (not isinstance(bucket, str) or not _BUCKET.fullmatch(bucket)
                    or type(start) is not int or type(end) is not int or start >= end
                    or not isinstance(response.get("taskId"), str) or not response["taskId"]):
                return None
    elif name == "GetQueryResults":
        query_id = request.get("queryId")
        if not isinstance(query_id, str) or not 1 <= len(query_id) <= 256:
            return None
    else:
        pointer = request.get("logRecordPointer")
        if not isinstance(pointer, str) or not pointer or len(pointer) > 8192:
            return None
    return {"cloud.provider": "aws", "event.source": _SOURCE,
            "event.name": name, "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record["eventTime"],
            "account.id": account, "actor.id": identity["arn"], "target.id": target,
            _NAMES[name]: True}
