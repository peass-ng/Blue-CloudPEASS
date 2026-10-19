"""Accepted indefinite EventBridge archive creation or update."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_eventbridge_archive(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "events.amazonaws.com"
            or name not in {"CreateArchive", "UpdateArchive"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    account, region, archive_name = record.get("recipientAccountId"), record.get("awsRegion"), request.get("archiveName")
    if (not isinstance(account, str) or re.fullmatch(r"\d{12}", account) is None
            or not isinstance(region, str)
            or not isinstance(archive_name, str) or re.fullmatch(r"[A-Za-z0-9._-]{1,48}", archive_name) is None):
        return None
    arn = f"arn:aws:events:{region}:{account}:archive/{archive_name}"
    source_valid = True
    if name == "CreateArchive":
        source = request.get("eventSourceArn")
        source_valid = isinstance(source, str) and re.fullmatch(
            rf"arn:aws:events:{re.escape(region)}:{account}:event-bus/[A-Za-z0-9._/-]+", source) is not None
    retention = request.get("retentionDays", 0 if name == "CreateArchive" else None)
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": "events.amazonaws.com",
            "event.name": name, "event.outcome": "failure" if failed else "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity.get("arn"), "target.id": arn,
            "request.eventbridge_indefinite_archive": (
                not failed and source_valid and retention == 0 and response.get("archiveArn") == arn
            )}
