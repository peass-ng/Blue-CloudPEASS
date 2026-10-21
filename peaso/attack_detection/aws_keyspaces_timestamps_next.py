"""Recognize an accepted Keyspaces table change enabling client timestamps."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,47}\Z")
_ENABLED = re.compile(
    r"['\"]?client_side_timestamps['\"]?\s*:\s*\{\s*['\"]?status['\"]?\s*:\s*['\"]enabled['\"]?\s*\}",
    re.IGNORECASE,
)


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "cassandra.amazonaws.com"
            or record.get("eventName") != "AlterTable"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    event_id, stamp = record.get("eventID"), record.get("eventTime")
    request = record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(event_id, str) or not event_id
            or not isinstance(stamp, str) or not isinstance(request, Mapping)):
        return None
    try:
        if datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
            return None
    except ValueError:
        return None
    keyspace, table = request.get("keyspaceName"), request.get("tableName")
    query = request.get("rawquery")
    if (not isinstance(keyspace, str) or not _NAME.fullmatch(keyspace)
            or not isinstance(table, str) or not _NAME.fullmatch(table)
            or not isinstance(query, str) or len(query) > 20_000):
        return None
    prefix = rf'^\s*ALTER\s+TABLE\s+"{re.escape(keyspace)}"\."{re.escape(table)}"(?=\s|$)'
    properties = re.search(r"\bWITH\s+CUSTOM_PROPERTIES\s*=\s*\{", query, re.IGNORECASE)
    if (not re.search(prefix, query, re.IGNORECASE)
            or properties is None or not _ENABLED.search(query, properties.end())):
        return None
    arn = f"arn:aws:cassandra:{region}:{account}:/keyspace/{keyspace}/table/{table}"
    resources = record.get("resources")
    if (not isinstance(resources, list) or not any(
            isinstance(item, Mapping) and item.get("type") == "AWS::Cassandra::Table"
            and item.get("ARN") == arn for item in resources)):
        return None
    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    return {
        "cloud.provider": "aws", "event.source": "cassandra.amazonaws.com",
        "event.name": "KeyspacesClientSideTimestampsEnabled", "event.outcome": "success",
        "event.id": event_id, "event.time": stamp, "account.id": account,
        "actor.id": actor,
        "target.id": "sha256:" + hashlib.sha256(arn.encode()).hexdigest()[:24],
        "request.keyspaces_client_side_timestamps_enabled": True,
    }
