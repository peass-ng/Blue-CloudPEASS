"""Bounded signals for optional Amazon Keyspaces CloudTrail data events."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_ROUTES = {
    "Select": ("KeyspacesTableSelect", "request.keyspaces_table_select", True),
    "Insert": ("KeyspacesTableInsert", "request.keyspaces_table_insert", False),
    "Update": ("KeyspacesTableUpdate", "request.keyspaces_table_update", False),
    "Delete": ("KeyspacesTableDelete", "request.keyspaces_table_delete", False),
    "GetShardIterator": ("KeyspacesShardIterator", "request.keyspaces_shard_iterator", True),
    "GetRecords": ("KeyspacesRecordsRequested", "request.keyspaces_records_requested", True),
}


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if name not in _ROUTES:
        return None
    synthetic, marker, read_only = _ROUTES[name]
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, resources = record.get("requestParameters"), record.get("resources")
    if (record.get("eventSource") != "cassandra.amazonaws.com"
            or record.get("eventCategory") != "Data"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not False
            or record.get("readOnly") is not read_only
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping) or not isinstance(resources, list)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str)):
        return None
    try:
        if datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00")).tzinfo is None:
            return None
    except ValueError:
        return None
    prefix = f"arn:aws:cassandra:{region}:{account}:/keyspace/"
    tables = [item.get("ARN") for item in resources if isinstance(item, Mapping)
              and item.get("type") == "AWS::Cassandra::Table"
              and isinstance(item.get("ARN"), str)
              and item["ARN"].startswith(prefix)]
    if len(tables) != 1:
        return None
    target = tables[0]
    suffix = target[len(prefix):]
    match = re.fullmatch(r"([A-Za-z][A-Za-z0-9_]{0,47})/table/([A-Za-z][A-Za-z0-9_]{0,47})", suffix)
    if not match:
        return None
    keyspace, table = match.groups()
    if name in {"Select", "Insert", "Update", "Delete"}:
        if request.get("keyspaceName") != keyspace or request.get("tableName") != table:
            return None
    else:
        streams = [item.get("ARN") for item in resources if isinstance(item, Mapping)
                   and item.get("type") == "AWS::Cassandra::Stream"
                   and isinstance(item.get("ARN"), str)
                   and item["ARN"].startswith(target + "/stream/")]
        if len(streams) != 1 or not re.fullmatch(re.escape(target) + r"/stream/[A-Za-z0-9_.:-]{1,128}", streams[0]):
            return None
        if name == "GetShardIterator":
            if (request.get("streamArn") != streams[0]
                    or not isinstance(request.get("shardId"), str)
                    or not request["shardId"]):
                return None
        elif not isinstance(request.get("shardIterator"), str) or not request["shardIterator"]:
            return None
    actor = record.get("userIdentity")
    return {
        "cloud.provider": "aws", "event.source": "cassandra.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account,
        "actor.id": actor.get("arn") if isinstance(actor, Mapping) else None,
        "target.id": target,
        marker: True,
    }
