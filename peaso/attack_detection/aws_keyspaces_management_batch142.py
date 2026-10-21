"""Accepted Keyspaces CDC discovery and destructive table configuration changes."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,47}\Z")
_ROUTES = {
    "CreateTable": ("KeyspacesCdcTableCreated", "request.keyspaces_cdc_table_created", False),
    "ListStreams": ("KeyspacesStreamsListed", "request.keyspaces_streams_listed", True),
    "GetStream": ("KeyspacesStreamRead", "request.keyspaces_stream_read", True),
    "DropTable": ("KeyspacesTableDropped", "request.keyspaces_table_dropped", False),
}


def _table_arn(region: str, account: str, keyspace: str, table: str) -> str:
    return f"arn:aws:cassandra:{region}:{account}:/keyspace/{keyspace}/table/{table}"


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name = record.get("eventName")
    if name not in _ROUTES and name != "AlterTable":
        return []
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request = record.get("requestParameters")
    expected_read_only = name in {"ListStreams", "GetStream"}
    if (record.get("eventSource") != "cassandra.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not expected_read_only
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str)):
        return []
    try:
        stamp = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return []
    except ValueError:
        return []
    if name == "GetStream":
        arn = request.get("streamArn")
        pattern = rf"arn:aws:cassandra:{re.escape(region)}:{account}:/keyspace/([A-Za-z][A-Za-z0-9_]{{0,47}})/table/([A-Za-z][A-Za-z0-9_]{{0,47}})/stream/([A-Za-z0-9_.:-]{{1,128}})\Z"
        if not isinstance(arn, str) or not re.fullmatch(pattern, arn):
            return []
    else:
        keyspace, table = request.get("keyspaceName"), request.get("tableName")
        if (not isinstance(keyspace, str) or not _NAME.fullmatch(keyspace)
                or not isinstance(table, str) or not _NAME.fullmatch(table)):
            return []
        arn = _table_arn(region, account, keyspace, table)
    if name in {"CreateTable", "AlterTable", "DropTable"}:
        query = request.get("rawquery")
        if not isinstance(query, str) or len(query) > 20_000:
            return []
        operation = {"CreateTable": "CREATE", "AlterTable": "ALTER", "DropTable": "DROP"}[name]
        prefix = rf'^\s*{operation}\s+TABLE\s+"{re.escape(keyspace)}"\."{re.escape(table)}"(?=\s|\(|$)'
        if not re.search(prefix, query, re.IGNORECASE):
            return []
    if name == "CreateTable":
        if not re.search(r"\bWITH\s+cdc\s*=\s*true\b", query, re.IGNORECASE):
            return []
        synthetic, marker, _ = _ROUTES[name]
        signals = [(synthetic, marker)]
    elif name == "AlterTable":
        signals = []
        if re.search(r"point_in_time_recovery['\"]?\s*:\s*\{\s*['\"]?status['\"]?\s*:\s*['\"]disabled['\"]", query, re.IGNORECASE):
            signals.append(("KeyspacesPitrDisabled", "request.keyspaces_pitr_disabled"))
        if re.search(r"\b(?:WITH|AND)\s+cdc\s*=\s*false\b", query, re.IGNORECASE):
            signals.append(("KeyspacesCdcDisabled", "request.keyspaces_cdc_disabled"))
        if not signals:
            return []
    else:
        synthetic, marker, _ = _ROUTES[name]
        signals = [(synthetic, marker)]
    actor = record.get("userIdentity")
    common = {
        "cloud.provider": "aws", "event.source": "cassandra.amazonaws.com",
        "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account,
        "actor.id": actor.get("arn") if isinstance(actor, Mapping) else None,
        "target.id": arn,
    }
    return [{**common, "event.name": synthetic, marker: True}
            for synthetic, marker in signals]
