"""Bounded DynamoDB table data-event signals; never expose item keys or values."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_TABLE = re.compile(r"[A-Za-z0-9_.-]{3,255}\Z")
_FULL_SELECT = re.compile(r"\s*SELECT\s+\*\s+FROM\s+(?:\"([A-Za-z0-9_.-]+)\"|([A-Za-z0-9_.-]+))\s*;?\s*\Z", re.I)
_NAMES = {"GetItem", "BatchGetItem", "TransactGetItems", "Query", "Scan",
          "ExecuteStatement", "BatchExecuteStatement", "UpdateItem", "PutItem"}
_READ_ONLY = {"GetItem", "BatchGetItem", "TransactGetItems", "Query", "Scan"}


def _table_arns(record: Mapping[str, Any], prefix: str) -> list[str]:
    resources = record.get("resources")
    if not isinstance(resources, list):
        return []
    result = []
    for item in resources:
        if not isinstance(item, Mapping) or item.get("type") != "AWS::DynamoDB::Table":
            continue
        arn = item.get("ARN")
        if isinstance(arn, str) and arn.startswith(prefix) and _TABLE.fullmatch(arn[len(prefix):]):
            result.append(arn)
    return sorted(set(result))


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "dynamodb.amazonaws.com"
            or not isinstance(name, str) or name not in _NAMES
            or record.get("eventCategory") != "Data"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is True
            # CloudTrail marks both PartiQL APIs as readOnly=false even for SELECT.
            or record.get("readOnly") is not (name in _READ_ONLY)
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    prefix = f"arn:aws:dynamodb:{region}:{account}:table/"
    targets = _table_arns(record, prefix)
    if not targets:
        return None
    table_name = request.get("tableName")
    if isinstance(table_name, str) and _TABLE.fullmatch(table_name):
        expected = prefix + table_name
        if expected not in targets:
            return None

    full_scan = name == "Scan" and not any(request.get(key) for key in (
        "filterExpression", "scanFilter", "exclusiveStartKey", "segment"))
    statement = request.get("statement")
    full_partiql = name == "ExecuteStatement" and isinstance(statement, str) and bool(_FULL_SELECT.fullmatch(statement))
    batch_items = request.get("requestItems")
    batch_select = (name == "BatchExecuteStatement" and isinstance(batch_items, list)
                    and bool(batch_items) and all(isinstance(item, Mapping)
                    and isinstance(item.get("statement"), str)
                    and re.match(r"\s*SELECT\s+", item["statement"], re.I)
                    for item in batch_items))
    old_image = name in {"UpdateItem", "PutItem"} and request.get("returnValue") == "ALL_OLD"
    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    return {
        "cloud.provider": "aws", "event.source": "dynamodb.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": actor,
        "target.id": targets[0] if len(targets) == 1 else None,
        "request.dynamodb_get_item": name == "GetItem",
        "request.dynamodb_batch_get_item": name == "BatchGetItem",
        "request.dynamodb_transact_get_items": name == "TransactGetItems",
        "request.dynamodb_query": name == "Query",
        "request.dynamodb_unfiltered_scan": full_scan,
        "request.dynamodb_unfiltered_partiql_select": full_partiql,
        "request.dynamodb_batch_partiql_read": batch_select,
        "request.dynamodb_old_image_requested": old_image,
    }
