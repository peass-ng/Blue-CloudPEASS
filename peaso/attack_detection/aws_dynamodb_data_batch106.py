"""DynamoDB cross-table writes and bounded denied-read to PartiQL correlation."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
import re
from typing import Any

from .aws_dynamodb_data_batch105 import normalize as normalize_table_data


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_TABLE = re.compile(r"[A-Za-z0-9_.-]{3,255}\Z")


def _base(record: Mapping[str, Any]) -> tuple[str, str, str | None, Mapping[str, Any], list[str]] | None:
    if (record.get("eventSource") != "dynamodb.amazonaws.com"
            or record.get("eventCategory") != "Data"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is True
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request = record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping)):
        return None
    prefix = f"arn:aws:dynamodb:{region}:{account}:table/"
    resources = record.get("resources")
    if not isinstance(resources, list):
        return None
    table_resources = [item for item in resources if isinstance(item, Mapping)
                       and item.get("type") == "AWS::DynamoDB::Table"]
    if any(not isinstance(item.get("ARN"), str)
           or not item["ARN"].startswith(prefix)
           or not _TABLE.fullmatch(item["ARN"][len(prefix):])
           for item in table_resources):
        return None
    targets = sorted({item["ARN"] for item in table_resources})
    if not targets:
        return None
    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    return account, region, actor, request, targets


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if not isinstance(name, str) or name not in {"BatchGetItem", "TransactWriteItems", "BatchWriteItem", "DeleteItem"}:
        return None
    common = _base(record)
    if common is None:
        return None
    account, _region, actor, request, targets = common
    error = record.get("errorCode")
    if name == "TransactWriteItems":
        failed = error == "TransactionCanceledException"
        if not failed or record.get("readOnly") is not False:
            return None
    elif error or record.get("errorMessage"):
        return None
    elif record.get("readOnly") is not (name == "BatchGetItem"):
        return None
    request_items = request.get("requestItems")
    multi_table = False
    if name == "BatchGetItem" and isinstance(request_items, list):
        requested = {item.get("tableName") for item in request_items
                     if isinstance(item, Mapping) and isinstance(item.get("tableName"), str)}
        resource_names = {target.rsplit("/", 1)[1] for target in targets}
        multi_table = len(requested) >= 2 and requested == resource_names
    old_transaction = False
    if name == "TransactWriteItems" and isinstance(request_items, list):
        old_transaction = any(isinstance(item, Mapping)
                              and item.get("operation") == "Update"
                              and item.get("returnValuesOnConditionCheckFailure") == "ALL_OLD"
                              for item in request_items)
    batch_write = (name == "BatchWriteItem" and isinstance(request_items, list)
                   and any(isinstance(item, Mapping)
                           and item.get("operation") in {"Put", "Delete"}
                           and isinstance(item.get("tableName"), str)
                           and any(target.endswith("/" + item["tableName"]) for target in targets)
                           for item in request_items))
    delete_old = name == "DeleteItem" and request.get("returnValue") == "ALL_OLD"
    return {
        "cloud.provider": "aws", "event.source": "dynamodb.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if error else "success",
        "event.id": record["eventID"], "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": actor,
        "target.id": targets[0] if len(targets) == 1 else None,
        "request.dynamodb_multi_table_batch_get": multi_table,
        "request.dynamodb_transaction_old_image_on_failure": old_transaction,
        "request.dynamodb_batch_write": batch_write,
        "request.dynamodb_delete_old_image": delete_old,
    }


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
    except ValueError:
        return None


def correlate_partiql_after_denials(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    denied: dict[tuple[str, str, str, str], list[tuple[datetime, str, str]]] = {}
    selects: list[tuple[datetime, Mapping[str, Any], Mapping[str, Any]]] = []
    for record in records:
        common = _base(record)
        if common is None or len(common[4]) != 1:
            continue
        account, _region, actor, _request, targets = common
        when = _when(record.get("eventTime"))
        if not isinstance(actor, str) or not actor or when is None:
            continue
        key = account, actor, targets[0], record.get("awsRegion")
        name = record.get("eventName")
        if not isinstance(name, str):
            continue
        if (name in {"GetItem", "Scan", "TransactGetItems"} and record.get("readOnly") is True
                and record.get("errorCode") in {"AccessDenied", "AccessDeniedException"}):
            denied.setdefault(key, []).append((when, name, record["eventID"]))
        elif name == "ExecuteStatement":
            normalized = normalize_table_data(record)
            if normalized and normalized.get("request.dynamodb_unfiltered_partiql_select") is True:
                selects.append((when, record, normalized))
    result = []
    for when, record, normalized in selects:
        key = normalized["account.id"], normalized["actor.id"], normalized["target.id"], record.get("awsRegion")
        preceding = [item for item in denied.get(key, []) if timedelta(0) <= when - item[0] <= timedelta(minutes=15)]
        by_name = {name: event_id for _time, name, event_id in preceding}
        if "Scan" not in by_name or not ({"GetItem", "TransactGetItems"} & by_name.keys()):
            continue
        result.append({
            "cloud.provider": "aws", "event.source": "dynamodb.amazonaws.com",
            "event.name": "ClassicReadsDeniedThenPartiQLSelect", "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record.get("eventTime"),
            "account.id": normalized["account.id"], "actor.id": normalized["actor.id"],
            "target.id": normalized["target.id"],
            "request.dynamodb_classic_denial_partiql_select": True,
            "correlation_evidence": {"denied_scan_event_id": by_name["Scan"],
                                     "denied_second_read_event_id": by_name.get("GetItem") or by_name["TransactGetItems"]},
        })
    return result
