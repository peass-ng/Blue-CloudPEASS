"""Normalize DynamoDB backup, stream, index and recovery control events."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_TABLE = re.compile(r"[A-Za-z0-9_.-]{3,255}\Z")
_NAMES = {"UpdateTable", "UpdateContinuousBackups", "CreateBackup",
          "RestoreTableFromBackup", "DeleteBackup"}
_FLAGS = (
    "request.dynamodb_old_new_stream_enabled",
    "request.dynamodb_all_projection_gsi_created",
    "request.dynamodb_pitr_enabled",
    "request.dynamodb_backup_created",
    "request.dynamodb_backup_restored",
    "request.dynamodb_backup_deleted",
)


def _backup_arn(value: Any, region: str, account: str) -> bool:
    prefix = f"arn:aws:dynamodb:{region}:{account}:table/"
    if not isinstance(value, str) or not value.startswith(prefix):
        return False
    parts = value[len(prefix):].split("/backup/")
    return len(parts) == 2 and bool(_TABLE.fullmatch(parts[0])) and bool(parts[1])


def normalize_aws_dynamodb_backup_stream(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "dynamodb.amazonaws.com" or name not in _NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request = record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping)):
        return None
    target = (request.get("targetTableName") if name == "RestoreTableFromBackup" else
              request.get("backupArn") if name == "DeleteBackup" else
              request.get("tableName"))
    if (name == "DeleteBackup" and not _backup_arn(target, region, account)
            or name != "DeleteBackup" and
            (not isinstance(target, str) or not _TABLE.fullmatch(target))):
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    response = record.get("responseElements")
    response = response if isinstance(response, Mapping) else {}
    accepted = not failed
    stream = request.get("streamSpecification")
    stream = stream if isinstance(stream, Mapping) else {}
    index_updates = request.get("globalSecondaryIndexUpdates")
    index_updates = index_updates if isinstance(index_updates, list) else []
    gsi_all = any(isinstance(item, Mapping) and isinstance(item.get("create"), Mapping)
                  and isinstance(item["create"].get("indexName"), str)
                  and bool(item["create"]["indexName"])
                  and isinstance(item["create"].get("projection"), Mapping)
                  and item["create"]["projection"].get("projectionType") == "ALL"
                  for item in index_updates)
    table_response = response.get("tableDescription")
    table_response = table_response if isinstance(table_response, Mapping) else {}
    same_table_updating = (table_response.get("tableName") == target
                           and table_response.get("tableStatus") == "UPDATING")
    pitr = request.get("pointInTimeRecoverySpecification")
    pitr = pitr if isinstance(pitr, Mapping) else {}
    backup_name = request.get("backupName")
    flags = dict.fromkeys(_FLAGS, False)
    flags["request.dynamodb_old_new_stream_enabled"] = bool(
        accepted and name == "UpdateTable" and same_table_updating
        and stream.get("streamEnabled") is True
        and stream.get("streamViewType") == "NEW_AND_OLD_IMAGES")
    flags["request.dynamodb_all_projection_gsi_created"] = bool(
        accepted and name == "UpdateTable" and same_table_updating and gsi_all)
    flags["request.dynamodb_pitr_enabled"] = bool(
        accepted and name == "UpdateContinuousBackups"
        and pitr.get("pointInTimeRecoveryEnabled") is True)
    flags["request.dynamodb_backup_created"] = bool(
        accepted and name == "CreateBackup" and isinstance(backup_name, str)
        and bool(backup_name))
    flags["request.dynamodb_backup_restored"] = bool(
        accepted and name == "RestoreTableFromBackup"
        and _backup_arn(request.get("backupArn"), region, account))
    flags["request.dynamodb_backup_deleted"] = bool(
        accepted and name == "DeleteBackup")
    actor = record.get("userIdentity")
    actor = actor if isinstance(actor, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": record["eventSource"],
            "event.name": name, "event.outcome": "failure" if failed else "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": actor.get("arn"), "target.id": target,
            **flags}
