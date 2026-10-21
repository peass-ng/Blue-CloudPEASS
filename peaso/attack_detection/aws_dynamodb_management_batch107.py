"""Normalize accepted DynamoDB export, restore, replica and Kinesis requests."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_TABLE = re.compile(r"[A-Za-z0-9_.-]{3,255}\Z")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")
_NAMES = {"ExportTableToPointInTime", "RestoreTableToPointInTime",
          "EnableKinesisStreamingDestination", "UpdateTable"}


def _valid_table(value: Any) -> bool:
    return isinstance(value, str) and bool(_TABLE.fullmatch(value))


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "dynamodb.amazonaws.com" or name not in _NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request = record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping)):
        return None
    target = request.get("tableName")
    flags = {
        "request.dynamodb_pitr_export": False,
        "request.dynamodb_pitr_restore": False,
        "request.dynamodb_kinesis_destination_enabled": False,
        "request.dynamodb_regional_replica_created": False,
    }
    accepted = not (record.get("errorCode") or record.get("errorMessage"))
    if name == "ExportTableToPointInTime":
        source_arn = request.get("tableArn")
        prefix = f"arn:aws:dynamodb:{region}:{account}:table/"
        if not isinstance(source_arn, str) or not source_arn.startswith(prefix):
            return None
        target = source_arn[len(prefix):]
        if not _valid_table(target):
            return None
        bucket = request.get("s3Bucket")
        owner = request.get("s3BucketOwner")
        flags["request.dynamodb_pitr_export"] = bool(
            accepted and isinstance(bucket, str) and _BUCKET.fullmatch(bucket)
            and (owner is None or isinstance(owner, str) and _ACCOUNT.fullmatch(owner)))
    elif name == "RestoreTableToPointInTime":
        source, target = request.get("sourceTableName"), request.get("targetTableName")
        if not _valid_table(source) or not _valid_table(target):
            return None
        flags["request.dynamodb_pitr_restore"] = bool(accepted and source != target)
    elif name == "EnableKinesisStreamingDestination":
        stream = request.get("streamArn")
        if not _valid_table(target):
            return None
        flags["request.dynamodb_kinesis_destination_enabled"] = bool(
            accepted and isinstance(stream, str)
            and re.fullmatch(r"arn:aws:kinesis:" + re.escape(region)
                             + r":[0-9]{12}:stream/[A-Za-z0-9_.-]{1,128}", stream))
    else:
        if not _valid_table(target):
            return None
        updates = request.get("replicaUpdates")
        if isinstance(updates, list):
            flags["request.dynamodb_regional_replica_created"] = bool(
                accepted and any(
                    isinstance(item, Mapping) and isinstance(item.get("create"), Mapping)
                    and isinstance(item["create"].get("regionName"), str)
                    and _REGION.fullmatch(item["create"]["regionName"])
                    and item["create"]["regionName"] != region
                    for item in updates))
    actor = record.get("userIdentity")
    actor = actor if isinstance(actor, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": record["eventSource"],
        "event.name": name, "event.outcome": "success" if accepted else "failure",
        "event.id": record["eventID"], "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": actor.get("arn"), "target.id": target,
        **flags,
    }
