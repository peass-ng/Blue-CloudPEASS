"""IVS recording destination configuration and association signals."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_ID = re.compile(r"[A-Za-z0-9_-]+\Z")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")
_NAMES = {
    "CreateRecordingConfiguration", "GetRecordingConfiguration", "UpdateChannel",
    "CreateStorageConfiguration", "GetStorageConfiguration", "UpdateStage",
}


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _arn(value: Any, account: str, region: str, kind: str) -> str | None:
    if not isinstance(value, str):
        return None
    prefix = f"arn:aws:ivs:{region}:{account}:{kind}/"
    tail = value[len(prefix):] if value.startswith(prefix) else ""
    return value if _ID.fullmatch(tail) else None


def _bucket(value: Any) -> str | None:
    return value if isinstance(value, str) and _BUCKET.fullmatch(value) else None


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name, account, region = (record.get(key) for key in
                             ("eventName", "recipientAccountId", "awsRegion"))
    request, response = record.get("requestParameters"), record.get("responseElements")
    read = name in {"GetRecordingConfiguration", "GetStorageConfiguration"}
    if (not isinstance(name, str) or name not in _NAMES
            or record.get("eventSource") != "ivs.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not read
            or record.get("errorCode") or record.get("errorMessage")
            or (isinstance(response, Mapping)
                and (response.get("errorCode") or response.get("errorMessage")))
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str)
            or not isinstance(request, Mapping)):
        return []
    try:
        timestamp = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            return []
    except ValueError:
        return []

    result = _mapping(response)
    target = None
    if name == "CreateRecordingConfiguration":
        destination = _mapping(request.get("destinationConfiguration"))
        bucket = _bucket(_mapping(destination.get("s3")).get("bucketName"))
        item = _mapping(result.get("recordingConfiguration"))
        target = _arn(item.get("arn"), account, region, "recording-configuration")
        if (bucket is None or target is None
                or _mapping(_mapping(item.get("destinationConfiguration")).get("s3")).get("bucketName") != bucket):
            return []
        synthetic, flag = "IvsRecordingConfigurationCreated", "request.ivs_recording_configuration_created"
    elif name == "GetRecordingConfiguration":
        target = _arn(request.get("arn"), account, region, "recording-configuration")
        synthetic, flag = "IvsRecordingDestinationRead", "request.ivs_recording_destination_read"
    elif name == "CreateStorageConfiguration":
        bucket = _bucket(_mapping(request.get("s3")).get("bucketName"))
        item = _mapping(result.get("storageConfiguration"))
        target = _arn(item.get("arn"), account, region, "storage-configuration")
        if bucket is None or target is None or _mapping(item.get("s3")).get("bucketName") != bucket:
            return []
        synthetic, flag = "IvsStorageConfigurationCreated", "request.ivs_storage_configuration_created"
    elif name == "GetStorageConfiguration":
        target = _arn(request.get("arn"), account, region, "storage-configuration")
        synthetic, flag = "IvsStageStorageDestinationRead", "request.ivs_stage_storage_destination_read"
    elif name == "UpdateChannel":
        target = _arn(request.get("arn"), account, region, "channel")
        item = _mapping(result.get("channel"))
        destination = request.get("recordingConfigurationArn")
        if target is None or item.get("arn") != target or not isinstance(destination, str):
            return []
        if destination:
            if (_arn(destination, account, region, "recording-configuration") is None
                    or item.get("recordingConfigurationArn") != destination):
                return []
            synthetic, flag = "IvsChannelRecordingAssigned", "request.ivs_channel_recording_assigned"
        else:
            if item.get("recordingConfigurationArn") not in ("", None):
                return []
            synthetic, flag = "IvsChannelRecordingDisabled", "request.ivs_channel_recording_disabled"
    else:
        target = _arn(request.get("arn"), account, region, "stage")
        item = _mapping(result.get("stage"))
        destination = _mapping(request.get("autoParticipantRecordingConfiguration")).get("storageConfigurationArn")
        response_destination = _mapping(item.get("autoParticipantRecordingConfiguration")).get("storageConfigurationArn")
        if target is None or item.get("arn") != target or not isinstance(destination, str):
            return []
        if destination:
            if (_arn(destination, account, region, "storage-configuration") is None
                    or response_destination != destination):
                return []
            synthetic, flag = "IvsStageRecordingAssigned", "request.ivs_stage_recording_assigned"
        else:
            if response_destination not in ("", None):
                return []
            synthetic, flag = "IvsStageRecordingDisabled", "request.ivs_stage_recording_disabled"
    if target is None:
        return []
    identity = _mapping(record.get("userIdentity"))
    return [{
        "cloud.provider": "aws", "event.source": "ivs.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": target, flag: True,
    }]
