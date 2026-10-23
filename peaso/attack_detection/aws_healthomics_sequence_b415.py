"""Sanitize accepted HealthOmics sequence-store changes from CloudTrail."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_NAMES = {
    "UpdateSequenceStore", "CreateMultipartReadSetUpload", "UploadReadSetPart",
    "CompleteMultipartReadSetUpload", "BatchDeleteReadSet", "DeleteSequenceStore",
    "GetReadSet",
}


def _time(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Describe only the accepted API, excluding payload, sample and subject IDs."""
    name = record.get("eventName")
    if (record.get("eventSource") != "omics.amazonaws.com" or name not in _NAMES
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name == "GetReadSet")
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request = record.get("userIdentity"), record.get("requestParameters")
    if (not _nonempty(account) or not _ACCOUNT.fullmatch(account)
            or not _nonempty(region) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or identity.get("type") == "AWSService" or not _nonempty(identity.get("arn"))
            or not isinstance(request, Mapping)
            or not _nonempty(request.get("sequenceStoreId"))
            or not _nonempty(record.get("eventID")) or not _time(record.get("eventTime"))):
        return None
    store_id = request["sequenceStoreId"]
    response = record.get("responseElements")
    if name == "UpdateSequenceStore":
        if (not isinstance(request.get("propagatedSetLevelTags"), list)
                or not all(_nonempty(tag) for tag in request["propagatedSetLevelTags"])
                or not isinstance(response, Mapping) or response.get("id") != store_id):
            return None
    elif name == "CreateMultipartReadSetUpload":
        if (not _nonempty(request.get("sampleId")) or not _nonempty(request.get("subjectId"))
                or not _nonempty(request.get("name"))
                or request.get("sourceFileType") not in {"FASTQ", "BAM", "CRAM", "UBAM"}
                or not isinstance(response, Mapping)
                or response.get("sequenceStoreId") != store_id
                or not _nonempty(response.get("uploadId"))):
            return None
    elif name == "UploadReadSetPart":
        if (not _nonempty(request.get("uploadId"))
                or request.get("partSource") not in {"SOURCE1", "SOURCE2"}
                or not isinstance(request.get("partNumber"), int)
                or isinstance(request["partNumber"], bool) or request["partNumber"] < 1
                or not isinstance(response, Mapping)
                or not _nonempty(response.get("checksum"))):
            return None
    elif name == "CompleteMultipartReadSetUpload":
        if (not _nonempty(request.get("uploadId"))
                or not isinstance(request.get("parts"), list) or not request["parts"]
                or not isinstance(response, Mapping)
                or not _nonempty(response.get("readSetId"))):
            return None
    elif name == "BatchDeleteReadSet":
        if (not isinstance(request.get("ids"), list) or not request["ids"]
                or not all(_nonempty(item) for item in request["ids"])):
            return None
    elif name == "GetReadSet":
        if (not _nonempty(request.get("id"))
                or request.get("file") not in {"SOURCE1", "SOURCE2", "INDEX"}
                or not isinstance(request.get("partNumber"), int)
                or isinstance(request["partNumber"], bool) or request["partNumber"] < 1):
            return None
    target_material = f"{account}:{region}:{store_id}"
    if name == "GetReadSet":
        target_material += f":{request['id']}"
    target = "sha256:" + hashlib.sha256(target_material.encode()).hexdigest()[:24]
    event = {
        "cloud.provider": "aws", "event.source": "omics.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": target,
    }
    if name == "GetReadSet":
        event["request.healthomics_read_set_part_retrieved"] = True
    else:
        event["request.healthomics_sequence_store_change_accepted"] = True
    return event
