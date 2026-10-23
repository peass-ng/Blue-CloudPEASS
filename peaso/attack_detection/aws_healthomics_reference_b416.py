"""Privacy preserving HealthOmics reference-store CloudTrail signals."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_NAMES = {"StartReferenceImportJob", "GetReference", "DeleteReference",
          "DeleteReferenceStore"}


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
    """Keep API metadata only; never emit reference bytes, S3 paths or role ARN."""
    name = record.get("eventName")
    if (record.get("eventSource") != "omics.amazonaws.com" or name not in _NAMES
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name == "GetReference")
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request = record.get("userIdentity"), record.get("requestParameters")
    if (not _nonempty(account) or not _ACCOUNT.fullmatch(account)
            or not _nonempty(region) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or identity.get("type") == "AWSService" or not _nonempty(identity.get("arn"))
            or not isinstance(request, Mapping)
            or not _nonempty(request.get("referenceStoreId"))
            or not _nonempty(record.get("eventID")) or not _time(record.get("eventTime"))):
        return None
    store = request["referenceStoreId"]
    if name == "StartReferenceImportJob":
        sources, response = request.get("sources"), record.get("responseElements")
        if (not _nonempty(request.get("roleArn"))
                or not request["roleArn"].startswith(f"arn:aws:iam::{account}:role/")
                or not isinstance(sources, list) or not sources
                or not all(isinstance(source, Mapping)
                           and _nonempty(source.get("sourceFile"))
                           and source["sourceFile"].startswith("s3://")
                           and _nonempty(source.get("name")) for source in sources)
                or not isinstance(response, Mapping)
                or response.get("referenceStoreId") != store
                or response.get("roleArn") != request["roleArn"]
                or response.get("status") not in {"SUBMITTED", "IN_PROGRESS"}
                or not _nonempty(response.get("id"))):
            return None
    elif name == "GetReference":
        if (not _nonempty(request.get("id"))
                or request.get("file") not in {"SOURCE", "INDEX"}
                or not isinstance(request.get("partNumber"), int)
                or isinstance(request["partNumber"], bool)
                or request["partNumber"] < 1):
            return None
    elif name == "DeleteReference":
        if not _nonempty(request.get("id")):
            return None
    target_material = f"{account}:{region}:{store}"
    if name in {"GetReference", "DeleteReference"}:
        target_material += f":{request['id']}"
    target = "sha256:" + hashlib.sha256(target_material.encode()).hexdigest()[:24]
    event = {
        "cloud.provider": "aws", "event.source": "omics.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": target,
    }
    field = {
        "StartReferenceImportJob": "request.healthomics_reference_import_started",
        "GetReference": "request.healthomics_reference_part_retrieved",
        "DeleteReference": "request.healthomics_reference_deletion_accepted",
        "DeleteReferenceStore": "request.healthomics_reference_store_deletion_accepted",
    }[name]
    event[field] = True
    return event
