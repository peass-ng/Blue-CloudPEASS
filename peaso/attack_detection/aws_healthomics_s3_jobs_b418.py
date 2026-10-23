"""CloudTrail signals for HealthOmics read-set S3 import/export jobs."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _time(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Omit S3 URIs, role ARN, sample/subject IDs and read-set IDs."""
    name = record.get("eventName")
    if (record.get("eventSource") != "omics.amazonaws.com"
            or name not in {"StartReadSetImportJob", "StartReadSetExportJob"}
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request, response = (record.get("userIdentity"),
                                   record.get("requestParameters"), record.get("responseElements"))
    if (not _nonempty(account) or not _ACCOUNT.fullmatch(account)
            or not _nonempty(region) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or identity.get("type") == "AWSService" or not _nonempty(identity.get("arn"))
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or not _nonempty(request.get("sequenceStoreId"))
            or not _nonempty(request.get("roleArn"))
            or not request["roleArn"].startswith(f"arn:aws:iam::{account}:role/")
            or not isinstance(request.get("sources"), list) or not request["sources"]
            or response.get("sequenceStoreId") != request["sequenceStoreId"]
            or response.get("status") not in {"SUBMITTED", "IN_PROGRESS"}
            or not _nonempty(response.get("id"))
            or not _nonempty(record.get("eventID")) or not _time(record.get("eventTime"))):
        return None
    if name == "StartReadSetImportJob":
        if (response.get("roleArn") != request["roleArn"]
                or not all(isinstance(source, Mapping)
                           and _nonempty(source.get("sampleId"))
                           and _nonempty(source.get("subjectId"))
                           and source.get("sourceFileType") in {"FASTQ", "BAM", "CRAM", "UBAM"}
                           and isinstance(source.get("sourceFiles"), Mapping)
                           and _nonempty(source["sourceFiles"].get("source1"))
                           and source["sourceFiles"]["source1"].startswith("s3://")
                           for source in request["sources"])):
            return None
        marker = "request.healthomics_read_set_import_submitted"
    else:
        destination = request.get("destination")
        if (not _nonempty(destination) or not destination.startswith("s3://")
                or response.get("destination") != destination
                or not all(isinstance(source, Mapping)
                           and _nonempty(source.get("readSetId"))
                           for source in request["sources"])):
            return None
        marker = "request.healthomics_read_set_export_submitted"
    store = request["sequenceStoreId"]
    target = "sha256:" + hashlib.sha256(f"{account}:{region}:sequence:{store}".encode()).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "omics.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": target,
        marker: True,
    }
