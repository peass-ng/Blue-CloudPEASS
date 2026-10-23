"""HealthOmics read-set downloads through its service-owned S3 access point."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_BUCKET = re.compile(r"aws-omics-[a-z0-9-]{1,63}\Z")
_ALIAS = re.compile(r"[a-z0-9-]+-s3alias\Z")


def _valid_time(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Retain the actor and a hashed object target, omitting the genomic key."""
    if (record.get("eventSource") != "s3.amazonaws.com"
            or record.get("eventName") != "GetObject"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Data"
            or record.get("managementEvent") is not False
            or record.get("readOnly") is not True
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request, resources = (record.get("userIdentity"),
                                    record.get("requestParameters"), record.get("resources"))
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or identity.get("type") == "AWSService"
            or not isinstance(identity.get("arn"), str) or not identity["arn"]
            or not isinstance(request, Mapping) or not isinstance(resources, list)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not _valid_time(record.get("eventTime"))):
        return None
    bucket, alias, key = (request.get("bucketName"), request.get("accessPointAlias"),
                          request.get("key"))
    if (not isinstance(bucket, str) or not _BUCKET.fullmatch(bucket)
            or region not in bucket
            or not isinstance(alias, str) or not _ALIAS.fullmatch(alias)
            or not isinstance(key, str) or not key or len(key) > 1024):
        return None
    bucket_resource = f"arn:aws:s3:::{bucket}"
    object_resource = f"{bucket_resource}/{key}"
    owners = {item.get("accountId") for item in resources if isinstance(item, Mapping)
               and item.get("type") == "AWS::S3::Bucket"
               and item.get("ARN") == bucket_resource
               and isinstance(item.get("accountId"), str)
               and _ACCOUNT.fullmatch(item["accountId"])
               and item["accountId"] != account}
    if len(owners) != 1:
        return None
    if not any(isinstance(item, Mapping)
               and item.get("type") == "AWS::S3::Object"
               and item.get("ARN") == object_resource for item in resources):
        return None
    access_points = [item for item in resources if isinstance(item, Mapping)
                     and item.get("type") == "AWS::S3::AccessPoint"
                     and isinstance(item.get("accountId"), str)
                     and _ACCOUNT.fullmatch(item["accountId"])
                     and item["accountId"] in owners
                     and isinstance(item.get("ARN"), str)
                     and item["ARN"].startswith(
                         f"arn:aws:s3:{region}:{item['accountId']}:accesspoint/")]
    if len(access_points) != 1:
        return None
    extra = record.get("additionalEventData")
    if not isinstance(extra, Mapping) or str(extra.get("httpStatusCode")) != "200":
        return None
    target = "sha256:" + hashlib.sha256(
        f"{account}:{region}:{bucket}:{key}".encode()).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "s3.amazonaws.com",
        "event.name": "GetObject", "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": target,
        "request.healthomics_s3_read_set_read": True,
    }
