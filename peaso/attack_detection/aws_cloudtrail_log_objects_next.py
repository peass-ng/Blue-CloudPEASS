"""Correlate versioned CloudTrail log-object changes with trail configuration."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any
from urllib.parse import parse_qs, unquote


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")
_KEY_ARN = re.compile(r"arn:aws(?:-us-gov|-cn)?:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+\Z")


def _common(record: Mapping[str, Any], source: str, names: set[str], category: str):
    if (record.get("eventSource") != source or record.get("eventName") not in names
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != category
            or record.get("managementEvent") is not (category == "Management")
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region, identity, request = (record.get("recipientAccountId"),
        record.get("awsRegion"), record.get("userIdentity"), record.get("requestParameters"))
    if (not isinstance(account, str) or _ACCOUNT.fullmatch(account) is None
            or not isinstance(region, str) or not region
            or not isinstance(identity, Mapping) or not isinstance(identity.get("arn"), str)
            or identity.get("accountId") not in (None, account)
            or not isinstance(request, Mapping)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None
    return account, region, identity["arn"], when, request


def _s3_object(record: Mapping[str, Any], bucket: str, key: str) -> bool:
    if not key.startswith(f"AWSLogs/{record['recipientAccountId']}/CloudTrail/"):
        return False
    resources = record.get("resources")
    if not isinstance(resources, list):
        return False
    wanted = f"arn:aws:s3:::{bucket}/{key}"
    return any(isinstance(x, Mapping) and x.get("type") == "AWS::S3::Object"
               and x.get("ARN") == wanted
               and x.get("accountId") in (None, record["recipientAccountId"])
               for x in resources)


def _same_object_copy(request: Mapping[str, Any], response: Mapping[str, Any],
                      bucket: str, key: str) -> str | None:
    source = request.get("x-amz-copy-source")
    if not isinstance(source, str) or len(source) > 2000:
        return None
    path, _, query = unquote(source).lstrip("/").partition("?")
    if path != f"{bucket}/{key}":
        return None
    version = parse_qs(query).get("versionId", [])
    if version and (len(version) != 1 or response.get("x-amz-copy-source-version-id") != version[0]):
        return None
    requested = request.get("x-amz-server-side-encryption-aws-kms-key-id")
    if (request.get("x-amz-server-side-encryption") != "aws:kms"
            or response.get("x-amz-server-side-encryption") != "aws:kms"
            or not isinstance(requested, str) or _KEY_ARN.fullmatch(requested) is None
            or response.get("x-amz-server-side-encryption-aws-kms-key-id") != requested
            or not isinstance(response.get("x-amz-version-id"), str)
            or not response["x-amz-version-id"]):
        return None
    return requested


def _canonical(record: Mapping[str, Any], actor: str, target: str,
               name: str, flag: str, evidence: Mapping[str, str]):
    return {"cloud.provider": "aws", "event.source": record["eventSource"],
            "event.name": name, "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record["eventTime"],
            "account.id": record["recipientAccountId"], "actor.id": actor,
            "target.id": target, flag: True, "correlation_evidence": dict(evidence)}


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    trails = []
    starts = []
    stops = []
    object_writes = []
    bucket_deletes = []
    key_disables = []
    for record in records:
        name = record.get("eventName")
        if name == "CreateTrail":
            common = _common(record, "cloudtrail.amazonaws.com", {name}, "Management")
            response = record.get("responseElements")
            if common is None or not isinstance(response, Mapping):
                continue
            account, region, actor, when, request = common
            bucket, trail_name, arn = (response.get("s3BucketName"),
                                       response.get("name"), response.get("trailARN"))
            if (not isinstance(bucket, str) or _BUCKET.fullmatch(bucket) is None
                    or not isinstance(trail_name, str) or not trail_name
                    or request.get("name") != trail_name or request.get("s3BucketName") != bucket
                    or not isinstance(arn, str) or not arn.startswith(
                        f"arn:aws:cloudtrail:{region}:{account}:trail/")
                    or not arn.endswith("/" + trail_name)):
                continue
            trails.append((when, account, region, actor, bucket, trail_name, arn, record))
        elif name in {"StartLogging", "StopLogging", "DeleteTrail"}:
            common = _common(record, "cloudtrail.amazonaws.com", {name}, "Management")
            if common is not None:
                account, region, actor, when, request = common
                ref = request.get("name")
                if isinstance(ref, str) and ref:
                    (starts if name == "StartLogging" else stops).append((
                        when, account, region, ref, name, record))
        elif name in {"CopyObject", "DeleteObject"}:
            common = _common(record, "s3.amazonaws.com", {name}, "Data")
            response = record.get("responseElements")
            if common is None or not isinstance(response, Mapping):
                continue
            account, region, actor, when, request = common
            bucket, key = request.get("bucketName"), request.get("key")
            if (not isinstance(bucket, str) or _BUCKET.fullmatch(bucket) is None
                    or not isinstance(key, str) or not _s3_object(record, bucket, key)):
                continue
            object_writes.append((when, account, region, actor, bucket, key,
                                  name, request, response, record))
        elif name == "DeleteBucket":
            common = _common(record, "s3.amazonaws.com", {name}, "Management")
            if common is not None:
                account, region, actor, when, request = common
                bucket = request.get("bucketName")
                if isinstance(bucket, str) and _BUCKET.fullmatch(bucket):
                    bucket_deletes.append((when, account, region, actor, bucket, record))
        elif name == "DisableKey":
            common = _common(record, "kms.amazonaws.com", {name}, "Management")
            response = record.get("responseElements")
            if common is None or not isinstance(response, Mapping):
                continue
            account, region, actor, when, request = common
            key, requested = response.get("keyId"), request.get("keyId")
            if (isinstance(key, str) and _KEY_ARN.fullmatch(key)
                    and isinstance(requested, str)
                    and requested in {key, key.rsplit("/", 1)[-1]}):
                key_disables.append((when, account, region, actor, key, record))

    output = []
    copies = []
    for when, account, region, actor, bucket, key, name, request, response, record in object_writes:
        prior = [t for t in trails if t[1:3] == (account, region) and t[4] == bucket
                 and timedelta(0) <= when-t[0] <= timedelta(days=30)]
        if not prior:
            continue
        trail = max(prior, key=lambda x: x[0])
        evidence = {"trail_create_event_id": trail[7]["eventID"],
                    "object_write_event_id": record["eventID"]}
        target = f"s3://{bucket}/{key}"
        if name == "CopyObject":
            cmk = _same_object_copy(request, response, bucket, key)
            if cmk:
                copies.append((when, account, region, cmk, record))
                output.append(_canonical(record, actor, target,
                    "CloudTrailHistoricalLogCopiedWithCustomerKey",
                    "request.cloudtrail_historical_log_cmk_copy", evidence))
        elif name == "DeleteObject":
            version = request.get("versionId")
            if isinstance(version, str) and version and response.get("x-amz-version-id") == version:
                output.append(_canonical(record, actor, target,
                    "CloudTrailHistoricalLogVersionDeleted",
                    "request.cloudtrail_log_version_deleted", evidence))
            elif (version is None and response.get("x-amz-delete-marker") == "true"
                  and isinstance(response.get("x-amz-version-id"), str)):
                output.append(_canonical(record, actor, target,
                    "CloudTrailLogDeleteMarkerCreated",
                    "request.cloudtrail_log_delete_marker_created", evidence))

    for when, account, region, actor, key, record in key_disables:
        previous = [c for c in copies if c[1:4] == (account, region, key)
                    and timedelta(0) <= when-c[0] <= timedelta(hours=24)]
        if not previous:
            continue
        copy = max(previous, key=lambda x: x[0])
        output.append(_canonical(record, actor, key,
            "CloudTrailReencryptedLogCustomerKeyDisabled",
            "request.cloudtrail_reencrypted_log_cmk_disabled",
            {"log_copy_event_id": copy[4]["eventID"],
             "key_disable_event_id": record["eventID"]}))

    for when, account, region, actor, bucket, record in bucket_deletes:
        prior = [t for t in trails if t[1:3] == (account, region) and t[4] == bucket
                 and timedelta(0) <= when-t[0] <= timedelta(days=30)]
        for trail in sorted(prior, key=lambda x: x[0], reverse=True):
            running = [s for s in starts if s[1:3] == (account, region)
                       and s[3] in {trail[5], trail[6]}
                       and trail[0] <= s[0] < when]
            if not running:
                continue
            latest_start = max(running, key=lambda x: x[0])
            halted = [s for s in stops if s[1:3] == (account, region)
                      and s[3] in {trail[5], trail[6]}
                      and latest_start[0] < s[0] <= when]
            if halted:
                continue
            output.append(_canonical(record, actor, f"s3://{bucket}",
                "CloudTrailLogBucketDeletedWhileLogging",
                "request.cloudtrail_log_bucket_deleted_while_logging",
                {"trail_create_event_id": trail[7]["eventID"],
                 "trail_start_event_id": latest_start[5]["eventID"],
                 "bucket_delete_event_id": record["eventID"]}))
            break
    return output
