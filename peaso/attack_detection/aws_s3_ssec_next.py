"""S3 SSE-C write and short-retention observations from CloudTrail.

Customer-provided encryption key bytes and their MD5 are never normalized.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
import re
from typing import Any
from urllib.parse import parse_qs, unquote


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")


def _common(record: Mapping[str, Any], names: set[str], category: str):
    if (record.get("eventSource") != "s3.amazonaws.com"
            or record.get("eventName") not in names
            or record.get("eventCategory") != category
            or record.get("eventType") != "AwsApiCall"
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
    bucket = request.get("bucketName")
    if not isinstance(bucket, str) or _BUCKET.fullmatch(bucket) is None:
        return None
    return account, region, identity["arn"], when, bucket, request


def _rules(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, Mapping):
        return []
    rules = value.get("Rule")
    rules = [rules] if isinstance(rules, Mapping) else rules
    return [x for x in rules if isinstance(x, Mapping)] if isinstance(rules, list) else []


def _short_lifecycle(value: Any):
    current = noncurrent = False
    for rule in _rules(value):
        if rule.get("Status") != "Enabled":
            continue
        filter_ = rule.get("Filter")
        prefix = filter_.get("Prefix") if isinstance(filter_, Mapping) else rule.get("Prefix")
        if not isinstance(prefix, str):
            continue
        exp = rule.get("Expiration")
        old = rule.get("NoncurrentVersionExpiration")
        current |= (isinstance(exp, Mapping) and type(exp.get("Days")) is int
                    and 1 <= exp["Days"] <= 7)
        noncurrent |= (isinstance(old, Mapping) and type(old.get("NoncurrentDays")) is int
                       and 1 <= old["NoncurrentDays"] <= 7)
    return current, noncurrent


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if name not in {"PutBucketEncryption", "PutBucketLifecycle"}:
        return None
    common = _common(record, {name}, "Management")
    if common is None:
        return None
    account, region, actor, when, bucket, request = common
    enabled = False
    current = noncurrent = False
    if name == "PutBucketEncryption":
        for rule in _rules(request.get("ServerSideEncryptionConfiguration")):
            blocked = rule.get("BlockedEncryptionTypes")
            if isinstance(blocked, Mapping) and blocked.get("EncryptionType") == "NONE":
                enabled = True
    else:
        current, noncurrent = _short_lifecycle(request.get("LifecycleConfiguration"))
    if not (enabled or current or noncurrent):
        return None
    return {"cloud.provider": "aws", "event.source": "s3.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record["eventTime"],
            "account.id": account, "actor.id": actor, "target.id": f"s3://{bucket}",
            "request.s3_ssec_unblocked": enabled,
            "request.s3_short_current_expiration": current,
            "request.s3_short_noncurrent_expiration": noncurrent}


def _object(record: Mapping[str, Any], bucket: str, key: str) -> bool:
    resources = record.get("resources")
    if not isinstance(resources, list) or not key or len(key) > 1024:
        return False
    wanted = f"arn:aws:s3:::{bucket}/{key}"
    return any(isinstance(x, Mapping) and x.get("type") == "AWS::S3::Object"
               and x.get("ARN") == wanted
               and x.get("accountId") in (None, record["recipientAccountId"])
               for x in resources)


def _canonical(record: Mapping[str, Any], actor: str, bucket: str, key: str,
               name: str, flag: str, evidence: Mapping[str, str]):
    return {"cloud.provider": "aws", "event.source": "s3.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record["eventTime"],
            "account.id": record["recipientAccountId"], "actor.id": actor,
            "target.id": f"s3://{bucket}/{key}", flag: True,
            "correlation_evidence": dict(evidence)}


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    writes = []
    for record in records:
        name = record.get("eventName")
        if name not in {"PutObject", "CopyObject"}:
            continue
        common = _common(record, {name}, "Data")
        response = record.get("responseElements")
        if common is None or not isinstance(response, Mapping):
            continue
        account, region, actor, when, bucket, request = common
        key = request.get("key")
        if not isinstance(key, str) or not _object(record, bucket, key):
            continue
        version = response.get("x-amz-version-id")
        if not isinstance(version, str) or not version:
            continue
        writes.append((when, account, region, actor, bucket, key, name, request,
                       response, version, record))

    output = []
    for when, account, region, actor, bucket, key, name, request, response, version, record in writes:
        if name == "PutObject":
            if (request.get("x-amz-server-side-encryption-customer-algorithm") != "AES256"
                    or response.get("x-amz-server-side-encryption-customer-algorithm") != "AES256"
                    or version.lower() == "null"):
                continue
            output.append(_canonical(record, actor, bucket, key,
                "S3ObjectVersionWrittenWithCustomerKey",
                "request.s3_object_version_ssec_written",
                {"ssec_put_event_id": record["eventID"]}))
        elif name == "CopyObject":
            source = request.get("x-amz-copy-source")
            if not isinstance(source, str) or len(source) > 2000:
                continue
            path, _, query = unquote(source).lstrip("/").partition("?")
            if path != f"{bucket}/{key}":
                continue
            requested_source_version = parse_qs(query).get("versionId", [])
            if (requested_source_version and (len(requested_source_version) != 1
                    or response.get("x-amz-copy-source-version-id") != requested_source_version[0])):
                continue
            if (request.get("x-amz-server-side-encryption-customer-algorithm") != "AES256"
                    or response.get("x-amz-server-side-encryption-customer-algorithm") != "AES256"
                    or version in requested_source_version):
                continue
            output.append(_canonical(record, actor, bucket, key,
                "S3ObjectCopiedOverItselfWithCustomerKey",
                "request.s3_object_ssec_self_copy",
                {"ssec_copy_event_id": record["eventID"]}))
    return output
