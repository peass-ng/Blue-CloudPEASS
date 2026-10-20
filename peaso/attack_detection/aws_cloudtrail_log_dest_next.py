"""Correlate CloudTrail log destinations with S3 and KMS control-plane writes.

These signals require a CreateTrail or UpdateTrail event in the ingested window.
They describe accepted configuration and key-state changes, not proven data loss.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")
_KEY = re.compile(r"arn:aws(?:-us-gov|-cn)?:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+\Z")


def _common(record: Mapping[str, Any], source: str, names: set[str]):
    if (record.get("eventSource") != source or record.get("eventName") not in names
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
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


def _rules(value: Any):
    if not isinstance(value, Mapping):
        return []
    rules = value.get("Rule")
    rules = [rules] if isinstance(rules, Mapping) else rules
    return [x for x in rules if isinstance(x, Mapping)] if isinstance(rules, list) else []


def _short_log_expiration(value: Any, account: str) -> bool:
    for rule in _rules(value):
        if rule.get("Status") != "Enabled":
            continue
        expiration = rule.get("Expiration")
        if (not isinstance(expiration, Mapping) or type(expiration.get("Days")) is not int
                or not 1 <= expiration["Days"] <= 7):
            continue
        filter_ = rule.get("Filter")
        prefix = filter_.get("Prefix") if isinstance(filter_, Mapping) else rule.get("Prefix")
        if isinstance(prefix, str) and f"AWSLogs/{account}/CloudTrail/".startswith(prefix):
            return True
    return False


def _items(value: Any):
    return value if isinstance(value, list) else [value]


def _delivery_deny(value: Any, bucket: str, account: str, trail_arn: str) -> bool:
    if not isinstance(value, Mapping):
        return False
    for statement in _items(value.get("Statement")):
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Deny":
            continue
        principal = statement.get("Principal")
        if principal != "*" and not (isinstance(principal, Mapping)
                and "cloudtrail.amazonaws.com" in _items(principal.get("Service"))):
            continue
        if not any(x in {"s3:PutObject", "s3:*", "*"} for x in _items(statement.get("Action"))):
            continue
        resources = _items(statement.get("Resource"))
        if not any(isinstance(x, str) and x in {
                f"arn:aws:s3:::{bucket}/*", f"arn:aws:s3:::{bucket}/AWSLogs/*",
                f"arn:aws:s3:::{bucket}/AWSLogs/{account}/*"} for x in resources):
            continue
        condition = statement.get("Condition")
        if condition and condition != {"StringEquals": {"aws:SourceArn": trail_arn}}:
            continue
        return True
    return False


def _bucket_cmk(value: Any, account: str, region: str) -> str | None:
    for rule in _rules(value):
        default = rule.get("ApplyServerSideEncryptionByDefault")
        if not isinstance(default, Mapping) or default.get("SSEAlgorithm") != "aws:kms":
            continue
        key = default.get("KMSMasterKeyID")
        if isinstance(key, str) and _KEY.fullmatch(key):
            parts = key.split(":")
            if parts[3:5] == [region, account]:
                return key
    return None


def _canonical(record: Mapping[str, Any], actor: str, target: str,
               name: str, flag: str, evidence: Mapping[str, str]):
    return {"cloud.provider": "aws", "event.source": record["eventSource"],
            "event.name": name, "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record["eventTime"],
            "account.id": record["recipientAccountId"], "actor.id": actor,
            "target.id": target, flag: True, "correlation_evidence": dict(evidence)}


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    trails = []
    bucket_writes = []
    key_writes = []
    for record in records:
        name = record.get("eventName")
        if name in {"CreateTrail", "UpdateTrail"}:
            common = _common(record, "cloudtrail.amazonaws.com", {name})
            response = record.get("responseElements")
            if common is None or not isinstance(response, Mapping):
                continue
            account, region, actor, when, request = common
            bucket, arn = response.get("s3BucketName"), response.get("trailARN")
            if (not isinstance(bucket, str) or _BUCKET.fullmatch(bucket) is None
                    or not isinstance(arn, str) or not arn.startswith(
                        f"arn:aws:cloudtrail:{region}:{account}:trail/")
                    or response.get("name") != request.get("name")):
                continue
            key = response.get("kmsKeyId")
            if not (isinstance(key, str) and _KEY.fullmatch(key)):
                key = None
            trails.append((when, account, region, actor, bucket, arn, key, name, record))
        elif name in {"PutBucketLifecycle", "PutBucketPolicy", "PutBucketEncryption"}:
            common = _common(record, "s3.amazonaws.com", {name})
            if common is not None:
                account, region, actor, when, request = common
                bucket = request.get("bucketName")
                if isinstance(bucket, str) and _BUCKET.fullmatch(bucket):
                    bucket_writes.append((when, account, region, actor, bucket, name, request, record))
        elif name in {"DisableKey", "ScheduleKeyDeletion"}:
            common = _common(record, "kms.amazonaws.com", {name})
            response = record.get("responseElements")
            if common is None or not isinstance(response, Mapping):
                continue
            account, region, actor, when, request = common
            key = response.get("keyId")
            requested = request.get("keyId")
            if (not isinstance(key, str) or _KEY.fullmatch(key) is None
                    or not isinstance(requested, str)
                    or requested not in {key, key.rsplit("/", 1)[-1]}):
                continue
            if name == "ScheduleKeyDeletion" and not (
                    response.get("keyState") == "PendingDeletion"
                    and isinstance(response.get("deletionDate"), str)):
                continue
            key_writes.append((when, account, region, actor, key, name, record))

    output = []
    bucket_key_links = []
    for when, account, region, actor, bucket, name, request, record in bucket_writes:
        prior = [t for t in trails if t[1:3] == (account, region) and t[4] == bucket
                 and timedelta(0) <= when-t[0] <= timedelta(days=30)]
        if not prior:
            continue
        trail = max(prior, key=lambda t: t[0])
        evidence = {"trail_config_event_id": trail[8]["eventID"],
                    "bucket_write_event_id": record["eventID"]}
        if name == "PutBucketLifecycle" and _short_log_expiration(
                request.get("LifecycleConfiguration"), account):
            output.append(_canonical(record, actor, f"s3://{bucket}",
                "CloudTrailLogBucketShortExpirationConfigured",
                "request.cloudtrail_log_bucket_short_expiration", evidence))
        elif name == "PutBucketPolicy" and _delivery_deny(
                request.get("bucketPolicy"), bucket, account, trail[5]):
            output.append(_canonical(record, actor, f"s3://{bucket}",
                "CloudTrailLogDeliveryPolicyDenied",
                "request.cloudtrail_log_delivery_policy_denied", evidence))
        elif name == "PutBucketEncryption":
            key = _bucket_cmk(request.get("ServerSideEncryptionConfiguration"), account, region)
            if key:
                bucket_key_links.append((when, account, region, key, trail[5], record))
                output.append(_canonical(record, actor, f"s3://{bucket}",
                    "CloudTrailLogBucketCustomerKeyConfigured",
                    "request.cloudtrail_log_bucket_customer_key_configured", evidence))

    for trail in trails:
        when, account, region, actor, bucket, arn, key, name, record = trail
        request = record.get("requestParameters")
        if (name == "UpdateTrail" and key and isinstance(request, Mapping)
                and request.get("kmsKeyId") == key):
            output.append(_canonical(record, actor, arn,
                "CloudTrailLogCustomerKeyExplicitlySet",
                "request.cloudtrail_log_customer_key_explicitly_set",
                {"trail_update_event_id": record["eventID"]}))

    for when, account, region, actor, key, name, record in key_writes:
        linked = [(t[0], t[8]["eventID"]) for t in trails if t[1:3] == (account, region)
                  and t[6] == key and timedelta(0) <= when-t[0] <= timedelta(days=30)]
        linked += [(b[0], b[5]["eventID"]) for b in bucket_key_links
                   if b[1:4] == (account, region, key)
                   and timedelta(0) <= when-b[0] <= timedelta(days=30)]
        if not linked:
            continue
        _, config_id = max(linked)
        flag = ("request.cloudtrail_log_cmk_disabled" if name == "DisableKey"
                else "request.cloudtrail_log_cmk_deletion_scheduled")
        output.append(_canonical(record, actor, key,
            "CloudTrailLogCustomerKeyDisabled" if name == "DisableKey"
            else "CloudTrailLogCustomerKeyDeletionScheduled", flag,
            {"log_key_config_event_id": config_id, "key_state_event_id": record["eventID"]}))
    return output
