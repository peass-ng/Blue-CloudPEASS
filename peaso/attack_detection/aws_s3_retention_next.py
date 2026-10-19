"""S3 bucket retention and deletion control-plane observations."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def _one_day_all_keys(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    rules = value.get("Rule")
    rules = [rules] if isinstance(rules, Mapping) else rules
    if not isinstance(rules, list):
        return False
    for rule in rules:
        if not isinstance(rule, Mapping) or rule.get("Status") != "Enabled":
            continue
        filter_ = rule.get("Filter")
        expiration = rule.get("Expiration")
        if (isinstance(filter_, Mapping) and filter_.get("Prefix") == ""
                and set(filter_) == {"Prefix"} and isinstance(expiration, Mapping)
                and type(expiration.get("Days")) is int and expiration["Days"] == 1):
            return True
    return False


def _public_object_read(value: Any, bucket: str) -> bool:
    if not isinstance(value, Mapping):
        return False
    statements = value.get("Statement")
    statements = [statements] if isinstance(statements, Mapping) else statements
    if not isinstance(statements, list):
        return False
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        if statement.get("Condition") or "NotAction" in statement or "NotResource" in statement:
            continue
        principal = statement.get("Principal")
        if principal != "*" and not (isinstance(principal, Mapping) and principal.get("AWS") == "*"):
            continue
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        resources = statement.get("Resource")
        resources = [resources] if isinstance(resources, str) else resources
        if (isinstance(actions, list) and any(a in {"s3:GetObject", "s3:*", "*"} for a in actions)
                and isinstance(resources, list)
                and f"arn:aws:s3:::{bucket}/*" in resources):
            return True
    return False


def normalize_aws_s3_retention(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "s3.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"PutBucketVersioning", "PutBucketLifecycle", "DeleteBucket",
                    "PutBucketObjectLockConfiguration",
                    "PutBucketPublicAccessBlock", "PutBucketPolicy", "PutBucketAcl", "PutBucketWebsite"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("readOnly") is not False or record.get("managementEvent") is not True):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    bucket = request.get("bucketName")
    if not isinstance(bucket, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
        return None
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    versioning = request.get("VersioningConfiguration")
    versioning = versioning if isinstance(versioning, Mapping) else {}
    block = request.get("PublicAccessBlockConfiguration")
    website = request.get("WebsiteConfiguration")
    redirect = website.get("RedirectAllRequestsTo") if isinstance(website, Mapping) else None
    lock = request.get("ObjectLockConfiguration")
    lock = lock if isinstance(lock, Mapping) else {}
    lock_rule = lock.get("Rule")
    retention = lock_rule.get("DefaultRetention") if isinstance(lock_rule, Mapping) else None
    return {
        "cloud.provider": "aws", "event.source": "s3.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId") or identity.get("accountId"),
        "actor.id": identity.get("arn"), "target.id": f"s3://{bucket}",
        "request.s3_versioning_suspended": (
            name == "PutBucketVersioning" and not failed and versioning.get("Status") == "Suspended"
        ),
        "request.s3_broad_one_day_expiration": (
            name == "PutBucketLifecycle" and not failed
            and _one_day_all_keys(request.get("LifecycleConfiguration"))
        ),
        "request.s3_bucket_deleted": name == "DeleteBucket" and not failed,
        "request.all_public_access_blocks_disabled": (
            name == "PutBucketPublicAccessBlock" and not failed and isinstance(block, Mapping)
            and all(block.get(k) is False for k in ("RestrictPublicBuckets", "BlockPublicPolicy",
                                                  "BlockPublicAcls", "IgnorePublicAcls"))
        ),
        "request.unconditional_public_object_read_policy": (
            name == "PutBucketPolicy" and not failed and _public_object_read(request.get("bucketPolicy"), bucket)
        ),
        "request.public_read_bucket_acl": (
            name == "PutBucketAcl" and not failed
            and request.get("x-amz-acl") in {"public-read", "public-read-write"}
        ),
        "request.website_redirect_all": (
            name == "PutBucketWebsite" and not failed and isinstance(redirect, Mapping)
            and isinstance(redirect.get("HostName"), str) and bool(redirect["HostName"])
        ),
        "request.s3_default_compliance_retention": (
            name == "PutBucketObjectLockConfiguration"
            and not failed and lock.get("ObjectLockEnabled") == "Enabled"
            and isinstance(retention, Mapping) and retention.get("Mode") == "COMPLIANCE"
            and ((type(retention.get("Days")) is int and retention["Days"] >= 1)
                 or (type(retention.get("Years")) is int and retention["Years"] >= 1))
        ),
    }
