"""Normalize explicit S3 bucket configuration writes from CloudTrail."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from .aws_security_controls import _arn, _event_time


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+\Z")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")
_NAMES = {"PutBucketPublicAccessBlock", "PutBucketPolicy", "PutBucketAcl", "PutBucketWebsite"}
_PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _contains(value: Any, expected: str) -> bool:
    return value == expected or isinstance(value, list) and expected in value


def _public_object_read(policy: Any, bucket: str, partition: str) -> bool:
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            return False
    if not isinstance(policy, Mapping):
        return False
    statements = policy.get("Statement")
    if isinstance(statements, Mapping):
        statements = [statements]
    if not isinstance(statements, list):
        return False
    object_prefix = f"arn:{partition}:s3:::{bucket}/"
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        if statement.get("Condition") or "NotAction" in statement or "NotResource" in statement:
            continue
        principal = statement.get("Principal")
        if principal != "*" and not (isinstance(principal, Mapping) and _contains(principal.get("AWS"), "*")):
            continue
        if not any(_contains(statement.get("Action"), action) for action in ("s3:GetObject", "s3:*", "*")):
            continue
        resources = statement.get("Resource")
        resources = resources if isinstance(resources, list) else [resources]
        if any(value == "*" or isinstance(value, str) and value.startswith(object_prefix)
               and len(value) > len(object_prefix) for value in resources):
            return True
    return False


def normalize_aws_s3_bucket(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Report the accepted configuration request, never effective public access."""
    if (record.get("eventSource") != "s3.amazonaws.com"
            or record.get("eventName") not in _NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") not in (None, True)
            or record.get("readOnly") not in (None, False)
            or record.get("errorCode") or record.get("errorMessage")
            or "responseElements" not in record):
        return None
    request = record.get("requestParameters")
    response = record.get("responseElements")
    identity = record.get("userIdentity")
    if (not isinstance(request, Mapping) or not isinstance(identity, Mapping)
            or response is not None and not isinstance(response, Mapping)
            or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage"))):
        return None
    account = record.get("recipientAccountId")
    region = record.get("awsRegion")
    actor_arn = identity.get("arn")
    actor = _arn(actor_arn)
    bucket = request.get("bucketName")
    event_id = record.get("eventID")
    event_time = _event_time(record.get("eventTime"))
    try:
        UUID(event_id)
    except (TypeError, ValueError, AttributeError):
        return None
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or actor is None or actor[4] != account or identity.get("accountId") != account
            or not isinstance(identity.get("type"), str) or not identity["type"]
            or not isinstance(bucket, str) or not _BUCKET.fullmatch(bucket)
            or event_time is None):
        return None
    name = record["eventName"]
    pab = request.get("PublicAccessBlockConfiguration")
    website = request.get("WebsiteConfiguration")
    redirect = website.get("RedirectAllRequestsTo") if isinstance(website, Mapping) else None
    redirect_host = redirect.get("HostName") if isinstance(redirect, Mapping) else None
    public_block_off = (name == "PutBucketPublicAccessBlock" and isinstance(pab, Mapping)
                        and all(pab.get(key) is False for key in _PAB_KEYS))
    public_policy = (name == "PutBucketPolicy"
                     and _public_object_read(request.get("bucketPolicy"), bucket, actor[1]))
    public_acl = name == "PutBucketAcl" and request.get("x-amz-acl") in {"public-read", "public-read-write"}
    website_redirect = (name == "PutBucketWebsite" and isinstance(redirect_host, str)
                        and bool(redirect_host.strip()))
    if not any((public_block_off, public_policy, public_acl, website_redirect)):
        return None
    return {
        "cloud.provider": "aws", "cloud.region": region,
        "event.source": "s3.amazonaws.com", "event.name": name,
        "event.outcome": "success", "event.id": event_id, "event.time": event_time,
        "account.id": account, "actor.id": actor_arn, "actor.kind": identity["type"],
        "target.id": f"arn:{actor[1]}:s3:::{bucket}", "request.bucket_name": bucket,
        "request.all_public_access_blocks_disabled": public_block_off,
        "request.unconditional_public_object_read_policy": public_policy,
        "request.public_read_bucket_acl": public_acl,
        "request.website_redirect_all": website_redirect,
        "request.website_redirect_host": redirect_host if website_redirect else None,
    }
