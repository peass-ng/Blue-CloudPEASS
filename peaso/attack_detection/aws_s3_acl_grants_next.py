"""S3 object ACL, CORS and Access Grants signals from CloudTrail.

These are API observations. They do not prove unauthenticated object access,
browser data theft, or privilege escalation by the location role.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")
_ROLE = re.compile(r"arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+\Z")
_PRINCIPAL = re.compile(r"arn:aws:iam::[0-9]{12}:(?:user|role)/[A-Za-z0-9+=,.@_/-]+\Z")


def _valid(record: Mapping[str, Any], *, category: str, read_only: bool):
    if (record.get("eventSource") != "s3.amazonaws.com"
            or record.get("eventCategory") != category
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not (category == "Management")
            or record.get("readOnly") is not read_only
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account = record.get("recipientAccountId")
    region = record.get("awsRegion")
    identity = record.get("userIdentity")
    request = record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not region
            or not isinstance(identity, Mapping)
            or not isinstance(identity.get("arn"), str)
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
    return account, identity["arn"], request


def _resource(record: Mapping[str, Any], kind: str, arn: str, account: str):
    resources = record.get("resources")
    return (isinstance(resources, list)
            and any(isinstance(r, Mapping) and r.get("type") == kind
                    and r.get("ARN") == arn and r.get("accountId") in (None, account)
                    for r in resources))


def _instance(record: Mapping[str, Any], account: str):
    arn = f"arn:aws:s3:{record['awsRegion']}:{account}:access-grants/default"
    return _resource(record, "AWS:S3::AccessGrantsInstance", arn, account)


def _base(record: Mapping[str, Any], actor: str, account: str, target: str, flag: str):
    return {"cloud.provider": "aws", "event.source": "s3.amazonaws.com",
            "event.name": record["eventName"], "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record["eventTime"],
            "account.id": account, "actor.id": actor, "target.id": target, flag: True}


def _bucket_scope(value: Any):
    if not isinstance(value, str) or not value.startswith("s3://"):
        return None
    path = value[5:]
    bucket, sep, rest = path.partition("/")
    if not sep or not _BUCKET.fullmatch(bucket):
        return None
    return bucket, rest


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if name not in {"PutObjectAcl", "PutBucketCors", "CreateAccessGrantsLocation",
                    "CreateAccessGrant", "GetDataAccess"}:
        return None
    category = "Data" if name == "PutObjectAcl" else "Management"
    common = _valid(record, category=category, read_only=(name == "GetDataAccess"))
    if common is None:
        return None
    account, actor, request = common

    if name == "PutObjectAcl":
        bucket, key = request.get("bucketName"), request.get("key")
        if (not isinstance(bucket, str) or not _BUCKET.fullmatch(bucket)
                or not isinstance(key, str) or not key or len(key) > 1024
                or request.get("x-amz-acl") not in {"public-read", "public-read-write"}
                or not _resource(record, "AWS::S3::Object", f"arn:aws:s3:::{bucket}/{key}", account)):
            return None
        version = request.get("versionId")
        if version is None:
            flag = "request.s3_current_object_public_acl"
        elif isinstance(version, str) and version and version.lower() != "null" and len(version) <= 256:
            flag = "request.s3_historical_object_public_acl"
        else:
            return None
        return _base(record, actor, account, f"s3://{bucket}/{key}", flag)

    if name == "PutBucketCors":
        bucket = request.get("bucketName")
        config = request.get("CORSConfiguration")
        if (not isinstance(bucket, str) or not _BUCKET.fullmatch(bucket)
                or not _resource(record, "AWS::S3::Bucket", f"arn:aws:s3:::{bucket}", account)
                or not isinstance(config, Mapping)):
            return None
        rules = config.get("CORSRule")
        rules = [rules] if isinstance(rules, Mapping) else rules
        if not isinstance(rules, list):
            return None
        for rule in rules:
            if not isinstance(rule, Mapping):
                continue
            origins = rule.get("AllowedOrigin")
            methods = rule.get("AllowedMethod")
            origins = [origins] if isinstance(origins, str) else origins
            methods = [methods] if isinstance(methods, str) else methods
            if isinstance(origins, list) and "*" in origins and isinstance(methods, list) \
                    and any(m in {"GET", "PUT", "POST", "DELETE", "HEAD"} for m in methods):
                return _base(record, actor, account, f"s3://{bucket}",
                             "request.s3_wildcard_cors")
        return None

    if not _instance(record, account):
        return None
    if name == "CreateAccessGrantsLocation":
        body = request.get("CreateAccessGrantsLocationRequest")
        if not isinstance(body, Mapping):
            return None
        role = body.get("IAMRoleArn")
        scope = _bucket_scope(body.get("LocationScope"))
        if (not isinstance(role, str) or not (match := _ROLE.fullmatch(role))
                or match.group(1) != account or scope is None or scope[1] != ""):
            return None
        return _base(record, actor, account, f"s3://{scope[0]}",
                     "request.s3_access_grants_bucket_location_registered")

    if name == "CreateAccessGrant":
        body = request.get("CreateAccessGrantRequest")
        if not isinstance(body, Mapping):
            return None
        loc = body.get("AccessGrantsLocationId")
        grantee = body.get("Grantee")
        config = body.get("AccessGrantsLocationConfiguration")
        if (not isinstance(loc, str) or not re.fullmatch(r"[A-Za-z0-9-]{8,128}", loc)
                or not isinstance(grantee, Mapping) or grantee.get("GranteeType") != "IAM"
                or not isinstance(grantee.get("GranteeIdentifier"), str)
                or not _PRINCIPAL.fullmatch(grantee["GranteeIdentifier"])
                or not isinstance(config, Mapping) or config.get("S3SubPrefix") != "*"
                or body.get("Permission") not in {"READ", "READWRITE"}):
            return None
        return _base(record, actor, account, f"access-grants-location:{loc}",
                     "request.s3_access_grants_broad_iam_grant")

    target = _bucket_scope(request.get("target"))
    if target is None or not target[1] or request.get("permission") not in {"READ", "READWRITE", "WRITE"}:
        return None
    return _base(record, actor, account, f"s3://{target[0]}",
                 "request.s3_access_grants_data_access_requested")
