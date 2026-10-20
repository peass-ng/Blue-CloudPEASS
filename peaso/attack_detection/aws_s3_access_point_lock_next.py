"""S3 Access Point and Object Lock observations from CloudTrail."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")
_AP = re.compile(r"[a-z0-9][a-z0-9-]{1,48}[a-z0-9]\Z")


def _common(record: Mapping[str, Any], category: str, read_only: bool,
            denied: bool = False):
    if (record.get("eventSource") != "s3.amazonaws.com"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != category
            or record.get("managementEvent") is not (category == "Management")
            or record.get("readOnly") is not read_only
            or (record.get("errorCode") != "AccessDenied" if denied
                else bool(record.get("errorCode") or record.get("errorMessage")))):
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
    return account, region, identity["arn"], when, request


def _resource(record: Mapping[str, Any], kind: str, arn: str, account: str):
    resources = record.get("resources")
    return (isinstance(resources, list)
            and any(isinstance(r, Mapping) and r.get("type") == kind
                    and r.get("ARN") == arn and r.get("accountId") in (None, account)
                    for r in resources))


def _bucket(request: Mapping[str, Any]):
    value = request.get("bucketName")
    return value if isinstance(value, str) and _BUCKET.fullmatch(value) else None


def _object(record: Mapping[str, Any], account: str, request: Mapping[str, Any]):
    bucket, key = _bucket(request), request.get("key")
    if (bucket is None or not isinstance(key, str) or not key or len(key) > 1024
            or not _resource(record, "AWS::S3::Object",
                             f"arn:aws:s3:::{bucket}/{key}", account)):
        return None
    return bucket, key


def _event(record: Mapping[str, Any], account: str, actor: str, target: str, flag: str,
           name: str | None = None):
    return {"cloud.provider": "aws", "event.source": "s3.amazonaws.com",
            "event.name": name or record["eventName"], "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record["eventTime"],
            "account.id": account, "actor.id": actor, "target.id": target, flag: True}


def _delegates_to_access_points(policy: Any, account: str, bucket: str):
    if not isinstance(policy, Mapping):
        return False
    statements = policy.get("Statement")
    statements = [statements] if isinstance(statements, Mapping) else statements
    if not isinstance(statements, list):
        return False
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if principal != "*" and (not isinstance(principal, Mapping)
                                 or principal.get("AWS") != "*"):
            continue
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        resources = statement.get("Resource")
        resources = [resources] if isinstance(resources, str) else resources
        condition = statement.get("Condition")
        equals = condition.get("StringEquals") if isinstance(condition, Mapping) else None
        if (isinstance(actions, list) and any(x in {"s3:GetObject", "s3:*", "*"} for x in actions)
                and isinstance(resources, list)
                and f"arn:aws:s3:::{bucket}/*" in resources
                and isinstance(equals, Mapping)
                and equals.get("s3:DataAccessPointAccount") == account):
            return True
    return False


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    names = {"CreateAccessPoint", "PutBucketPolicy", "PutAccessPointPolicy",
             "GetObject", "PutObjectLockLegalHold", "PutObjectLockRetention",
             "PutBucketObjectLockConfiguration"}
    if name not in names:
        return None
    category = "Data" if name in {"GetObject", "PutObjectLockLegalHold",
                                  "PutObjectLockRetention"} else "Management"
    common = _common(record, category, read_only=(name == "GetObject"))
    if common is None:
        return None
    account, region, actor, _, request = common

    if name == "CreateAccessPoint":
        body = request.get("CreateAccessPointRequest")
        bucket = body.get("Bucket") if isinstance(body, Mapping) else None
        if not isinstance(bucket, str) or not _BUCKET.fullmatch(bucket):
            return None
        return _event(record, account, actor, f"s3://{bucket}",
                      "request.s3_access_point_created")

    if name == "PutAccessPointPolicy":
        # CloudTrail omits both access point name and submitted policy body.
        if not isinstance(request.get("PutAccessPointPolicyRequest"), Mapping):
            return None
        return _event(record, account, actor, f"s3-access-points:{account}",
                      "request.s3_access_point_policy_submitted")

    if name == "PutBucketPolicy":
        bucket = _bucket(request)
        if (bucket is None or not _resource(
                record, "AWS::S3::Bucket", f"arn:aws:s3:::{bucket}", account)
                or not _delegates_to_access_points(request.get("bucketPolicy"),
                                                    account, bucket)):
            return None
        return _event(record, account, actor, f"s3://{bucket}",
                      "request.s3_bucket_access_point_delegation")

    if name == "PutBucketObjectLockConfiguration":
        bucket = _bucket(request)
        config = request.get("ObjectLockConfiguration")
        rule = config.get("Rule") if isinstance(config, Mapping) else None
        retention = rule.get("DefaultRetention") if isinstance(rule, Mapping) else None
        if (bucket is None or not _resource(
                record, "AWS::S3::Bucket", f"arn:aws:s3:::{bucket}", account)
                or not isinstance(retention, Mapping)
                or retention.get("Mode") != "GOVERNANCE"
                or not (type(retention.get("Days")) is int and retention["Days"] >= 1
                        or type(retention.get("Years")) is int and retention["Years"] >= 1)):
            return None
        return _event(record, account, actor, f"s3://{bucket}",
                      "request.s3_default_governance_retention")

    object_ = _object(record, account, request)
    if object_ is None:
        return None
    bucket, key = object_
    target = f"s3://{bucket}/{key}"
    if name == "GetObject":
        ap = request.get("accessPointName")
        if (not isinstance(ap, str) or not _AP.fullmatch(ap)
                or request.get("accountId") != account
                or not _resource(record, "AWS::S3::AccessPoint",
                                 f"arn:aws:s3:{region}:{account}:accesspoint/{ap}",
                                 account)):
            return None
        return _event(record, account, actor, target,
                      "request.s3_access_point_object_read")
    version = request.get("versionId")
    if not isinstance(version, str) or not version or version.lower() == "null":
        return None
    if name == "PutObjectLockLegalHold":
        return _event(record, account, actor, target,
                      "request.s3_object_legal_hold_changed")
    return _event(record, account, actor, target,
                  "request.s3_object_retention_changed")


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    denied = []
    reads = []
    for record in records:
        if record.get("eventName") != "GetObject":
            continue
        bad = _common(record, "Data", read_only=True, denied=True)
        if bad is not None:
            account, region, actor, when, request = bad
            object_ = _object(record, account, request)
            if object_ is not None and not request.get("accessPointName"):
                denied.append((account, region, actor, when, object_, record))
        good = normalize(record)
        if good is not None and good.get("request.s3_access_point_object_read") is True:
            common = _common(record, "Data", read_only=True)
            if common is not None:
                account, region, actor, when, request = common
                object_ = _object(record, account, request)
                if object_ is not None:
                    reads.append((account, region, actor, when, object_, record))
    output = []
    for account, region, actor, when, object_, read in reads:
        matching = [item for item in denied
                    if item[:3] == (account, region, actor)
                    and item[4] == object_ and abs(when - item[3]) <= timedelta(minutes=30)
                    and item[5]["eventID"] != read["eventID"]]
        if not matching:
            continue
        denied_event = min(matching, key=lambda item: abs(when - item[3]))[5]
        result = _event(read, account, actor, f"s3://{object_[0]}/{object_[1]}",
                        "request.s3_access_point_read_with_direct_denial",
                        "S3AccessPointReadWithDirectBucketDenial")
        result["correlation_evidence"] = {
            "denied_direct_get_event_id": denied_event["eventID"],
            "accepted_access_point_get_event_id": read["eventID"]}
        output.append(result)
    return output
