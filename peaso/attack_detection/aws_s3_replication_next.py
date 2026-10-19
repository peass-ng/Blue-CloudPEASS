"""Explicit cross-account S3 replication configuration."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_s3_replication(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "s3.amazonaws.com" or record.get("eventName") != "PutBucketReplication":
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    bucket = request.get("bucketName")
    if not isinstance(bucket, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
        return None
    account = record.get("recipientAccountId")
    if not isinstance(account, str) or re.fullmatch(r"\d{12}", account) is None:
        return None
    config = request.get("ReplicationConfiguration")
    rules = config.get("Rule") if isinstance(config, Mapping) else None
    rules = [rules] if isinstance(rules, Mapping) else rules
    external_destination = False
    if isinstance(rules, list):
        for rule in rules:
            if not isinstance(rule, Mapping) or rule.get("Status") != "Enabled":
                continue
            destination = rule.get("Destination")
            if not isinstance(destination, Mapping):
                continue
            owner = destination.get("Account")
            target = destination.get("Bucket")
            if (isinstance(owner, str) and re.fullmatch(r"\d{12}", owner)
                    and owner != account and isinstance(target, str)
                    and re.fullmatch(r"arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", target)):
                external_destination = True
                break
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    return {
        "cloud.provider": "aws", "event.source": "s3.amazonaws.com",
        "event.name": "PutBucketReplication", "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": f"s3://{bucket}",
        "request.s3_explicit_cross_account_replication": not failed and external_destination,
    }
