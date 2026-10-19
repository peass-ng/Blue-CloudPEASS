"""Accepted cancellation of a scheduled KMS key deletion."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_KEY_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


def normalize_aws_kms_cancel_deletion(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "kms.amazonaws.com"
            or record.get("eventName") != "CancelKeyDeletion"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account) or not isinstance(region, str):
        return None
    key = request.get("keyId")
    prefix = f"arn:aws:kms:{region}:{account}:key/"
    if not isinstance(key, str):
        return None
    arn = key if key.startswith(prefix) else prefix + key
    if not _KEY_ID.fullmatch(arn[len(prefix):]):
        return None
    resources = record.get("resources")
    if not isinstance(resources, list) or not any(isinstance(item, Mapping)
            and item.get("accountId") == account and item.get("ARN") == arn
            for item in resources):
        return None
    accepted = (not record.get("errorCode") and not record.get("errorMessage")
                and response.get("keyId") == arn)
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": "kms.amazonaws.com",
            "event.name": "CancelKeyDeletion",
            "event.outcome": "success" if accepted else "failure",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity.get("arn"), "target.id": arn,
            "request.kms_deletion_cancelled": accepted}
