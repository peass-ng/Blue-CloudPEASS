"""Scoped CloudTrail evidence for reads of PCS managed Slurm secrets."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_SECRET = re.compile(r"pcs!slurm-secret-[A-Za-z0-9_-]{6,100}-[A-Za-z0-9]{6}\Z")
_ARN = re.compile(
    r"arn:(?:aws|aws-us-gov|aws-cn):secretsmanager:([a-z]{2}(?:-[a-z]+)+-[0-9]):([0-9]{12}):secret:(.+)\Z"
)


def normalize_aws_pcs_slurm_secret_read(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Identify an accepted secret read without copying secret or request content."""
    if (record.get("eventSource") != "secretsmanager.amazonaws.com"
            or record.get("eventName") != "GetSecretValue"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not True
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request, identity = record.get("requestParameters"), record.get("userIdentity")
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if (not isinstance(request, Mapping) or not isinstance(identity, Mapping)
            or identity.get("type") not in {"IAMUser", "AssumedRole", "Root"}
            or identity.get("accountId") != account
            or not isinstance(identity.get("arn"), str)
            or not isinstance(account, str) or _ACCOUNT.fullmatch(account) is None
            or not isinstance(region, str) or _REGION.fullmatch(region) is None):
        return None
    if (not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str) or not record["eventTime"]):
        return None
    secret = request.get("secretId")
    if not isinstance(secret, str):
        return None
    match = _ARN.fullmatch(secret)
    if match:
        if match.group(1) != region or match.group(2) != account:
            return None
        secret_name = match.group(3)
    else:
        secret_name = secret
    if _SECRET.fullmatch(secret_name) is None:
        return None
    return {
        "cloud.provider": "aws",
        "event.source": "secretsmanager.amazonaws.com",
        "event.name": "GetSecretValue",
        "event.outcome": "success",
        "event.id": record.get("eventID"),
        "event.time": record.get("eventTime"),
        "account.id": account,
        "actor.id": identity["arn"],
        "target.id": "sha256:" + hashlib.sha256(secret.encode()).hexdigest()[:24],
        "request.pcs_slurm_secret_read": True,
    }
