"""Bounded Cloud Control resource creation with a passed CloudFormation role."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
from typing import Any


def normalize_aws_cloudcontrol_role_b441(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "cloudcontrolapi.amazonaws.com"
            or record.get("eventName") != "CreateResource"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    role = request.get("roleArn") or request.get("RoleArn")
    kind = request.get("typeName") or request.get("TypeName")
    account = record.get("recipientAccountId")
    if (not isinstance(account, str) or len(account) != 12 or not account.isdigit()
            or not isinstance(role, str)
            or not role.startswith(f"arn:aws:iam::{account}:role/")
            or kind != "AWS::IAM::User"):
        return None
    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    hash_value = lambda value: "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "cloudcontrolapi.amazonaws.com",
        "event.name": "CreateResource", "event.outcome": "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account,
        "actor.id": hash_value(actor) if isinstance(actor, str) else None,
        "target.id": hash_value(role),
        "request.cloudcontrol_iam_user_with_role": True,
    }
