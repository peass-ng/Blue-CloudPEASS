"""Project IAM policy-removal management events to accepted-call signals.

This reports accepted API writes only. It never infers that access expanded,
that a removed policy contained a Deny, or that a principal used new access.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any


EVENT_TARGETS = {
    "DeleteGroupPolicy": ("groupName", "policyName"),
    "DeleteRolePolicy": ("roleName", "policyName"),
    "DeleteUserPolicy": ("userName", "policyName"),
    "DeletePolicyVersion": ("policyArn", "versionId"),
    "DetachGroupPolicy": ("groupName", "policyArn"),
    "DetachRolePolicy": ("roleName", "policyArn"),
    "DetachUserPolicy": ("userName", "policyArn"),
    "DeletePolicy": ("policyArn",),
}
NAME = re.compile(r"[\w+=,.@-]{1,128}", re.ASCII)
POLICY_ARN = re.compile(r"arn:aws(?:-[a-z]+)?:iam::(?:\d{12}|aws):policy/.+")
VERSION = re.compile(r"v[1-9][0-9]*")


def get(mapping: Mapping[str, Any], key: str) -> Any:
    wanted = "".join(c for c in key.lower() if c.isalnum())
    for actual, value in mapping.items():
        if isinstance(actual, str) and "".join(c for c in actual.lower() if c.isalnum()) == wanted:
            return value
    return None


def normalize(event: Mapping[str, Any]) -> dict[str, Any] | None:
    action = event.get("eventName")
    if (action not in EVENT_TARGETS or event.get("eventSource") != "iam.amazonaws.com"
            or event.get("eventCategory") != "Management"
            or event.get("eventType") != "AwsApiCall"
            or event.get("managementEvent") is not True
            or event.get("awsRegion") != "us-east-1"):
        return None
    account = event.get("recipientAccountId")
    if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account):
        return None
    request = event.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    fields: dict[str, str] = {}
    for key in EVENT_TARGETS[action]:
        value = get(request, key)
        if not isinstance(value, str):
            return None
        if key == "policyArn":
            if (POLICY_ARN.fullmatch(value) is None
                    or not (value.startswith(f"arn:aws:iam::{account}:policy/")
                            or value.startswith("arn:aws:iam::aws:policy/"))):
                return None
            if action in {"DeletePolicy", "DeletePolicyVersion"} and value.startswith("arn:aws:iam::aws:policy/"):
                return None
        elif key == "versionId":
            if VERSION.fullmatch(value) is None:
                return None
        elif NAME.fullmatch(value) is None:
            return None
        fields[key] = value
    success = not (event.get("errorCode") or event.get("errorMessage"))
    target_kind = ("group" if "groupName" in fields else "role" if "roleName" in fields
                   else "user" if "userName" in fields else "policy")
    target = fields.get(f"{target_kind}Name") or fields.get("policyArn")
    identity = event.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    return {
        "cloud.provider": "aws",
        "event.source": "iam.amazonaws.com",
        "event.name": action,
        "event.outcome": "success" if success else "failure",
        "event.id": event.get("eventID"),
        "event.time": event.get("eventTime"),
        "account.id": account,
        "cloud.region": "us-east-1",
        "actor.id": actor if isinstance(actor, str) else None,
        "target.type": target_kind,
        "target.id": target,
        "request.policy_arn": fields.get("policyArn"),
        "request.policy_name": fields.get("policyName"),
        "request.version_id": fields.get("versionId"),
        "request.iam_policy_removal_observed": success,
        "request.iam_policy_removal_action": action,
    }
