"""Normalize an unconditional wildcard IAM role trust-policy write."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any
from urllib.parse import unquote
from uuid import UUID

_ACCOUNT = re.compile(r"[0-9]{12}")
_ROLE = re.compile(r"[A-Za-z0-9_+=,.@-]{1,64}")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-\d+")


def _unconditional_wildcard_aws_trust(value: Any) -> bool:
    if isinstance(value, str):
        try:
            value = json.loads(unquote(value))
        except (TypeError, ValueError):
            return False
    if not isinstance(value, Mapping):
        return False
    statements = value.get("Statement")
    if isinstance(statements, Mapping):
        statements = [statements]
    if not isinstance(statements, list) or not statements or any(not isinstance(item, Mapping) for item in statements):
        return False
    if any(item.get("Effect") == "Deny" or "NotPrincipal" in item or "NotAction" in item for item in statements):
        return False
    wildcard = False
    for item in statements:
        if item.get("Effect") != "Allow":
            return False
        principal = item.get("Principal")
        aws = principal.get("AWS") if isinstance(principal, Mapping) else None
        aws_values = aws if isinstance(aws, list) else [aws]
        actions = item.get("Action")
        actions = actions if isinstance(actions, list) else [actions]
        if "*" in aws_values and "sts:AssumeRole" in actions:
            # Any Condition (even {}) makes the proof ambiguous. A Deny elsewhere
            # in the document is also rejected above because it may narrow trust.
            if "Condition" in item or set(item) - {"Sid", "Effect", "Principal", "Action"}:
                return False
            wildcard = True
    return wildcard


def normalize_aws_wildcard_role_trust(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Report the accepted trust write; do not infer assumption or effective access."""
    if (not isinstance(record, Mapping)
            or record.get("eventSource") != "iam.amazonaws.com"
            or record.get("eventName") != "UpdateAssumeRolePolicy"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")
            or "responseElements" not in record):
        return None
    request = record.get("requestParameters")
    identity = record.get("userIdentity")
    response = record.get("responseElements")
    if (not isinstance(request, Mapping) or not isinstance(identity, Mapping)
            or response is not None and not isinstance(response, Mapping)
            or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage"))
            or not _unconditional_wildcard_aws_trust(request.get("policyDocument"))):
        return None
    account = record.get("recipientAccountId")
    region = record.get("awsRegion")
    role = request.get("roleName")
    actor = identity.get("arn")
    actor_parts = actor.split(":", 5) if isinstance(actor, str) else []
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(role, str) or not _ROLE.fullmatch(role)
            or len(actor_parts) != 6 or actor_parts[0] != "arn"
            or actor_parts[1] not in {"aws", "aws-us-gov", "aws-cn"}
            or actor_parts[2] not in {"iam", "sts"} or actor_parts[3] != ""
            or actor_parts[4] != account or not actor_parts[5]
            or identity.get("accountId") != account
            or not isinstance(identity.get("type"), str) or not identity["type"]):
        return None
    event_id = record.get("eventID")
    event_time = record.get("eventTime")
    try:
        UUID(event_id)
        parsed_time = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
    except (TypeError, AttributeError, ValueError):
        return None
    if parsed_time.tzinfo is None:
        return None
    return {
        "cloud.provider": "aws", "cloud.region": region,
        "event.source": "iam.amazonaws.com", "event.name": "UpdateAssumeRolePolicy",
        "event.outcome": "success", "event.id": event_id, "event.time": event_time,
        "account.id": account, "actor.id": actor, "actor.kind": identity["type"],
        "target.id": f"iam-role:{account}:{role}",
        "request.role_name": role, "request.unconditional_wildcard_trust": True,
    }
