"""Normalize a successful IAM role permissions-boundary deletion from CloudTrail."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any
from uuid import UUID

_ACCOUNT = re.compile(r"[0-9]{12}")
_ROLE = re.compile(r"[A-Za-z0-9_+=,.@-]{1,64}")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-\d+")


def normalize_aws_role_boundary_delete(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Report the accepted API write, without inferring a net permission increase."""
    if (not isinstance(record, Mapping)
            or record.get("eventSource") != "iam.amazonaws.com"
            or record.get("eventName") != "DeleteRolePermissionsBoundary"
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
            or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage"))):
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
        "event.source": "iam.amazonaws.com", "event.name": "DeleteRolePermissionsBoundary",
        "event.outcome": "success", "event.id": event_id, "event.time": event_time,
        "account.id": account, "actor.id": actor, "actor.kind": identity["type"],
        "target.id": f"iam-role:{account}:{role}",
        "request.role_name": role, "request.role_boundary_delete_observed": True,
    }
