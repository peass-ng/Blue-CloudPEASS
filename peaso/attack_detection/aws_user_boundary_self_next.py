"""Evidence for an IAM user deleting its own permissions boundary."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any
from uuid import UUID


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_USER = re.compile(r"[A-Za-z0-9_+=,.@-]{1,64}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+\Z")


def normalize_aws_self_user_boundary_delete(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Report the accepted self-boundary deletion, never a net privilege claim."""
    if (not isinstance(record, Mapping)
            or record.get("eventSource") != "iam.amazonaws.com"
            or record.get("eventName") != "DeleteUserPermissionsBoundary"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
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
    user = request.get("userName")
    actor_arn = identity.get("arn")
    parts = actor_arn.split(":", 5) if isinstance(actor_arn, str) else []
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(user, str) or not _USER.fullmatch(user)
            or identity.get("type") != "IAMUser" or identity.get("userName") != user
            or identity.get("accountId") != account
            or len(parts) != 6 or parts[0] != "arn" or parts[1] not in {"aws", "aws-us-gov", "aws-cn"}
            or parts[2] != "iam" or parts[3] != "" or parts[4] != account
            or not parts[5].startswith("user/") or parts[5].rsplit("/", 1)[-1] != user):
        return None
    event_id = record.get("eventID")
    event_time = record.get("eventTime")
    try:
        UUID(event_id)
        parsed = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
    except (TypeError, AttributeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return None
    return {
        "cloud.provider": "aws", "cloud.region": region,
        "event.source": "iam.amazonaws.com", "event.name": "DeleteUserPermissionsBoundary",
        "event.outcome": "success", "event.id": event_id, "event.time": event_time,
        "account.id": account, "actor.id": actor_arn, "actor.kind": "IAMUser",
        "target.id": actor_arn, "request.user_name": user,
        "request.self_user_boundary_delete_observed": True,
    }
