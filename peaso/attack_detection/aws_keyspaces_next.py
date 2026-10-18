"""Cache-only candidate for observed other-user Keyspaces credential creation.

The accepted IAM write is evidence of credential creation, not Keyspaces use,
malicious intent, or a net persistence gain. No secret or raw response is emitted.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any
from uuid import UUID

_ACCOUNT = re.compile(r"[0-9]{12}")
_USER = re.compile(r"[A-Za-z0-9_+=,.@-]{1,64}")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-\d+")
_CREDENTIAL_ID = re.compile(r"[A-Za-z0-9_]{20,128}")
_SERVICE = "cassandra.amazonaws.com"


def normalize_keyspaces_other_user_credential(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return flat fields only when request, response, actor and target agree."""
    if (not isinstance(record, Mapping)
            or record.get("eventSource") != "iam.amazonaws.com"
            or record.get("eventName") != "CreateServiceSpecificCredential"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request = record.get("requestParameters")
    response = record.get("responseElements")
    identity = record.get("userIdentity")
    if (not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or not isinstance(identity, Mapping)
            or response.get("errorCode") or response.get("errorMessage")):
        return None
    credential = response.get("serviceSpecificCredential")
    if not isinstance(credential, Mapping):
        return None
    account = record.get("recipientAccountId")
    region = record.get("awsRegion")
    target = request.get("userName")
    service = request.get("serviceName")
    actor = identity.get("arn")
    actor_user = identity.get("userName")
    actor_parts = actor.split(":", 5) if isinstance(actor, str) else []
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(target, str) or not _USER.fullmatch(target)
            or service != _SERVICE
            or identity.get("type") != "IAMUser"
            or identity.get("accountId") != account
            or not isinstance(actor_user, str) or not _USER.fullmatch(actor_user)
            or target == actor_user
            or len(actor_parts) != 6 or actor_parts[0] != "arn"
            or actor_parts[1] not in {"aws", "aws-us-gov", "aws-cn"}
            or actor_parts[2] != "iam" or actor_parts[3] != ""
            or actor_parts[4] != account or not actor_parts[5].startswith("user/")
            or actor_parts[5].rsplit("/", 1)[-1] != actor_user
            or credential.get("serviceName") != service
            or credential.get("userName") != target
            or credential.get("status") != "Active"
            or not isinstance(credential.get("serviceSpecificCredentialId"), str)
            or not _CREDENTIAL_ID.fullmatch(credential["serviceSpecificCredentialId"])):
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
        "event.source": "iam.amazonaws.com",
        "event.name": "CreateServiceSpecificCredential", "event.outcome": "success",
        "event.id": event_id, "event.time": event_time,
        "account.id": account, "actor.id": actor, "actor.kind": "IAMUser",
        "target.id": f"iam-user:{account}:{target}",
        "request.user_name": target, "request.service_name": _SERVICE,
        "request.other_user_keyspaces_credential_created": True,
    }
