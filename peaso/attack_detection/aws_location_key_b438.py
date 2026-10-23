"""Amazon Location no-expiry API key creation from CloudTrail management events."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
from typing import Any


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def normalize_aws_location_key_b438(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "geo.amazonaws.com" or record.get("eventName") != "CreateKey":
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    response = record.get("responseElements")
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")))
    name = request.get("KeyName")
    restrictions = request.get("Restrictions")
    restrictions = restrictions if isinstance(restrictions, Mapping) else {}
    actions = restrictions.get("AllowActions")
    resources = restrictions.get("AllowResources")
    delegated = (isinstance(actions, list) and bool(actions)
                 and all(isinstance(action, str) and bool(action) for action in actions)
                 and isinstance(resources, list) and bool(resources)
                 and all(isinstance(resource, str) and bool(resource) for resource in resources))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "geo.amazonaws.com",
        "event.name": "CreateKey", "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId"),
        "actor.id": _hash(identity["arn"]) if isinstance(identity.get("arn"), str) else None,
        "target.id": _hash(name) if isinstance(name, str) and name else None,
        "request.location_nonexpiring_bearer_created": bool(
            not failed and isinstance(name, str) and bool(name)
            and request.get("NoExpiry") is True and delegated
        ),
    }
