"""Bounded CloudTrail signal for an Identity Store group membership addition."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
from typing import Any


def _field(value: Mapping[str, Any], lower: str, upper: str) -> Any:
    return value.get(lower, value.get(upper))


def _id(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 128


def normalize_aws_identitystore_membership(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "identitystore.amazonaws.com"
            or record.get("eventName") != "CreateGroupMembership"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account = record.get("recipientAccountId")
    if not isinstance(account, str) or len(account) != 12 or not account.isdigit():
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    store = _field(request, "identityStoreId", "IdentityStoreId")
    group = _field(request, "groupId", "GroupId")
    member = _field(request, "memberId", "MemberId")
    user = _field(member, "userId", "UserId") if isinstance(member, Mapping) else None
    if not all(_id(value) for value in (store, group, user)):
        return None
    response = record.get("responseElements")
    if isinstance(response, Mapping):
        if response.get("errorCode") or response.get("errorMessage"):
            return None
        response_store = _field(response, "identityStoreId", "IdentityStoreId")
        if response_store is not None and response_store != store:
            return None
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    target = "sha256:" + hashlib.sha256(
        f"{account}:{store}:{group}:{user}".encode("utf-8")
    ).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "identitystore.amazonaws.com",
        "event.name": "CreateGroupMembership", "event.outcome": "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": target, "request.identitystore_group_membership_created": True,
    }
