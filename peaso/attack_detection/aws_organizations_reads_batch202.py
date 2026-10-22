"""Normalize Organizations list events whose resources contain only ARNPrefix."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_TYPES = {
    "ListRoots": "AWS::Organizations::Root",
    "ListAccounts": "AWS::Organizations::Account",
    "ListDelegatedAdministrators": "AWS::Organizations::Account",
    "ListPolicies": "AWS::Organizations::Policy",
}


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "organizations.amazonaws.com"
            or name not in _TYPES or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not True
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, resources = record.get("recipientAccountId"), record.get("resources")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(resources, list) or len(resources) != 1
            or not isinstance(resources[0], Mapping)
            or resources[0].get("type") != _TYPES[name]
            or resources[0].get("accountId") != account
            or not isinstance(resources[0].get("ARNPrefix"), str)
            or not resources[0]["ARNPrefix"].startswith(f"arn:aws:organizations::{account}:")
            or not isinstance(record.get("eventID"), str)
            or not record["eventID"]):
        return None
    request = record.get("requestParameters")
    if (name == "ListPolicies" and
            (not isinstance(request, Mapping) or request.get("filter") != "SERVICE_CONTROL_POLICY")):
        return None
    identity = record.get("userIdentity")
    if (not isinstance(identity, Mapping) or identity.get("type") == "AWSService"
            or identity.get("invokedBy") or identity.get("accountId") != account):
        return None
    target = "sha256:" + hashlib.sha256(
        f"{account}:{record['eventID']}".encode()
    ).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "organizations.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": target,
        "request.organizations_scope_listed": True,
    }
