"""AppStream user pool foothold controls from management events."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_NAMES = {"CreateUser", "BatchAssociateUserStack", "EnableUser"}


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "appstream.amazonaws.com" or name not in _NAMES
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, request = record.get("recipientAccountId"), record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(request, Mapping)
            or not isinstance(record.get("eventID"), str)):
        return None
    identity = record.get("userIdentity")
    if (not isinstance(identity, Mapping) or identity.get("type") == "AWSService"
            or identity.get("invokedBy") or identity.get("accountId") != account):
        return None
    response = record.get("responseElements")
    flags = {
        "request.appstream_userpool_suppressed_create": False,
        "request.appstream_userpool_stack_associated": False,
        "request.appstream_userpool_user_enabled": False,
    }
    target = "sha256:" + hashlib.sha256(f"{account}:{record['eventID']}".encode()).hexdigest()[:24]
    if name == "CreateUser":
        flags["request.appstream_userpool_suppressed_create"] = (
            request.get("authenticationType") == "USERPOOL"
            and request.get("messageAction") == "SUPPRESS"
        )
    elif name == "EnableUser":
        flags["request.appstream_userpool_user_enabled"] = request.get("authenticationType") == "USERPOOL"
    else:
        associations = request.get("userStackAssociations")
        if (isinstance(associations, list) and associations
                and isinstance(response, Mapping) and response.get("errors") == []):
            valid = [a for a in associations if isinstance(a, Mapping)
                     and a.get("authenticationType") == "USERPOOL"
                     and isinstance(a.get("stackName"), str) and a["stackName"]]
            if valid:
                flags["request.appstream_userpool_stack_associated"] = True
                target = "sha256:" + hashlib.sha256(
                    f"{account}:{','.join(sorted(a['stackName'] for a in valid))}".encode()
                ).hexdigest()[:24]
    if not any(flags.values()):
        return None
    return {
        "cloud.provider": "aws", "event.source": "appstream.amazonaws.com",
        "event.name": name, "event.outcome": "success", "event.id": record["eventID"],
        "event.time": record.get("eventTime"), "account.id": account,
        "actor.id": identity.get("arn"), "target.id": target, **flags,
    }
