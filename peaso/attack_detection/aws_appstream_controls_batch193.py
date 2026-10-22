"""Bounded AppStream entitlement and client transfer control signals."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_ATTRIBUTES = {"roles", "department", "organization", "groups", "title", "costCenter", "userType"}
_TRANSFER = {"CLIPBOARD_COPY_FROM_LOCAL_DEVICE", "CLIPBOARD_COPY_TO_LOCAL_DEVICE",
             "FILE_UPLOAD", "FILE_DOWNLOAD", "PRINTING_TO_LOCAL_DEVICE"}
_NAMES = {"CreateEntitlement", "UpdateEntitlement", "UpdateStack"}


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Emit only accepted, precise settings; never surface SAML tags or stack names."""
    name = record.get("eventName")
    if (record.get("eventSource") != "appstream.amazonaws.com" or name not in _NAMES
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return []
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    event_id, stamp = record.get("eventID"), record.get("eventTime")
    request, identity = record.get("requestParameters"), record.get("userIdentity")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(event_id, str) or not 0 < len(event_id) <= 128
            or not isinstance(stamp, str) or not isinstance(request, Mapping)
            or not isinstance(identity, Mapping) or identity.get("invokedBy")
            or identity.get("type") == "AWSService"):
        return []
    try:
        if datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
            return []
    except ValueError:
        return []
    stack = request.get("stackName") if name != "UpdateStack" else request.get("name")
    if not isinstance(stack, str) or not _NAME.fullmatch(stack):
        return []
    flags: dict[str, bool] = {}
    target = stack
    if name in {"CreateEntitlement", "UpdateEntitlement"}:
        entitlement, attrs = request.get("name"), request.get("attributes")
        if (not isinstance(entitlement, str) or not _NAME.fullmatch(entitlement)
                or not isinstance(attrs, list) or not 1 <= len(attrs) <= 20
                or any(not isinstance(item, Mapping)
                       or item.get("name") not in _ATTRIBUTES
                       or not isinstance(item.get("value"), str)
                       or not 0 < len(item["value"]) <= 256
                       for item in attrs)):
            return []
        target += ":" + entitlement
        if request.get("appVisibility") == "ALL":
            flags["request.appstream_entitlement_all_apps"] = True
    else:
        settings = request.get("userSettings")
        if settings is not None:
            if (not isinstance(settings, list) or not 1 <= len(settings) <= 20
                    or any(not isinstance(item, Mapping) for item in settings)):
                return []
            if any(item.get("action") in _TRANSFER and item.get("permission") == "ENABLED"
                   for item in settings):
                flags["request.appstream_transfer_channel_enabled"] = True
        agent = request.get("agentAccessConfig")
        if agent is not None:
            if not isinstance(agent, Mapping):
                return []
            actions = agent.get("settings")
            if actions is not None:
                if (not isinstance(actions, list) or not 1 <= len(actions) <= 20
                        or any(not isinstance(item, Mapping) for item in actions)):
                    return []
                if any(item.get("agentAction") == "COMPUTER_INPUT"
                       and item.get("permission") == "ENABLED" for item in actions):
                    flags["request.appstream_agent_input_enabled"] = True
    if not flags:
        return []
    return [{
        "cloud.provider": "aws", "event.source": "appstream.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": event_id, "event.time": stamp, "account.id": account,
        "actor.id": identity.get("arn"),
        "target.id": "sha256:" + hashlib.sha256(
            f"{account}:{region}:{target}".encode()).hexdigest()[:24],
        **flags,
    }]
