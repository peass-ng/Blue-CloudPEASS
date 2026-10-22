"""Accepted AppStream stack updates enabling client transfer channels."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_EGRESS = {"CLIPBOARD_COPY_TO_LOCAL_DEVICE", "FILE_DOWNLOAD", "PRINTING_TO_LOCAL_DEVICE"}
_INGRESS = {"CLIPBOARD_COPY_FROM_LOCAL_DEVICE", "FILE_UPLOAD"}


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _enabled(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    found: dict[str, str] = {}
    for item in value:
        if not isinstance(item, Mapping):
            return set()
        action, permission = item.get("action"), item.get("permission")
        if (not isinstance(action, str) or permission not in {"ENABLED", "DISABLED"}
                or action in found):
            return set()
        found[action] = permission
    return {action for action, permission in found.items() if permission == "ENABLED"}


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "appstream.amazonaws.com"
            or record.get("eventName") != "UpdateStack"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region, event_id, stamp = (record.get(k) for k in
                                        ("recipientAccountId", "awsRegion", "eventID", "eventTime"))
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(event_id, str) or not event_id
            or not isinstance(stamp, str)):
        return None
    try:
        if datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
            return None
    except ValueError:
        return None
    request = _map(record.get("requestParameters"))
    response = _map(_map(record.get("responseElements")).get("stack"))
    name = request.get("name")
    if (not isinstance(name, str) or not _NAME.fullmatch(name)
            or response.get("name") != name):
        return None
    requested = _enabled(request.get("userSettings"))
    confirmed = _enabled(response.get("userSettings"))
    active = requested & confirmed
    if not active & (_EGRESS | _INGRESS):
        return None
    identity = _map(record.get("userIdentity"))
    if (identity.get("type") == "AWSService" or identity.get("invokedBy")
            or identity.get("accountId") != account
            or not isinstance(identity.get("arn"), str)):
        return None
    arn = f"arn:aws:appstream:{region}:{account}:stack/{name}"
    return {
        "cloud.provider": "aws", "event.source": "appstream.amazonaws.com",
        "event.name": "UpdateStack", "event.outcome": "success",
        "event.id": event_id, "event.time": stamp,
        "account.id": account, "actor.id": identity["arn"],
        "target.id": "sha256:" + hashlib.sha256(arn.encode()).hexdigest()[:24],
        "request.appstream_client_egress_enabled": bool(active & _EGRESS),
        "request.appstream_client_ingress_enabled": bool(active & _INGRESS),
    }
