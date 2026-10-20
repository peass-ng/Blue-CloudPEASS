"""Normalize Chime SDK AppInstance administrator promotions."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_chime_admin(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "chime.amazonaws.com" or record.get("eventName") != "CreateAppInstanceAdmin":
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    account = record.get("recipientAccountId")
    request = record.get("requestParameters")
    if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account) or not isinstance(request, Mapping):
        return None
    app = request.get("appInstanceArn")
    admin = request.get("appInstanceAdminArn")
    if not isinstance(app, str) or not re.fullmatch(
            rf"arn:aws:chime:[a-z0-9-]+:{re.escape(account)}:app-instance/[a-f0-9-]+", app):
        return None
    if not isinstance(admin, str) or not re.fullmatch(
            re.escape(app) + r"/(?:user|bot)/[A-Za-z0-9:_\-.@]+", admin):
        return None
    response = record.get("responseElements")
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": record.get("eventSource"),
        "event.name": record.get("eventName"),
        "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": admin,
        "request.chime_app_instance_admin_promoted": not failed,
    }
