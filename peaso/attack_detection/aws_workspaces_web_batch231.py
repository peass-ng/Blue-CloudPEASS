"""Bounded WorkSpaces Secure Browser configuration change signals."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_RESOURCE = re.compile(r"[A-Za-z0-9-]{1,128}\Z")
_TRANSFER_FIELDS = (
    "copyAllowed", "pasteAllowed", "downloadAllowed", "uploadAllowed", "printAllowed",
)


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Confirm accepted settings, retaining neither policies nor ARNs in output."""
    name = record.get("eventName")
    if (record.get("eventSource") != "workspaces-web.amazonaws.com"
            or name not in {"UpdateDataProtectionSettings", "UpdateUserSettings"}
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)):
        return None
    prefix, arn_key, response_key = (
        ("dataProtectionSettings", "dataProtectionSettingsArn", "dataProtectionSettings")
        if name == "UpdateDataProtectionSettings" else
        ("userSettings", "userSettingsArn", "userSettings")
    )
    arn = request.get(arn_key)
    returned = response.get(response_key)
    expected_prefix = f"arn:aws:workspaces-web:{region}:{account}:{prefix}/"
    if (not isinstance(arn, str) or not arn.startswith(expected_prefix)
            or not _RESOURCE.fullmatch(arn[len(expected_prefix):])
            or not isinstance(returned, Mapping) or returned.get(arn_key) != arn):
        return None
    if name == "UpdateDataProtectionSettings":
        sent_config = request.get("inlineRedactionConfiguration")
        returned_config = returned.get("inlineRedactionConfiguration")
        confirmed = (
            isinstance(sent_config, Mapping) and isinstance(returned_config, Mapping)
            and sent_config.get("inlineRedactionPatterns") == []
            and returned_config.get("inlineRedactionPatterns") == []
        )
        field = "request.workspaces_web_redaction_patterns_empty"
    else:
        confirmed = any(
            request.get(key) == "Enabled" and returned.get(key) == "Enabled"
            for key in _TRANSFER_FIELDS
        )
        field = "request.workspaces_web_transfer_enabled"
    if not confirmed:
        return None
    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    return {
        "cloud.provider": "aws", "event.source": "workspaces-web.amazonaws.com",
        "event.name": name, "event.category": "Management",
        "event.outcome": "success", "event.read_only": False,
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": actor,
        "target.id": "sha256:" + hashlib.sha256(arn.encode()).hexdigest()[:24],
        field: True,
    }
