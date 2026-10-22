"""Safe opt-in CloudTrail envelope for catalog-only API event rules."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any
from urllib.parse import quote, unquote_to_bytes


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_SOURCE = re.compile(r"[a-z0-9-]+\.amazonaws\.com\Z")
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9]{0,127}\Z")
_TYPE = re.compile(r"AWS::[A-Za-z][A-Za-z0-9]*::[A-Za-z][A-Za-z0-9]*\Z")
_ARN = re.compile(r"arn:(aws(?:-[a-z-]+)?):[a-z0-9-]+:([a-z0-9-]*):([0-9]{12}):([^\s]+)\Z")
_ARTIFACT_REPORT_PATH = re.compile(r"report/(?:[A-Za-z0-9_-]+|\*)(?::(?:[0-9]+|\*))?\Z")
_NETWORKMANAGER_ATTACHMENT = re.compile(
    r"arn:aws(?:-[a-z-]+)?:networkmanager::([0-9]{12}):attachment/attachment-[0-9a-f]{8,17}\Z"
)
_UNSCOPED_TYPE = "CloudTrail::UnscopedEvent"


def _networkmanager_attachment_arn(value: Any, account: str) -> str | None:
    if not isinstance(value, str) or len(value) > 2048:
        return None
    if value.startswith("arn:"):
        arn = value
    else:
        try:
            arn = unquote_to_bytes(value).decode("ascii")
        except (UnicodeDecodeError, ValueError):
            return None
        if quote(arn, safe="") != value:
            return None
    match = _NETWORKMANAGER_ATTACHMENT.fullmatch(arn)
    return arn if match is not None and match.group(1) == account else None


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Emit opaque resource or unscoped envelopes; never copy request or response content."""
    source, name = record.get("eventSource"), record.get("eventName")
    category, read_only = record.get("eventCategory"), record.get("readOnly")
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    stamp, event_id = record.get("eventTime"), record.get("eventID")
    resources = record.get("resources")
    console_token = (
        source == "signin.amazonaws.com"
        and name == "GetSigninToken"
        and record.get("eventType") == "AwsConsoleSignIn"
        and category == "Management"
        and read_only is False
        and not resources
        and isinstance(record.get("responseElements"), Mapping)
        and record["responseElements"].get("GetSigninToken") == "Success"
    )
    if (not isinstance(source, str) or not _SOURCE.fullmatch(source)
            or not isinstance(name, str) or not _NAME.fullmatch(name)
            or category not in {"Management", "Data"}
            or (record.get("eventType") != "AwsApiCall" and not console_token)
            or (source == "signin.amazonaws.com" and name == "GetSigninToken" and not console_token)
            or record.get("managementEvent") is not (category == "Management")
            or not isinstance(read_only, bool)
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(stamp, str) or not isinstance(event_id, str) or not event_id
            or (resources is not None and (not isinstance(resources, list) or len(resources) > 100))):
        return []
    try:
        if datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
            return []
    except ValueError:
        return []
    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    if console_token and isinstance(actor, str):
        actor = "sha256:" + hashlib.sha256(actor.encode("utf-8")).hexdigest()[:24]
    if not resources:
        request = record.get("requestParameters")
        attachment_arn = _networkmanager_attachment_arn(
            request.get("resourceArn") if isinstance(request, Mapping) else None, account
        )
        attachment = (
            source == "networkmanager.amazonaws.com"
            and name in {"TagResource", "UntagResource"}
            and category == "Management" and read_only is False
            and attachment_arn is not None
        )
        target_material = attachment_arn if attachment else f"{account}:{region}:{event_id}"
        target = "sha256:" + hashlib.sha256(target_material.encode("utf-8")).hexdigest()[:24]
        return [{
            "cloud.provider": "aws", "event.source": source,
            "event.name": name, "event.category": category,
            "event.read_only": read_only, "event.outcome": "success",
            "resource.type": "AWS::NetworkManager::Attachment" if attachment else _UNSCOPED_TYPE,
            "event.id": event_id,
            "event.time": stamp, "account.id": account,
            "actor.id": actor, "target.id": target,
            "__raw_cloudtrail": True,
        }]
    result = []
    seen = set()
    for item in resources:
        if not isinstance(item, Mapping):
            continue
        kind, arn = item.get("type"), item.get("ARN")
        if (not isinstance(kind, str) or not _TYPE.fullmatch(kind)
                or not isinstance(arn, str) or len(arn) > 2048):
            continue
        match = _ARN.fullmatch(arn)
        if match and match.group(3) == account and match.group(2) in {"", region}:
            resource_path = match.group(4)
        elif source == "artifact.amazonaws.com" and kind == "AWS::Artifact::Report":
            # Artifact reports belong to AWS, so their CloudTrail ARNs have no
            # account component. Keep this exception limited to report paths.
            parts = arn.split(":", 5)
            if (len(parts) != 6 or parts[:3] != ["arn", "aws", "artifact"]
                    or parts[3] != region or parts[4] != ""
                    or not _ARTIFACT_REPORT_PATH.fullmatch(parts[5])):
                continue
            resource_path = parts[5]
        else:
            continue
        key = (kind, arn)
        if key in seen:
            continue
        seen.add(key)
        target = "sha256:" + hashlib.sha256(arn.encode("utf-8")).hexdigest()[:24]
        result.append({
            "cloud.provider": "aws", "event.source": source,
            "event.name": name, "event.category": category,
            "event.read_only": read_only, "event.outcome": "success",
            "resource.type": kind, "event.id": event_id,
            "event.time": stamp, "account.id": account,
            "actor.id": actor, "target.id": target,
            "__raw_cloudtrail": True,
            "__resource_path": resource_path,
            "resource.path_scope_checked": True,
        })
    return result
