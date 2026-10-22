"""Recognize accepted Studio lifecycle code storage and space attachment."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}\Z")
_DOMAIN = re.compile(r"d-[a-z0-9]{1,32}\Z")


def normalize_aws_sagemaker_space_lcc(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Emit fixed lifecycle flags with hashed targets, never script content."""
    action = record.get("eventName")
    if (record.get("eventSource") != "sagemaker.amazonaws.com"
            or action not in {"CreateStudioLifecycleConfig", "UpdateSpace"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)):
        return None
    stamp, event_id = record.get("eventTime"), record.get("eventID")
    if not isinstance(stamp, str) or not isinstance(event_id, str) or not event_id:
        return None
    try:
        if datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
            return None
    except ValueError:
        return None
    identity, request, response = (record.get("userIdentity"), record.get("requestParameters"),
                                   record.get("responseElements"))
    if (not isinstance(identity, Mapping) or identity.get("accountId") != account
            or not isinstance(identity.get("arn"), str)
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or response.get("errorCode") or response.get("errorMessage")):
        return None
    created = attached = False
    target: str | None = None
    if action == "CreateStudioLifecycleConfig":
        name = request.get("studioLifecycleConfigName")
        content = request.get("studioLifecycleConfigContent")
        if (not isinstance(name, str) or not _NAME.fullmatch(name)
                or request.get("studioLifecycleConfigAppType") not in {"JupyterLab", "CodeEditor"}
                or not isinstance(content, str) or not content or len(content) > 16384):
            return None
        target = f"arn:aws:sagemaker:{region}:{account}:studio-lifecycle-config/{name}"
        if response.get("studioLifecycleConfigArn") != target:
            return None
        created = True
    else:
        domain, space = request.get("domainId"), request.get("spaceName")
        if (not isinstance(domain, str) or not _DOMAIN.fullmatch(domain)
                or not isinstance(space, str) or not _NAME.fullmatch(space)):
            return None
        settings = request.get("spaceSettings")
        if not isinstance(settings, Mapping):
            return None
        attached_arns = []
        for app_key in ("jupyterLabAppSettings", "codeEditorAppSettings"):
            app_settings = settings.get(app_key)
            spec = app_settings.get("defaultResourceSpec") if isinstance(app_settings, Mapping) else None
            arn = spec.get("lifecycleConfigArn") if isinstance(spec, Mapping) else None
            if arn is not None:
                attached_arns.append(arn)
        prefix = f"arn:aws:sagemaker:{region}:{account}:studio-lifecycle-config/"
        if (len(attached_arns) != 1 or not isinstance(attached_arns[0], str)
                or not attached_arns[0].startswith(prefix)
                or not _NAME.fullmatch(attached_arns[0][len(prefix):])):
            return None
        target = f"arn:aws:sagemaker:{region}:{account}:space/{domain}/{space}"
        if response.get("spaceArn") != target:
            return None
        attached = True
    return {
        "cloud.provider": "aws", "event.source": "sagemaker.amazonaws.com",
        "event.name": action, "event.outcome": "success", "event.id": event_id,
        "event.time": stamp, "account.id": account, "actor.id": identity["arn"],
        "target.id": "sha256:" + hashlib.sha256(target.encode("utf-8")).hexdigest()[:24],
        "request.sagemaker_studio_lcc_code_created": created,
        "request.sagemaker_space_lcc_attached": attached,
    }
