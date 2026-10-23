"""Bounded Lambda EFS mount and subsequent code update signals."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_FUNCTION_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_MOUNT_PATH = re.compile(r"/mnt/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*\Z")
_ATTACH = "UpdateFunctionConfiguration20150331v2"
_CODE = "UpdateFunctionCode20150331v2"


def _function_arn(value: Any, account: str, region: str) -> str | None:
    prefix = f"arn:aws:lambda:{region}:{account}:function:"
    if isinstance(value, str) and value.startswith(prefix):
        name = value[len(prefix):]
    else:
        name = value
    if not isinstance(name, str) or _FUNCTION_NAME.fullmatch(name) is None:
        return None
    return prefix + name


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else None
    except ValueError:
        return None


def _event(record: Mapping[str, Any]) -> tuple[datetime, str, str, str, str, str, bool, bool] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "lambda.amazonaws.com"
            or name not in {_ATTACH, _CODE}
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request, response = (record.get(key) for key in
                                   ("userIdentity", "requestParameters", "responseElements"))
    event_id = record.get("eventID")
    when = _time(record.get("eventTime"))
    if (not isinstance(account, str) or _ACCOUNT.fullmatch(account) is None
            or not isinstance(region, str) or _REGION.fullmatch(region) is None
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or identity.get("type") == "AWSService"
            or not isinstance(identity.get("arn"), str) or not identity["arn"]
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or not isinstance(event_id, str) or not event_id or when is None):
        return None
    function = _function_arn(request.get("functionName"), account, region)
    if function is None or response.get("functionArn") != function:
        return None
    if name == _CODE and request.get("dryRun") is True:
        return None
    attached = detached = False
    if name == _ATTACH:
        configs = request.get("fileSystemConfigs")
        if not isinstance(configs, list):
            return None
        if configs == []:
            detached = True
        elif len(configs) == 1 and isinstance(configs[0], Mapping):
            item = configs[0]
            ap_arn = item.get("arn")
            path = item.get("localMountPath")
            prefix = f"arn:aws:elasticfilesystem:{region}:{account}:access-point/"
            if (isinstance(ap_arn, str) and ap_arn.startswith(prefix)
                    and re.fullmatch(r"fsap-[0-9a-f]{8,17}", ap_arn[len(prefix):])
                    and isinstance(path, str) and _MOUNT_PATH.fullmatch(path)):
                confirmed = response.get("fileSystemConfigs")
                attached = (confirmed is None or
                            isinstance(confirmed, list) and len(confirmed) == 1
                            and isinstance(confirmed[0], Mapping)
                            and confirmed[0].get("arn") == ap_arn
                            and confirmed[0].get("localMountPath") == path)
        if not attached and not detached:
            return None
    return when, name, account, region, identity["arn"], function, attached, detached


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Report accepted EFS attachment configuration without exposing its ARN."""
    event = _event(record)
    if event is None or not event[6]:
        return None
    _, name, account, _, actor, function, _, _ = event
    return {
        "cloud.provider": "aws", "event.source": "lambda.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": actor,
        "target.id": "sha256:" + hashlib.sha256(function.encode()).hexdigest()[:24],
        "request.lambda_efs_access_point_configured": True,
    }


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Flag a code update shortly after an accepted EFS mount on one function."""
    ordered = [(event, record) for record in records
               if (event := _event(record)) is not None]
    ordered.sort(key=lambda item: item[0][0])
    prior: dict[tuple[str, str, str], tuple[datetime, str]] = {}
    seen: set[str] = set()
    findings = []
    for event, record in ordered:
        when, name, account, _, actor, function, attached, detached = event
        key = account, actor, function
        if attached:
            prior[key] = when, record["eventID"]
        elif detached:
            prior.pop(key, None)
        elif name == _CODE:
            parent = prior.get(key)
            if (parent is None or not timedelta(0) <= when - parent[0] <= timedelta(minutes=15)
                    or record["eventID"] in seen):
                continue
            seen.add(record["eventID"])
            findings.append({
                "cloud.provider": "aws", "event.source": "lambda.amazonaws.com",
                "event.name": name, "event.outcome": "success",
                "event.id": record["eventID"], "event.time": record["eventTime"],
                "account.id": account, "actor.id": actor,
                "target.id": "sha256:" + hashlib.sha256(function.encode()).hexdigest()[:24],
                "request.lambda_efs_mount_followed_by_code_update": True,
                "correlation_evidence": {"earlier_event_id": parent[1]},
            })
    return findings
