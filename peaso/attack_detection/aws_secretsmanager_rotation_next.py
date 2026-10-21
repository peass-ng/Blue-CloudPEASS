"""Recognize manual secret rotation, cancellation and staged version promotion."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any


_SECRET = re.compile(r"arn:aws:secretsmanager:([a-z0-9-]+):(\d{12}):secret:[A-Za-z0-9/_+=.@-]+\Z")
_LAMBDA = re.compile(r"arn:aws:lambda:([a-z0-9-]+):(\d{12}):function:[A-Za-z0-9_-]+\Z")
_TOKEN = re.compile(r"[A-Za-z0-9-]{32,64}\Z")
_BUILTIN_STAGES = {"AWSCURRENT", "AWSPENDING", "AWSPREVIOUS"}


def _base(record: Mapping[str, Any], names: set[str]) -> tuple[Mapping[str, Any], str, str, str] | None:
    if (record.get("eventSource") != "secretsmanager.amazonaws.com"
            or record.get("eventName") not in names
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    target = request.get("secretId")
    match = _SECRET.fullmatch(target) if isinstance(target, str) else None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if (not match or match.group(1) != region or match.group(2) != account
            or response.get("arn") != target):
        return None
    return request, target, account, region


def _actor(record: Mapping[str, Any]) -> str | None:
    identity = record.get("userIdentity")
    return identity.get("arn") if isinstance(identity, Mapping) and isinstance(identity.get("arn"), str) else None


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result if result.tzinfo else None


def _custom_stage(request: Mapping[str, Any]) -> bool:
    stages = request.get("versionStages")
    return (isinstance(stages, list) and bool(stages)
            and all(isinstance(stage, str) and re.fullmatch(r"[A-Za-z0-9_+=.@-]{1,256}", stage)
                    for stage in stages)
            and any(stage not in _BUILTIN_STAGES for stage in stages)
            and isinstance(request.get("clientRequestToken"), str)
            and _TOKEN.fullmatch(request["clientRequestToken"]) is not None)


def normalize_aws_secretsmanager_rotation(record: Mapping[str, Any]) -> dict[str, Any] | None:
    parsed = _base(record, {"RotateSecret", "CancelRotateSecret", "PutSecretValue"})
    if parsed is None:
        return None
    request, target, account, _ = parsed
    name = record["eventName"]
    manual = name == "RotateSecret" and request.get("rotateImmediately") is True
    cancelled = name == "CancelRotateSecret"
    planted = name == "PutSecretValue" and _custom_stage(request)
    if not (manual or cancelled or planted):
        return None
    result = {
        "cloud.provider": "aws", "event.source": "secretsmanager.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": _actor(record), "target.id": target,
    }
    if manual:
        result["request.secretsmanager_manual_rotation_requested"] = True
    if cancelled:
        result["request.secretsmanager_rotation_cancelled"] = True
    if planted:
        result["request.secretsmanager_custom_stage_version_planted"] = True
    return result


def correlate_aws_secretsmanager_rotation(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rotations = []
    plants = []
    promotions = []
    for record in records:
        parsed = _base(record, {"RotateSecret", "PutSecretValue", "UpdateSecretVersionStage"})
        if parsed is None:
            continue
        request, target, account, region = parsed
        when, actor = _time(record.get("eventTime")), _actor(record)
        if when is None or actor is None:
            continue
        name = record["eventName"]
        if name == "RotateSecret":
            function = request.get("rotationLambdaARN")
            match = _LAMBDA.fullmatch(function) if isinstance(function, str) else None
            if match and match.group(1) == region and match.group(2) == account:
                rotations.append((when, account, target, actor, function, record))
        elif name == "PutSecretValue" and _custom_stage(request):
            plants.append((when, account, target, actor, request["clientRequestToken"], record))
        elif (name == "UpdateSecretVersionStage" and request.get("versionStage") == "AWSCURRENT"
              and isinstance(request.get("moveToVersionId"), str)
              and isinstance(request.get("removeFromVersionId"), str)
              and request["moveToVersionId"] != request["removeFromVersionId"]):
            promotions.append((when, account, target, actor, request["moveToVersionId"], record))
    result = []
    for when, account, target, actor, function, record in rotations:
        if not any(previous_time < when <= previous_time + timedelta(minutes=15)
                   and previous_account == account and previous_target == target
                   and previous_actor == actor and previous_function != function
                   for previous_time, previous_account, previous_target, previous_actor,
                   previous_function, _ in rotations):
            continue
        result.append({
            "cloud.provider": "aws", "event.source": "secretsmanager.amazonaws.com",
            "event.name": "RotateSecret", "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": actor, "target.id": target,
            "request.secretsmanager_rotation_lambda_swapped": True,
        })
    for when, account, target, actor, token, record in promotions:
        if not any(plant_time <= when <= plant_time + timedelta(minutes=15)
                   and plant_account == account and plant_target == target
                   and plant_actor == actor and plant_token == token
                   for plant_time, plant_account, plant_target, plant_actor,
                   plant_token, _ in plants):
            continue
        result.append({
            "cloud.provider": "aws", "event.source": "secretsmanager.amazonaws.com",
            "event.name": "UpdateSecretVersionStage", "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": actor, "target.id": target,
            "request.secretsmanager_custom_stage_promoted": True,
        })
    return result
