"""Recognize accepted EMR Serverless custom-image application updates."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_APP_ID = re.compile(r"[0-9a-z]{1,64}\Z")
_IMAGE = re.compile(
    r"([0-9]{12})\.dkr\.ecr\.([a-z]{2}(?:-[a-z]+)+-[0-9])\.amazonaws\.com(?:\.cn)?/"
    r"[a-z0-9_./-]+(?::[A-Za-z0-9_.-]+|@sha256:[0-9a-f]{64})\Z"
)


def _uri(value: Any, account: str, region: str) -> str | None:
    match = _IMAGE.fullmatch(value) if isinstance(value, str) and len(value) <= 2048 else None
    return value if match and match.group(1) == account and match.group(2) == region else None


def _images(request: Mapping[str, Any], account: str, region: str) -> dict[str, str] | None:
    top = request.get("imageConfiguration")
    workers = request.get("workerTypeSpecifications")
    if top is not None and workers is not None:
        return None
    if isinstance(top, Mapping):
        image = _uri(top.get("imageUri"), account, region)
        return {"application": image} if image else None
    if not isinstance(workers, Mapping) or not workers or len(workers) > 4:
        return None
    result = {}
    for worker, config in workers.items():
        if worker not in {"Driver", "Executor", "HiveDriver", "TezTask"} or not isinstance(config, Mapping):
            return None
        image_config = config.get("imageConfiguration")
        image = (_uri(image_config.get("imageUri"), account, region)
                 if isinstance(image_config, Mapping) else None)
        if image is None:
            return None
        result[worker] = image
    return result


def normalize_aws_emr_custom_image(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Emit a fixed request flag and hashed app ID; never copy image details."""
    if (record.get("eventSource") != "emr-serverless.amazonaws.com"
            or record.get("eventName") != "UpdateApplication"
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
    app_id = request.get("applicationId")
    images = _images(request, account, region)
    if not isinstance(app_id, str) or not _APP_ID.fullmatch(app_id) or not images:
        return None
    app = response.get("application")
    if not isinstance(app, Mapping) or app.get("applicationId") != app_id:
        return None
    arn = app.get("arn")
    expected = {f"arn:{partition}:emr-serverless:{region}:{account}:/applications/{app_id}"
                for partition in ("aws", "aws-us-gov", "aws-cn")}
    if arn not in expected or app.get("type") not in {"Spark", "Hive"}:
        return None
    if "application" in images:
        config = app.get("imageConfiguration")
        if not isinstance(config, Mapping) or config.get("imageUri") != images["application"]:
            return None
    else:
        configurations = app.get("workerTypeSpecifications")
        if not isinstance(configurations, Mapping):
            return None
        for worker, image in images.items():
            config = configurations.get(worker)
            image_config = config.get("imageConfiguration") if isinstance(config, Mapping) else None
            if not isinstance(image_config, Mapping) or image_config.get("imageUri") != image:
                return None
    return {
        "cloud.provider": "aws", "event.source": "emr-serverless.amazonaws.com",
        "event.name": "UpdateApplication", "event.outcome": "success",
        "event.id": event_id, "event.time": stamp, "account.id": account,
        "actor.id": identity["arn"],
        "target.id": "sha256:" + hashlib.sha256(arn.encode("utf-8")).hexdigest()[:24],
        "request.emr_custom_image_update_requested": True,
    }
