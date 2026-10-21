"""IVS composition topology and control signals from CloudTrail management calls."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_ID = re.compile(r"[A-Za-z0-9_-]+\Z")
_ROUTES = {
    "CreateEncoderConfiguration": ("IvsEncoderConfigurationCreated", "request.ivs_encoder_configuration_created", False),
    "StartComposition": ("IvsCompositionToChannelStarted", "request.ivs_composition_to_channel_started", False),
    "StopComposition": ("IvsCompositionStopped", "request.ivs_composition_stopped", False),
    "GetComposition": ("IvsCompositionRead", "request.ivs_composition_read", True),
    "ListCompositions": ("IvsCompositionsListed", "request.ivs_compositions_listed", True),
}


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _arn(value: Any, account: str, region: str, kind: str) -> str | None:
    if not isinstance(value, str):
        return None
    prefix = f"arn:aws:ivs:{region}:{account}:{kind}/"
    tail = value[len(prefix):] if value.startswith(prefix) else ""
    return value if _ID.fullmatch(tail) else None


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name, account, region = (record.get(key) for key in
                             ("eventName", "recipientAccountId", "awsRegion"))
    route = _ROUTES.get(name) if isinstance(name, str) else None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (route is None or record.get("eventSource") != "ivs.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not route[2]
            or record.get("errorCode") or record.get("errorMessage")
            or (isinstance(response, Mapping)
                and (response.get("errorCode") or response.get("errorMessage")))
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str)
            or not isinstance(request, Mapping)):
        return []
    try:
        timestamp = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            return []
    except ValueError:
        return []

    synthetic, flag, _ = route
    destination = None
    encoder = None
    composition = None
    if name == "CreateEncoderConfiguration":
        video = _map(request.get("video"))
        item = _map(_map(response).get("encoderConfiguration"))
        target = _arn(item.get("arn"), account, region, "encoder-configuration")
        if (target is None or not isinstance(video.get("width"), int)
                or not isinstance(video.get("height"), int)
                or not isinstance(video.get("bitrate"), int)):
            return []
    elif name == "StartComposition":
        target = _arn(request.get("stageArn"), account, region, "stage")
        destinations = request.get("destinations")
        if (target is None or not isinstance(destinations, list)
                or len(destinations) != 1 or not isinstance(destinations[0], Mapping)):
            return []
        channel = _map(destinations[0].get("channel"))
        destination = _arn(channel.get("channelArn"), account, region, "channel")
        encoder = _arn(channel.get("encoderConfigurationArn"), account, region, "encoder-configuration")
        item = _map(_map(response).get("composition"))
        composition = _arn(item.get("arn"), account, region, "composition")
        actual_destinations = item.get("destinations")
        if (destination is None or encoder is None or composition is None
                or item.get("stageArn") != target
                or not isinstance(actual_destinations, list) or not actual_destinations
                or not any(_map(_map(_map(actual).get("configuration")).get("channel")).get("channelArn") == destination
                           and _map(_map(_map(actual).get("configuration")).get("channel")).get("encoderConfigurationArn") == encoder
                           for actual in actual_destinations)):
            return []
    elif name == "ListCompositions":
        stage = request.get("filterByStageArn")
        target = _arn(stage, account, region, "stage") if stage is not None else account
        if target is None:
            return []
    else:
        target = _arn(request.get("arn"), account, region, "composition")
        if target is None:
            return []

    identity = _map(record.get("userIdentity"))
    finding = {
        "cloud.provider": "aws", "event.source": "ivs.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": target, flag: True,
    }
    if destination:
        finding["destination.id"] = destination
    if encoder:
        finding["encoder.id"] = encoder
    if composition:
        finding["composition.id"] = composition
    return [finding]
