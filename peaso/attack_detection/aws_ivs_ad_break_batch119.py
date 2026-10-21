"""IVS server-side ad insertion and its MediaTailor configuration signals."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any
from urllib.parse import urlsplit

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_ID = re.compile(r"[A-Za-z0-9_-]+\Z")
_ROUTES = {
    ("mediatailor.amazonaws.com", "PutPlaybackConfiguration"): ("MediaTailorPlaybackConfigurationCreated", "request.mediatailor_playback_configuration_created", False),
    ("mediatailor.amazonaws.com", "GetPlaybackConfiguration"): ("MediaTailorPlaybackConfigurationRead", "request.mediatailor_playback_configuration_read", True),
    ("ivs.amazonaws.com", "CreateAdConfiguration"): ("IvsAdConfigurationCreated", "request.ivs_ad_configuration_created", False),
    ("ivs.amazonaws.com", "GetAdConfiguration"): ("IvsAdConfigurationRead", "request.ivs_ad_configuration_read", True),
    ("ivs.amazonaws.com", "ListAdConfigurations"): ("IvsAdConfigurationsListed", "request.ivs_ad_configurations_listed", True),
    ("ivs.amazonaws.com", "UpdateChannel"): ("IvsChannelAdConfigurationAssigned", "request.ivs_channel_ad_configuration_assigned", False),
    ("ivs.amazonaws.com", "InsertAdBreak"): ("IvsAdBreakInserted", "request.ivs_ad_break_inserted", False),
}


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _arn(value: Any, service: str, region: str, account: str, kind: str) -> str | None:
    if not isinstance(value, str):
        return None
    prefix = f"arn:aws:{service}:{region}:{account}:{kind}/"
    tail = value[len(prefix):] if value.startswith(prefix) else ""
    return value if _ID.fullmatch(tail) else None


def _url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parts = urlsplit(value)
        return parts.scheme in ("http", "https") and bool(parts.hostname)
    except ValueError:
        return False


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    source, name, account, region = (record.get(key) for key in
                                     ("eventSource", "eventName", "recipientAccountId", "awsRegion"))
    route = _ROUTES.get((source, name)) if isinstance(source, str) and isinstance(name, str) else None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (route is None or record.get("eventCategory") != "Management"
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

    result = _mapping(response)
    target = None
    extra: dict[str, Any] = {}
    if name == "PutPlaybackConfiguration":
        config_name = request.get("Name")
        ads_url, source_url = request.get("AdDecisionServerUrl"), request.get("VideoContentSourceUrl")
        if (not isinstance(config_name, str) or not _NAME.fullmatch(config_name)
                or not _url(ads_url) or not _url(source_url)
                or request.get("InsertionMode") not in ("PLAYER_SELECT", "STITCHED_ONLY")
                or result.get("Name") != config_name):
            return []
        target = _arn(result.get("PlaybackConfigurationArn"), "mediatailor", region, account, "playbackConfiguration")
        if target is None or target.rsplit("/", 1)[-1] != config_name:
            return []
        extra["ad.insertion_mode"] = request["InsertionMode"]
    elif name == "GetPlaybackConfiguration":
        config_name = request.get("Name")
        if not isinstance(config_name, str) or not _NAME.fullmatch(config_name):
            return []
        target = f"arn:aws:mediatailor:{region}:{account}:playbackConfiguration/{config_name}"
    elif name == "CreateAdConfiguration":
        config_name = request.get("name")
        configurations = request.get("mediaTailorPlaybackConfigurations")
        if (not isinstance(config_name, str) or not _NAME.fullmatch(config_name)
                or not isinstance(configurations, list) or not configurations
                or not all(_arn(_mapping(item).get("playbackConfigurationArn"), "mediatailor", region, account,
                                "playbackConfiguration") for item in configurations)):
            return []
        item = _mapping(result.get("adConfiguration"))
        target = _arn(item.get("arn"), "ivs", region, account, "ad-configuration")
        if target is None or item.get("name") != config_name:
            return []
        extra["ad.playback_configuration_count"] = len(configurations)
    elif name == "GetAdConfiguration":
        target = _arn(request.get("arn"), "ivs", region, account, "ad-configuration")
    elif name == "ListAdConfigurations":
        target = f"arn:aws:ivs:{region}:{account}:ad-configuration"
    elif name == "UpdateChannel":
        target = _arn(request.get("arn"), "ivs", region, account, "channel")
        ad_arn = _arn(request.get("adConfigurationArn"), "ivs", region, account, "ad-configuration")
        if ad_arn is None or _mapping(result.get("channel")).get("adConfigurationArn") != ad_arn:
            return []
        extra["ad.configuration_arn"] = ad_arn
    elif name == "InsertAdBreak":
        target = _arn(request.get("channelArn"), "ivs", region, account, "channel")
        duration = request.get("durationSeconds")
        if (not isinstance(duration, int) or isinstance(duration, bool) or duration <= 0
                or not isinstance(result.get("adBreakId"), str) or not result["adBreakId"]):
            return []
        extra["ad.duration_seconds"] = duration
    if target is None:
        return []

    identity = _mapping(record.get("userIdentity"))
    synthetic, flag, _ = route
    return [{
        "cloud.provider": "aws", "event.source": source,
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": target, flag: True, **extra,
    }]
