"""Normalize Kinesis Video Streams media and signaling endpoint discovery."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_RESOURCE = re.compile(r"[A-Za-z0-9_.-]+/[0-9]+\Z")
_MEDIA_APIS = {
    "GET_MEDIA": "request.kvs_get_media_endpoint_discovered",
    "LIST_FRAGMENTS": "request.kvs_list_fragments_endpoint_discovered",
}


def _arn(value: Any, kind: str, region: str, account: str) -> bool:
    prefix = f"arn:aws:kinesisvideo:{region}:{account}:{kind}/"
    return isinstance(value, str) and value.startswith(prefix) and bool(
        _RESOURCE.fullmatch(value[len(prefix):]))


def normalize_aws_kinesis_video_endpoint(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "kinesisvideo.amazonaws.com"
            or name not in {"GetDataEndpoint", "GetSignalingChannelEndpoint"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not True):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    flags = dict.fromkeys([*_MEDIA_APIS.values(), "request.kvs_signaling_viewer_endpoint_discovered"], False)
    if name == "GetDataEndpoint":
        target = request.get("streamARN")
        api = request.get("aPIName")
        if (not _arn(target, "stream", region, account)
                or not isinstance(api, str) or api not in _MEDIA_APIS):
            return None
        flag = _MEDIA_APIS[api]
    else:
        target = request.get("channelARN")
        config = request.get("singleMasterChannelEndpointConfiguration")
        if (not _arn(target, "channel", region, account)
                or not isinstance(config, Mapping)
                or config.get("role") != "VIEWER"
                or not isinstance(config.get("protocols"), list)
                or "HTTPS" not in config["protocols"]):
            return None
        flag = "request.kvs_signaling_viewer_endpoint_discovered"
    success = not (record.get("errorCode") or record.get("errorMessage"))
    flags[flag] = success
    actor = record.get("userIdentity")
    actor = actor if isinstance(actor, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": record["eventSource"],
            "event.name": name, "event.outcome": "success" if success else "failure",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": actor.get("arn"), "target.id": target,
            **flags}
