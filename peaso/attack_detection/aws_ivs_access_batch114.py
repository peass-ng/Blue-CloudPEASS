"""IVS access and persistence signals from observed CloudTrail management calls."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_RESOURCE = re.compile(r"[A-Za-z0-9_-]+\Z")
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_ROUTES = {
    "GetStreamKey": ("stream-key", "IvsStreamKeyRead", "request.ivs_stream_key_read", True),
    "GetChannel": ("channel", "IvsChannelEndpointRead", "request.ivs_channel_endpoint_read", True),
    "GetStage": ("stage", "IvsStageEndpointRead", "request.ivs_stage_endpoint_read", True),
    "GetIngestConfiguration": ("ingest-configuration", "IvsIngestKeyRead", "request.ivs_ingest_key_read", True),
    "UpdateChannel": ("channel", "IvsPlaybackAuthorizationDisabled", "request.ivs_playback_authorization_disabled", False),
    "ImportPublicKey": ("public-key", "IvsRealtimeSigningKeyImported", "request.ivs_realtime_signing_key_imported", False),
    "ImportPlaybackKeyPair": ("playback-key", "IvsPlaybackSigningKeyImported", "request.ivs_playback_signing_key_imported", False),
    "CreateIngestConfiguration": ("ingest-configuration", "IvsReusableIngestCreated", "request.ivs_reusable_ingest_created", False),
    "UpdateIngestConfiguration": ("ingest-configuration", "IvsIngestStageAssigned", "request.ivs_ingest_stage_assigned", False),
}


def _arn(value: Any, account: str, region: str, kind: str) -> str | None:
    if not isinstance(value, str):
        return None
    prefix = f"arn:aws:ivs:{region}:{account}:{kind}/"
    suffix = value[len(prefix):] if value.startswith(prefix) else ""
    return value if _RESOURCE.fullmatch(suffix) else None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name, account, region = (record.get(key) for key in
                             ("eventName", "recipientAccountId", "awsRegion"))
    route = _ROUTES.get(name) if isinstance(name, str) else None
    request = record.get("requestParameters")
    response = record.get("responseElements")
    if (route is None or record.get("eventSource") != "ivs.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not route[3]
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
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return []
    except ValueError:
        return []

    kind, synthetic, flag, is_read = route
    target = _arn(request.get("arn"), account, region, kind)
    result = _mapping(response)
    if is_read:
        if target is None:
            return []
    elif name == "UpdateChannel":
        channel = _mapping(result.get("channel"))
        if (target is None or request.get("authorized") is not False
                or channel.get("arn") != target or channel.get("authorized") is not False):
            return []
    elif name in {"ImportPublicKey", "ImportPlaybackKeyPair"}:
        item = _mapping(result.get("publicKey" if name == "ImportPublicKey" else "keyPair"))
        target = _arn(item.get("arn"), account, region, kind)
        if (target is None or not isinstance(request.get("name"), str)
                or not _NAME.fullmatch(request["name"])
                or not isinstance(request.get("publicKeyMaterial"), str)
                or not request["publicKeyMaterial"].strip()
                or not isinstance(item.get("fingerprint"), str)
                or not item["fingerprint"]):
            return []
    elif name == "CreateIngestConfiguration":
        item = _mapping(result.get("ingestConfiguration"))
        target = _arn(item.get("arn"), account, region, kind)
        stage = _arn(request.get("stageArn"), account, region, "stage")
        if (target is None or stage is None or item.get("stageArn") != stage
                or request.get("ingestProtocol") != "RTMPS"
                or not isinstance(request.get("name"), str)
                or not _NAME.fullmatch(request["name"])):
            return []
    else:
        item = _mapping(result.get("ingestConfiguration"))
        stage = _arn(request.get("stageArn"), account, region, "stage")
        if (target is None or stage is None or item.get("arn") != target
                or item.get("stageArn") != stage):
            return []

    identity = _mapping(record.get("userIdentity"))
    finding = {
        "cloud.provider": "aws", "event.source": "ivs.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": target, flag: True,
    }
    return [finding]
