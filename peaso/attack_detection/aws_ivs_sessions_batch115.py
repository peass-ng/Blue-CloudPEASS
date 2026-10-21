"""IVS stream/session controls and token issuance from CloudTrail management events."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_ID = re.compile(r"[A-Za-z0-9_-]+\Z")
_ROUTES = {
    "CreateStreamKey": ("IvsStreamKeyCreated", "request.ivs_stream_key_created", False),
    "ListStreamKeys": ("IvsStreamKeysListed", "request.ivs_stream_keys_listed", True),
    "CreateParticipantToken": ("IvsParticipantTokenIssued", "request.ivs_participant_token_issued", False),
    "PutMetadata": ("IvsLiveMetadataInserted", "request.ivs_live_metadata_inserted", False),
    "StopStream": ("IvsLiveStreamStopped", "request.ivs_live_stream_stopped", False),
    "ListStreamSessions": ("IvsStreamSessionsListed", "request.ivs_stream_sessions_listed", True),
    "GetStreamSession": ("IvsStreamSessionRead", "request.ivs_stream_session_read", True),
    "StartViewerSessionRevocation": ("IvsViewerSessionRevocationStarted", "request.ivs_viewer_revocation_started", True),
    "BatchStartViewerSessionRevocation": ("IvsViewerSessionsBatchRevoked", "request.ivs_viewers_batch_revoked", True),
}


def _arn(value: Any, account: str, region: str, kind: str) -> str | None:
    if not isinstance(value, str):
        return None
    prefix = f"arn:aws:ivs:{region}:{account}:{kind}/"
    tail = value[len(prefix):] if value.startswith(prefix) else ""
    return value if _ID.fullmatch(tail) else None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


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

    target = _arn(request.get("stageArn"), account, region, "stage") if name == "CreateParticipantToken" else (
        _arn(request.get("channelArn"), account, region, "channel"))
    result = _mapping(response)
    if name == "BatchStartViewerSessionRevocation":
        rows = request.get("viewerSessions")
        if (not isinstance(rows, list) or not rows
                or any(not isinstance(row, Mapping) for row in rows)):
            return []
        channels = {_arn(row.get("channelArn"), account, region, "channel") for row in rows}
        if (len(channels) != 1 or None in channels
                or any(not isinstance(row.get("viewerId"), str) or not row["viewerId"]
                       for row in rows)
                or result.get("errors")):
            return []
        target = next(iter(channels))
    elif target is None:
        return []

    if name == "CreateStreamKey":
        stream_key = _mapping(result.get("streamKey"))
        if (_arn(stream_key.get("arn"), account, region, "stream-key") is None
                or stream_key.get("channelArn") != target):
            return []
    elif name == "CreateParticipantToken":
        capabilities = request.get("capabilities")
        duration = request.get("duration")
        if (not isinstance(capabilities, list) or not capabilities
                or any(cap not in {"PUBLISH", "SUBSCRIBE"} for cap in capabilities)
                or not isinstance(duration, int) or isinstance(duration, bool)
                or not 1 <= duration <= 20160
                or not isinstance(request.get("userId"), str) or not request["userId"]
                or not isinstance(result.get("participantToken"), Mapping)):
            return []
    elif name == "PutMetadata":
        if not isinstance(request.get("metadata"), str) or not request["metadata"]:
            return []
    elif name == "GetStreamSession":
        stream_id = request.get("streamId")
        if stream_id is not None and (not isinstance(stream_id, str)
                                      or not re.fullmatch(r"st-[A-Za-z0-9]{20,30}", stream_id)):
            return []
    elif name == "StartViewerSessionRevocation":
        if not isinstance(request.get("viewerId"), str) or not request["viewerId"]:
            return []

    identity = _mapping(record.get("userIdentity"))
    synthetic, flag, _ = route
    return [{
        "cloud.provider": "aws", "event.source": "ivs.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": target, flag: True,
    }]
