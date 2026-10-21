"""IVS real-time stage history and participant control signals."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_ID = re.compile(r"[A-Za-z0-9_-]+\Z")
_SESSION = re.compile(r"st-[A-Za-z0-9]{13}\Z")
_PARTICIPANT = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_ROUTES = {
    "ListStageSessions": ("IvsStageSessionsListed", "request.ivs_stage_sessions_listed", True),
    "GetStageSession": ("IvsStageSessionRead", "request.ivs_stage_session_read", True),
    "ListParticipants": ("IvsParticipantsListed", "request.ivs_participants_listed", True),
    "GetParticipant": ("IvsParticipantRead", "request.ivs_participant_read", True),
    "ListParticipantEvents": ("IvsParticipantEventsRead", "request.ivs_participant_events_read", True),
    "DisconnectParticipant": ("IvsParticipantDisconnected", "request.ivs_participant_disconnected", False),
}


def _arn(value: Any, account: str, region: str) -> str | None:
    if not isinstance(value, str):
        return None
    prefix = f"arn:aws:ivs:{region}:{account}:stage/"
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

    target = _arn(request.get("stageArn"), account, region)
    if target is None:
        return []
    session = request.get("sessionId")
    if name in {"GetStageSession", "ListParticipants", "GetParticipant", "ListParticipantEvents"}:
        if not isinstance(session, str) or not _SESSION.fullmatch(session):
            return []
    else:
        session = None
    participant = request.get("participantId")
    if name in {"GetParticipant", "ListParticipantEvents", "DisconnectParticipant"}:
        if not isinstance(participant, str) or not _PARTICIPANT.fullmatch(participant):
            return []
    else:
        participant = None

    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    synthetic, flag, _ = route
    finding = {
        "cloud.provider": "aws", "event.source": "ivs.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": target, flag: True,
    }
    if session:
        finding["session.id"] = session
    if participant:
        finding["participant.id"] = participant
    return [finding]
