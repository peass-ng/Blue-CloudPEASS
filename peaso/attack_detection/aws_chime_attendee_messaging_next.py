"""Chime SDK attendee and messaging control-plane observations."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any


_UUID = re.compile(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}\Z")
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}-[a-z]+-[0-9]\Z")

_FLAGS = {
    "CreateAttendee": "request.chime_attendee_created",
    "BatchCreateAttendee": "request.chime_attendees_batch_created",
    "GetAttendee": "request.chime_attendee_token_read",
    "ListAttendees": "request.chime_attendee_tokens_listed",
    "GetMeeting": "request.chime_meeting_media_read",
    "CreateAppInstanceUser": "request.chime_app_instance_user_created",
    "CreateChannelMembership": "request.chime_channel_member_added",
    "ListChannelMessages": "request.chime_channel_history_read",
    "SendChannelMessage": "request.chime_channel_message_sent",
}
_READS = {"GetAttendee", "ListAttendees", "GetMeeting", "ListChannelMessages"}


def _chime_prefix(account: str, region: str) -> str:
    return f"arn:aws:chime:{region}:{account}:app-instance/"


def _app(value: Any, account: str, region: str) -> str | None:
    prefix = _chime_prefix(account, region)
    if isinstance(value, str) and value.startswith(prefix) and _UUID.fullmatch(value[len(prefix):]):
        return value
    return None


def _channel_bearer(request: Mapping[str, Any], account: str, region: str):
    channel = request.get("channelArn")
    bearer = request.get("chimeBearer")
    prefix = _chime_prefix(account, region)
    if not isinstance(channel, str) or not channel.startswith(prefix):
        return None
    suffix = channel[len(prefix):]
    app_id, sep, channel_id = suffix.partition("/channel/")
    if not sep or not _UUID.fullmatch(app_id) or not _UUID.fullmatch(channel_id):
        return None
    base = prefix + app_id
    if (not isinstance(bearer, str) or not any(
            bearer.startswith(base + kind) and 0 < len(bearer[len(base + kind):]) <= 64
            and "/" not in bearer[len(base + kind):]
            for kind in ("/user/", "/bot/"))):
        return None
    return channel, bearer, base


def normalize_aws_chime_attendee_messaging(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (not isinstance(name, str) or name not in _FLAGS
            or record.get("eventSource") != "chime.amazonaws.com"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name in _READS)
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, identity = record.get("requestParameters"), record.get("userIdentity")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping) or not isinstance(identity, Mapping)
            or identity.get("accountId") not in (None, account)
            or not isinstance(identity.get("arn"), str) or not identity["arn"]
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None

    if name in {"CreateAttendee", "BatchCreateAttendee", "GetAttendee", "ListAttendees", "GetMeeting"}:
        meeting = request.get("meetingId")
        if not isinstance(meeting, str) or not _UUID.fullmatch(meeting):
            return None
        if name == "CreateAttendee" and not isinstance(request.get("externalUserId"), str):
            return None
        if name == "CreateAttendee":
            response = record.get("responseElements")
            if not isinstance(response, Mapping) or not isinstance(response.get("attendee"), Mapping):
                return None
        if name == "BatchCreateAttendee":
            attendees = request.get("attendees")
            response = record.get("responseElements")
            if (not isinstance(attendees, list) or not attendees
                    or not all(isinstance(a, Mapping) and isinstance(a.get("externalUserId"), str)
                               for a in attendees)
                    or not isinstance(response, Mapping)
                    or not isinstance(response.get("attendees"), list)
                    or not response["attendees"]):
                return None
        if name == "GetAttendee":
            attendee = request.get("attendeeId")
            if not isinstance(attendee, str) or not _UUID.fullmatch(attendee):
                return None
        target = f"arn:aws:chime:{region}:{account}:meeting/{meeting}"
    elif name == "CreateAppInstanceUser":
        app = _app(request.get("appInstanceArn"), account, region)
        user_id = request.get("appInstanceUserId")
        response = record.get("responseElements")
        created_arn = response.get("appInstanceUserArn") if isinstance(response, Mapping) else None
        if (app is None or not isinstance(user_id, str) or not re.fullmatch(r"[A-Za-z0-9:_\-.@]{1,64}", user_id)
                or not isinstance(created_arn, str)
                or not created_arn.startswith(app + "/user/")
                or not re.fullmatch(r"[A-Za-z0-9:_\-.@]{1,64}", created_arn[len(app + "/user/"):])):
            return None
        target = created_arn
    else:
        channel_bearer = _channel_bearer(request, account, region)
        if channel_bearer is None:
            return None
        channel, bearer, app = channel_bearer
        if name == "CreateChannelMembership":
            member = request.get("memberArn")
            if (not isinstance(member, str) or not member.startswith(app + "/user/")
                    or not re.fullmatch(r"[A-Za-z0-9:_\-.@]{1,64}", member[len(app + "/user/"):])):
                return None
            target = member
        elif name == "SendChannelMessage":
            response = record.get("responseElements")
            status = response.get("status") if isinstance(response, Mapping) else None
            if (request.get("type") != "STANDARD"
                    or request.get("persistence") not in {"PERSISTENT", "NON_PERSISTENT"}
                    or not isinstance(request.get("content"), str)
                    or not isinstance(status, Mapping) or status.get("value") != "SENT"):
                return None
            target = channel
        else:
            target = channel

    return {
        "cloud.provider": "aws", "event.source": "chime.amazonaws.com",
        "event.name": name, "event.outcome": "success", "event.id": record["eventID"],
        "event.time": record["eventTime"], "account.id": account,
        "actor.id": identity["arn"], "target.id": target, _FLAGS[name]: True,
    }
