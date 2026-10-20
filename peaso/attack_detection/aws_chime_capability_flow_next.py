"""Chime SDK attendee capability and channel-flow management signals."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any


_UUID = re.compile(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}\Z")
_FLOW_ID = re.compile(r"[a-fA-F0-9]{64}\Z")
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}-[a-z]+-[0-9]\Z")
_SEND = {"Send", "SendReceive"}
_CAPABILITIES = {"None", "Receive", "Send", "SendReceive"}
_NAMES = {"UpdateAttendeeCapabilities", "CreateChannelFlow", "UpdateChannelFlow",
          "AssociateChannelFlow", "ChannelFlowCallback"}


def _common(record: Mapping[str, Any]):
    name = record.get("eventName")
    if (not isinstance(name, str) or name not in _NAMES
            or record.get("eventSource") != "chime.amazonaws.com"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request = record.get("userIdentity"), record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping)
            or identity.get("accountId") not in (None, account)
            or not isinstance(identity.get("arn"), str) or not identity["arn"]
            or not isinstance(request, Mapping)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None
    return name, account, region, identity["arn"], request


def _app(value: Any, account: str, region: str):
    prefix = f"arn:aws:chime:{region}:{account}:app-instance/"
    return value if isinstance(value, str) and value.startswith(prefix) and _UUID.fullmatch(value[len(prefix):]) else None


def _child(value: Any, app: str, kind: str):
    prefix = app + "/" + kind + "/"
    pattern = _FLOW_ID if kind == "channel-flow" else _UUID
    return value if isinstance(value, str) and value.startswith(prefix) and pattern.fullmatch(value[len(prefix):]) else None


def _base_of(value: Any, account: str, region: str, kind: str):
    prefix = f"arn:aws:chime:{region}:{account}:app-instance/"
    if not isinstance(value, str) or not value.startswith(prefix):
        return None
    app_id, sep, child_id = value[len(prefix):].partition(f"/{kind}/")
    pattern = _FLOW_ID if kind == "channel-flow" else _UUID
    if not sep or not _UUID.fullmatch(app_id) or not pattern.fullmatch(child_id):
        return None
    return prefix + app_id


def _bearer(value: Any, app: str):
    if not isinstance(value, str):
        return False
    for kind in ("user", "bot"):
        prefix = app + "/" + kind + "/"
        if value.startswith(prefix) and re.fullmatch(r"[A-Za-z0-9:_\-.@]{1,64}", value[len(prefix):]):
            return True
    return False


def _processor_lambdas(value: Any, account: str, region: str):
    if not isinstance(value, list) or not 1 <= len(value) <= 3:
        return False
    prefix = f"arn:aws:lambda:{region}:{account}:function:"
    orders = set()
    for processor in value:
        if not isinstance(processor, Mapping):
            return False
        order = processor.get("executionOrder")
        config = processor.get("configuration")
        lamb = config.get("lambda") if isinstance(config, Mapping) else None
        arn = lamb.get("resourceArn") if isinstance(lamb, Mapping) else None
        if (not isinstance(order, int) or isinstance(order, bool) or not 1 <= order <= 3
                or order in orders or processor.get("fallbackAction") not in {"CONTINUE", "ABORT"}
                or not isinstance(arn, str) or not arn.startswith(prefix)
                or not re.fullmatch(r"[A-Za-z0-9_\-.]{1,64}", arn[len(prefix):])
                or lamb.get("invocationType") != "ASYNC"):
            return False
        orders.add(order)
    return True


def normalize_aws_chime_capability_flow(record: Mapping[str, Any]) -> dict[str, Any] | None:
    common = _common(record)
    if common is None:
        return None
    name, account, region, actor, request = common
    response = record.get("responseElements")
    flags = {}

    if name == "UpdateAttendeeCapabilities":
        meeting, attendee, caps = (request.get("meetingId"), request.get("attendeeId"),
                                   request.get("capabilities"))
        updated = response.get("attendee") if isinstance(response, Mapping) else None
        if (not isinstance(meeting, str) or not _UUID.fullmatch(meeting)
                or not isinstance(attendee, str) or not _UUID.fullmatch(attendee)
                or not isinstance(caps, Mapping)
                or set(caps) != {"audio", "video", "content"}
                or any(not isinstance(caps[k], str) or caps[k] not in _CAPABILITIES for k in caps)
                or not isinstance(updated, Mapping)
                or updated.get("attendeeId") != attendee
                or updated.get("capabilities") != caps):
            return None
        target = f"arn:aws:chime:{region}:{account}:meeting/{meeting}"
        flags["request.chime_attendee_capabilities_updated"] = True
        flags["request.chime_attendee_send_enabled"] = any(v in _SEND for v in caps.values())
        flags["request.chime_attendee_all_media_disabled"] = all(v == "None" for v in caps.values())
    elif name in {"CreateChannelFlow", "UpdateChannelFlow"}:
        if not _processor_lambdas(request.get("processors"), account, region):
            return None
        if name == "CreateChannelFlow":
            app = _app(request.get("appInstanceArn"), account, region)
            flow = response.get("channelFlowArn") if isinstance(response, Mapping) else None
            if app is None or _child(flow, app, "channel-flow") is None:
                return None
            flag = "request.chime_channel_flow_created"
        else:
            flow = request.get("channelFlowArn")
            app = _base_of(flow, account, region, "channel-flow")
            if (app is None or not isinstance(response, Mapping)
                    or response.get("channelFlowArn") != flow):
                return None
            flag = "request.chime_channel_flow_updated"
        target = flow
        flags[flag] = True
    elif name == "AssociateChannelFlow":
        channel, flow = request.get("channelArn"), request.get("channelFlowArn")
        app = _base_of(channel, account, region, "channel")
        if (app is None or _child(flow, app, "channel-flow") is None
                or not _bearer(request.get("chimeBearer"), app)):
            return None
        target = channel
        flags["request.chime_channel_flow_associated"] = True
    else:
        channel = request.get("channelArn")
        app = _base_of(channel, account, region, "channel")
        message = request.get("channelMessage")
        if (app is None or not isinstance(message, Mapping)
                or not isinstance(message.get("messageId"), str) or not message["messageId"]
                or not isinstance(response, Mapping)
                or response.get("channelArn") != channel
                or response.get("callbackId") != request.get("callbackId")):
            return None
        target = channel
        flags["request.chime_channel_flow_callback"] = True

    return {"cloud.provider": "aws", "event.source": "chime.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record["eventTime"],
            "account.id": account, "actor.id": actor, "target.id": target, **flags}
