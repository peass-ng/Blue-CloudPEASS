"""Accepted Device Farm remote-device and TestGrid session operations."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_UUID = r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"
_MOBILE_SESSION = _UUID + r"/" + _UUID + r"/[0-9]+"
_GRID_SESSION = _UUID + r"/[a-f0-9]{32}"
_ROUTES = {
    "GetRemoteAccessSession": ("RemoteAccessSessionRead", "request.devicefarm_remote_session_read", "session", True, "arn"),
    "StopRemoteAccessSession": ("RemoteAccessSessionStopRequested", "request.devicefarm_remote_session_stop", "session", False, "arn"),
    "DeleteRemoteAccessSession": ("RemoteAccessSessionDeleted", "request.devicefarm_remote_session_deleted", "session", False, "arn"),
    "ListTestGridSessions": ("TestGridSessionsListed", "request.devicefarm_testgrid_sessions_listed", "testgrid-project", True, "projectArn"),
    "GetTestGridSession": ("TestGridSessionRead", "request.devicefarm_testgrid_session_read", "testgrid-session", True, "sessionArn"),
    "ListTestGridSessionActions": ("TestGridSessionActionsListed", "request.devicefarm_testgrid_actions_listed", "testgrid-session", True, "sessionArn"),
    "ListTestGridSessionArtifacts": ("TestGridSessionArtifactsListed", "request.devicefarm_testgrid_artifacts_listed", "testgrid-session", True, "sessionArn"),
}


def _target(arn: Any, kind: str, region: str, account: str) -> bool:
    suffix = (_MOBILE_SESSION if kind == "session" else
              _GRID_SESSION if kind == "testgrid-session" else _UUID)
    pattern = rf"arn:aws:devicefarm:{re.escape(region)}:{account}:{kind}:{suffix}\Z"
    return isinstance(arn, str) and re.fullmatch(pattern, arn) is not None


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name = record.get("eventName")
    if not isinstance(name, str) or (name not in _ROUTES and name != "CreateRemoteAccessSession"):
        return []
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request = record.get("requestParameters")
    expected_read_only = name in {
        "GetRemoteAccessSession", "ListTestGridSessions", "GetTestGridSession",
        "ListTestGridSessionActions", "ListTestGridSessionArtifacts",
    }
    if (record.get("eventSource") != "devicefarm.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not expected_read_only
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str)):
        return []
    try:
        stamp = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return []
    except ValueError:
        return []
    if name == "CreateRemoteAccessSession":
        project = request.get("projectArn")
        response = record.get("responseElements")
        detail = response.get("remoteAccessSession") if isinstance(response, Mapping) else None
        device = request.get("deviceArn")
        arn = detail.get("arn") if isinstance(detail, Mapping) else None
        if (not _target(project, "project", region, account)
                or not _target(arn, "session", region, account)
                or not isinstance(device, str)
                or not re.fullmatch(rf"arn:aws:devicefarm:{re.escape(region)}::device:[A-Fa-f0-9]{{32}}", device)
                or detail.get("status") not in ("PENDING", "PROCESSING", "RUNNING")
                or arn.split(":session:", 1)[1].split("/", 1)[0] != project.rsplit(":", 1)[1]):
            return []
        synthetic, marker = "RemoteAccessSessionCreated", "request.devicefarm_remote_session_created"
    else:
        synthetic, marker, kind, _read_only, parameter = _ROUTES[name]
        arn = request.get(parameter)
        if not _target(arn, kind, region, account):
            return []
        if name == "StopRemoteAccessSession":
            response = record.get("responseElements")
            detail = response.get("remoteAccessSession") if isinstance(response, Mapping) else None
            if (not isinstance(detail, Mapping)
                    or detail.get("arn") not in (arn, arn.replace(":devicefarm:", ":aatp:", 1))
                    or detail.get("status") not in ("STOPPING", "STOPPED", "COMPLETED")):
                return []
        if name == "ListTestGridSessionArtifacts" and request.get("type") not in ("LOG", "VIDEO"):
            return []
    actor = record.get("userIdentity")
    return [{
        "cloud.provider": "aws", "event.source": "devicefarm.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account,
        "actor.id": actor.get("arn") if isinstance(actor, Mapping) else None,
        "target.id": arn,
        marker: True,
    }]
