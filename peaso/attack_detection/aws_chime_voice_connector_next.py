"""Chime SDK Voice Connector control-plane changes from CloudTrail."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import ipaddress
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}-[a-z]+-[0-9]\Z")
_CONNECTOR = re.compile(r"[A-Za-z0-9]{10,64}\Z")
_NAMES = {
    "PutVoiceConnectorTermination", "PutVoiceConnectorTerminationCredentials",
    "PutVoiceConnectorOrigination", "PutVoiceConnectorStreamingConfiguration",
    "PutVoiceConnectorLoggingConfiguration",
}


def _cidrs(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    try:
        return all(isinstance(item, str) and ipaddress.ip_network(item, strict=True).version == 4
                   for item in value)
    except ValueError:
        return False


def normalize_aws_chime_voice_connector(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (not isinstance(name, str) or name not in _NAMES
            or record.get("eventSource") != "chime-sdk-voice.amazonaws.com"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
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
    connector_id = request.get("voiceConnectorId")
    if not isinstance(connector_id, str) or not _CONNECTOR.fullmatch(connector_id):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None

    response = record.get("responseElements")
    flags = {}
    if name == "PutVoiceConnectorTermination":
        submitted = request.get("termination")
        accepted = response.get("termination") if isinstance(response, Mapping) else None
        if (not isinstance(submitted, Mapping) or not isinstance(accepted, Mapping)
                or submitted.get("disabled") is not False or accepted.get("disabled") is not False
                or not _cidrs(submitted.get("cidrAllowedList"))
                or accepted.get("cidrAllowedList") != submitted["cidrAllowedList"]):
            return None
        flags["request.chime_voice_termination_enabled_with_cidrs"] = True
    elif name == "PutVoiceConnectorTerminationCredentials":
        credentials = request.get("credentials")
        if (not isinstance(credentials, list) or not credentials
                or not all(isinstance(c, Mapping) and isinstance(c.get("username"), str)
                           and c["username"] and "password" in c for c in credentials)):
            return None
        flags["request.chime_voice_termination_credentials_submitted"] = True
    elif name == "PutVoiceConnectorOrigination":
        submitted = request.get("origination")
        accepted = response.get("origination") if isinstance(response, Mapping) else None
        if (not isinstance(submitted, Mapping) or not isinstance(accepted, Mapping)
                or submitted.get("disabled") is not False or accepted.get("disabled") is not False
                or not isinstance(submitted.get("routes"), list) or not submitted["routes"]
                or not all(isinstance(route, Mapping)
                           and isinstance(route.get("host"), str) and route["host"]
                           and isinstance(route.get("port"), int) and 1 <= route["port"] <= 65535
                           for route in submitted["routes"])
                or accepted.get("routes") != submitted["routes"]):
            return None
        flags["request.chime_voice_origination_route_enabled"] = True
    elif name == "PutVoiceConnectorStreamingConfiguration":
        submitted = request.get("streamingConfiguration")
        accepted = response.get("streamingConfiguration") if isinstance(response, Mapping) else None
        if (not isinstance(submitted, Mapping) or not isinstance(accepted, Mapping)
                or submitted.get("disabled") is not False or accepted.get("disabled") is not False
                or not isinstance(submitted.get("dataRetentionInHours"), int)
                or isinstance(submitted["dataRetentionInHours"], bool)
                or submitted["dataRetentionInHours"] < 0
                or accepted.get("dataRetentionInHours") != submitted["dataRetentionInHours"]):
            return None
        flags["request.chime_voice_streaming_enabled"] = True
    else:
        submitted = request.get("loggingConfiguration")
        accepted = response.get("loggingConfiguration") if isinstance(response, Mapping) else None
        if not isinstance(submitted, Mapping) or not isinstance(accepted, Mapping):
            return None
        for key, flag in (("enableSIPLogs", "request.chime_voice_sip_logs_disabled"),
                          ("enableMediaMetricLogs", "request.chime_voice_media_logs_disabled")):
            flags[flag] = submitted.get(key) is False and accepted.get(key) is False
        if not any(flags.values()):
            return None

    return {"cloud.provider": "aws", "event.source": "chime-sdk-voice.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record["eventTime"],
            "account.id": account, "actor.id": identity["arn"],
            "target.id": f"arn:aws:chime:{region}:{account}:vc/{connector_id}", **flags}
