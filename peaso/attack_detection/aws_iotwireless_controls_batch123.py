"""IoT Wireless reads, routing changes and analyzer configuration signals.

CloudTrail omits device keys and read responses. Never propagate request payloads.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
_NAME = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_ROUTES = {
    "GetWirelessDevice": ("IotWirelessDeviceSecretsRead", "request.iotwireless_device_secrets_read", True),
    "GetDestination": ("IotWirelessDestinationRead", "request.iotwireless_destination_read", True),
    "GetResourcePosition": ("IotWirelessPositionRead", "request.iotwireless_position_read", True),
    "GetNetworkAnalyzerConfiguration": ("IotWirelessAnalyzerRead", "request.iotwireless_analyzer_read", True),
    "GetDeviceProfile": ("IotWirelessDeviceProfileRead", "request.iotwireless_device_profile_read", True),
    "GetServiceProfile": ("IotWirelessServiceProfileRead", "request.iotwireless_service_profile_read", True),
    "CreateDestination": ("IotWirelessDestinationCreated", "request.iotwireless_destination_created", False),
    "UpdateWirelessDevice": ("IotWirelessDeviceDestinationChanged", "request.iotwireless_device_destination_changed", False),
    # These calls were delivered later than the other management events and omit
    # the resource identifier, so findings intentionally have no target ID.
    "UpdateResourcePosition": ("IotWirelessPositionChanged", "request.iotwireless_position_changed", False),
    "SendDataToWirelessDevice": ("IotWirelessDownlinkSent", "request.iotwireless_downlink_sent", False),
    # IoT Wireless marks this successful create as readOnly=true in Event History.
    "CreateNetworkAnalyzerConfiguration": ("IotWirelessAnalyzerConfigured", "request.iotwireless_analyzer_configured", True),
}


def _name(value: Any) -> bool:
    return isinstance(value, str) and bool(_NAME.fullmatch(value))


def _uuid(value: Any) -> bool:
    return isinstance(value, str) and bool(_UUID.fullmatch(value))


def _arn(region: str, account: str, kind: str, ident: str) -> str:
    return f"arn:aws:iotwireless:{region}:{account}:{kind}/{ident}"


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name = record.get("eventName")
    route = _ROUTES.get(name) if isinstance(name, str) else None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (route is None or record.get("eventSource") != "iotwireless.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not route[2]
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str)
            or not isinstance(request, Mapping)):
        return []
    if isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")):
        return []
    try:
        timestamp = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            return []
    except ValueError:
        return []

    target: str | None
    if name == "GetWirelessDevice":
        ident = request.get("identifier")
        if request.get("identifierType") != "WirelessDeviceId" or not _uuid(ident):
            return []
        target = _arn(region, account, "WirelessDevice", ident)
    elif name == "GetDestination":
        dest = request.get("name")
        if not _name(dest):
            return []
        target = _arn(region, account, "Destination", dest)
    elif name == "GetResourcePosition":
        ident, kind = request.get("resourceIdentifier"), request.get("resourceType")
        if kind not in ("WirelessDevice", "WirelessGateway") or not _uuid(ident):
            return []
        target = _arn(region, account, kind, ident)
    elif name == "GetNetworkAnalyzerConfiguration":
        config = request.get("configurationName")
        if not _name(config):
            return []
        target = _arn(region, account, "NetworkAnalyzerConfiguration", config)
    elif name in ("GetDeviceProfile", "GetServiceProfile"):
        ident = request.get("id")
        if not _uuid(ident):
            return []
        kind = "DeviceProfile" if name == "GetDeviceProfile" else "ServiceProfile"
        target = _arn(region, account, kind, ident)
    elif name == "CreateDestination":
        dest = request.get("name")
        result = response if isinstance(response, Mapping) else {}
        if (not _name(dest) or request.get("expressionType") not in ("MqttTopic", "RuleName")
                or result.get("name") != dest
                or result.get("arn") != _arn(region, account, "Destination", dest)):
            return []
        target = result["arn"]
    elif name == "UpdateWirelessDevice":
        ident, dest = request.get("id"), request.get("destinationName")
        if not _uuid(ident) or not _name(dest):
            return []
        target = _arn(region, account, "WirelessDevice", ident)
    elif name == "UpdateResourcePosition":
        if not isinstance(request.get("geoJsonPayload"), Mapping):
            return []
        target = None
    elif name == "SendDataToWirelessDevice":
        result = response if isinstance(response, Mapping) else {}
        if (request.get("transmitMode") not in (0, 1)
                or not isinstance(request.get("payloadData"), str)
                or not request["payloadData"]
                or not isinstance(request.get("wirelessMetadata"), Mapping)
                or not isinstance(result.get("messageId"), str)
                or not result["messageId"]):
            return []
        target = None
    else:
        config = request.get("name")
        trace = request.get("traceContent")
        members = ("wirelessDevices", "wirelessGateways", "multicastGroups")
        if (not _name(config) or not isinstance(trace, Mapping)
                or not any(isinstance(request.get(key), list) and request[key] for key in members)):
            return []
        target = _arn(region, account, "NetworkAnalyzerConfiguration", config)

    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    synthetic, flag, _ = route
    return [{
        "cloud.provider": "aws", "event.source": "iotwireless.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": actor,
        "target.id": target, flag: True,
    }]
