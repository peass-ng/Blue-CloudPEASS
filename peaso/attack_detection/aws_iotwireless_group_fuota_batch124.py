"""IoT Wireless multicast, FUOTA and gateway firmware control-plane signals."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
_NAME = re.compile(r"[A-Za-z0-9_-]{1,256}\Z")
_ROUTES = {
    "CreateMulticastGroup": ("IotWirelessMulticastGroupCreated", "request.iotwireless_multicast_group_created", False),
    "GetMulticastGroup": ("IotWirelessMulticastGroupRead", "request.iotwireless_multicast_group_read", True),
    "UpdateMulticastGroup": ("IotWirelessMulticastGroupUpdated", "request.iotwireless_multicast_group_updated", False),
    "CreateFuotaTask": ("IotWirelessFuotaTaskCreated", "request.iotwireless_fuota_task_created", False),
    "GetFuotaTask": ("IotWirelessFuotaTaskRead", "request.iotwireless_fuota_task_read", True),
    "UpdateFuotaTask": ("IotWirelessFuotaTaskUpdated", "request.iotwireless_fuota_task_updated", False),
    "CreateWirelessGatewayTaskDefinition": ("IotWirelessGatewayTaskDefinitionCreated", "request.iotwireless_gateway_task_definition_created", False),
    "GetWirelessGatewayTaskDefinition": ("IotWirelessGatewayTaskDefinitionRead", "request.iotwireless_gateway_task_definition_read", True),
    "ListWirelessGatewayTaskDefinitions": ("IotWirelessGatewayTaskDefinitionsListed", "request.iotwireless_gateway_task_definitions_listed", True),
}


def _uuid(value: Any) -> bool:
    return isinstance(value, str) and bool(_UUID.fullmatch(value))


def _name(value: Any) -> bool:
    return isinstance(value, str) and bool(_NAME.fullmatch(value))


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
    if name in ("CreateMulticastGroup", "CreateFuotaTask", "CreateWirelessGatewayTaskDefinition"):
        ident = response.get("id") if isinstance(response, Mapping) else None
        arn = response.get("arn") if isinstance(response, Mapping) else None
        if not _uuid(ident) or not _name(request.get("name")):
            return []
        kind = {"CreateMulticastGroup": "MulticastGroup", "CreateFuotaTask": "FuotaTask",
                "CreateWirelessGatewayTaskDefinition": "WirelessGatewayTaskDefinition"}[name]
        if arn != _arn(region, account, kind, ident):
            return []
        if name == "CreateMulticastGroup":
            if not isinstance(request.get("loRaWAN"), Mapping):
                return []
        elif name == "CreateFuotaTask":
            if (not isinstance(request.get("firmwareUpdateImage"), str)
                    or not request["firmwareUpdateImage"]
                    or not isinstance(request.get("firmwareUpdateRole"), str)
                    or not request["firmwareUpdateRole"]):
                return []
        else:
            update = request.get("update")
            if (not isinstance(request.get("autoCreateTasks"), bool)
                    or not isinstance(update, Mapping)
                    or not isinstance(update.get("updateDataSource"), str)
                    or not update["updateDataSource"]
                    or not isinstance(update.get("updateDataRole"), str)
                    or not update["updateDataRole"]):
                return []
        target = arn
    elif name in ("GetMulticastGroup", "UpdateMulticastGroup", "GetFuotaTask", "UpdateFuotaTask", "GetWirelessGatewayTaskDefinition"):
        ident = request.get("id")
        if not _uuid(ident):
            return []
        kind = ("MulticastGroup" if name.endswith("MulticastGroup") else
                "FuotaTask" if name.endswith("FuotaTask") else
                "WirelessGatewayTaskDefinition")
        target = _arn(region, account, kind, ident)
    else:
        target = None

    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    synthetic, flag, _ = route
    base = {
        "cloud.provider": "aws", "event.source": "iotwireless.amazonaws.com",
        "event.outcome": "success", "event.id": record["eventID"],
        "event.time": record["eventTime"], "account.id": account,
        "actor.id": actor, "target.id": target,
    }
    output = [{**base, "event.name": synthetic, flag: True}]
    if name == "UpdateFuotaTask" and isinstance(request.get("firmwareUpdateImage"), str) and request["firmwareUpdateImage"]:
        output.append({**base, "event.name": "IotWirelessFuotaFirmwareSourceSet",
                       "request.iotwireless_fuota_firmware_source_set": True})
    return output
