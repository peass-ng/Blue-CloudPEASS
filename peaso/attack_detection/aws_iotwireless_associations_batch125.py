"""IoT Wireless multicast and FUOTA membership management signals."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
_ROUTES = {
    "AssociateWirelessDeviceWithMulticastGroup": ("IotWirelessDeviceJoinedMulticastGroup", "request.iotwireless_device_joined_multicast_group", False),
    "DisassociateWirelessDeviceFromMulticastGroup": ("IotWirelessDeviceLeftMulticastGroup", "request.iotwireless_device_left_multicast_group", False),
    "AssociateWirelessDeviceWithFuotaTask": ("IotWirelessDeviceJoinedFuotaTask", "request.iotwireless_device_joined_fuota_task", False),
    "DisassociateWirelessDeviceFromFuotaTask": ("IotWirelessDeviceLeftFuotaTask", "request.iotwireless_device_left_fuota_task", False),
    "AssociateMulticastGroupWithFuotaTask": ("IotWirelessMulticastGroupJoinedFuotaTask", "request.iotwireless_multicast_group_joined_fuota_task", False),
    "DisassociateMulticastGroupFromFuotaTask": ("IotWirelessMulticastGroupLeftFuotaTask", "request.iotwireless_multicast_group_left_fuota_task", False),
    "ListMulticastGroupsByFuotaTask": ("IotWirelessFuotaMulticastGroupsListed", "request.iotwireless_fuota_multicast_groups_listed", True),
}


def _uuid(value: Any) -> bool:
    return isinstance(value, str) and bool(_UUID.fullmatch(value))


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
        stamp = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return []
    except ValueError:
        return []

    task_or_group = request.get("id")
    if not _uuid(task_or_group):
        return []
    if name in ("AssociateWirelessDeviceWithMulticastGroup", "DisassociateWirelessDeviceFromMulticastGroup",
                "AssociateWirelessDeviceWithFuotaTask", "DisassociateWirelessDeviceFromFuotaTask"):
        added = request.get("wirelessDeviceId")
        if not _uuid(added):
            return []
        target = f"arn:aws:iotwireless:{region}:{account}:WirelessDevice/{added}"
    elif name in ("AssociateMulticastGroupWithFuotaTask", "DisassociateMulticastGroupFromFuotaTask"):
        added = request.get("multicastGroupId")
        if not _uuid(added):
            return []
        target = f"arn:aws:iotwireless:{region}:{account}:MulticastGroup/{added}"
    else:
        target = f"arn:aws:iotwireless:{region}:{account}:FuotaTask/{task_or_group}"

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
