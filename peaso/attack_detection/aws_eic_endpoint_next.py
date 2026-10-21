"""CloudTrail signals for EC2 Instance Connect Endpoint access paths."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import ipaddress
import re
from typing import Any


_ENDPOINT = re.compile(r"(?:eice|eici)-[0-9a-f]{8,17}\Z")
_GROUP = re.compile(r"sg-[0-9a-f]{8,17}\Z")
_SUBNET = re.compile(r"subnet-[0-9a-f]{8,17}\Z")


def _valid(record: Mapping[str, Any], name: str) -> bool:
    return (record.get("eventSource") == "ec2.amazonaws.com"
            and record.get("eventName") == name
            and record.get("eventCategory") == "Management"
            and record.get("eventType") == "AwsApiCall"
            and record.get("managementEvent") is True
            and record.get("readOnly") is False
            and not record.get("errorCode") and not record.get("errorMessage")
            and isinstance(record.get("recipientAccountId"), str)
            and re.fullmatch(r"\d{12}", record["recipientAccountId"]) is not None
            and isinstance(record.get("awsRegion"), str))


def _actor(record: Mapping[str, Any]) -> str | None:
    identity = record.get("userIdentity")
    return identity.get("arn") if isinstance(identity, Mapping) else None


def _time(record: Mapping[str, Any]) -> datetime | None:
    value = record.get("eventTime")
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result if result.tzinfo else None


def _created(record: Mapping[str, Any]) -> tuple[str, set[str]] | None:
    if not _valid(record, "CreateInstanceConnectEndpoint"):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    request = request.get("CreateInstanceConnectEndpointRequest")
    response = response.get("CreateInstanceConnectEndpointResponse")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    endpoint = response.get("instanceConnectEndpoint")
    if not isinstance(endpoint, Mapping):
        return None
    endpoint_id, subnet = endpoint.get("instanceConnectEndpointId"), request.get("SubnetId")
    if (not isinstance(endpoint_id, str) or not _ENDPOINT.fullmatch(endpoint_id)
            or not isinstance(subnet, str) or not _SUBNET.fullmatch(subnet)
            or endpoint.get("subnetId") != subnet
            or endpoint.get("ownerId") != record["recipientAccountId"]
            or endpoint.get("state") not in {"create-in-progress", "create-complete"}
            or not isinstance(endpoint.get("instanceConnectEndpointArn"), str)
            or not endpoint["instanceConnectEndpointArn"].endswith("/" + endpoint_id)):
        return None
    group_set = endpoint.get("securityGroupIdSet")
    group_items = group_set.get("item") if isinstance(group_set, Mapping) else None
    if isinstance(group_items, str):
        group_items = [group_items]
    if not isinstance(group_items, list) or not group_items or not all(
            isinstance(group, str) and _GROUP.fullmatch(group) for group in group_items):
        return None
    return endpoint_id, set(group_items)


def normalize_aws_eic_endpoint(record: Mapping[str, Any]) -> dict[str, Any] | None:
    created = _created(record)
    if created is None:
        return None
    return {
        "cloud.provider": "aws", "event.source": "ec2.amazonaws.com",
        "event.name": "CreateInstanceConnectEndpoint", "event.outcome": "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record["recipientAccountId"], "actor.id": _actor(record),
        "target.id": created[0], "request.eic_endpoint_created": True,
    }


def normalize_aws_eic_connection(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "ec2-instance-connect.amazonaws.com"
            or name not in {"SendSSHPublicKey", "OpenTunnel"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(record.get("recipientAccountId"), str)
            or re.fullmatch(r"\d{12}", record["recipientAccountId"]) is None):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping):
        return None
    if name == "SendSSHPublicKey":
        target = request.get("instanceId")
        if (not isinstance(target, str) or re.fullmatch(r"i-[0-9a-f]{8,17}", target) is None
                or not isinstance(request.get("instanceOSUser"), str)
                or not request["instanceOSUser"]
                or not isinstance(request.get("sSHPublicKey"), str)
                or not request["sSHPublicKey"].startswith("ssh-")
                or not isinstance(response, Mapping)
                or response.get("success") is not True):
            return None
    else:
        target = request.get("instanceConnectEndpointId")
        if not isinstance(target, str) or _ENDPOINT.fullmatch(target) is None:
            return None
        try:
            private_ip = ipaddress.ip_address(request.get("privateIpAddress"))
        except (TypeError, ValueError):
            return None
        if (not isinstance(private_ip, ipaddress.IPv4Address) or not private_ip.is_private
                or str(request.get("remotePort")) != "22" or response is not None):
            return None
    return {
        "cloud.provider": "aws", "event.source": "ec2-instance-connect.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record["recipientAccountId"], "actor.id": _actor(record),
        "target.id": target,
        "request.eic_ssh_key_sent": name == "SendSSHPublicKey",
        "request.eic_private_ssh_tunnel_opened": name == "OpenTunnel",
    }


def _ssh_source_groups(record: Mapping[str, Any]) -> set[str]:
    if not _valid(record, "AuthorizeSecurityGroupIngress"):
        return set()
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or response.get("_return") is not True
            or not isinstance(request.get("groupId"), str)
            or not _GROUP.fullmatch(request["groupId"])):
        return set()
    permissions = request.get("ipPermissions")
    permissions = permissions.get("items") if isinstance(permissions, Mapping) else None
    if not isinstance(permissions, list):
        return set()
    result = set()
    for permission in permissions:
        if (not isinstance(permission, Mapping) or permission.get("ipProtocol") != "tcp"
                or permission.get("fromPort") != 22 or permission.get("toPort") != 22):
            continue
        groups = permission.get("groups")
        groups = groups.get("items") if isinstance(groups, Mapping) else None
        if isinstance(groups, list):
            result.update(item["groupId"] for item in groups if isinstance(item, Mapping)
                          and isinstance(item.get("groupId"), str)
                          and _GROUP.fullmatch(item["groupId"]))
    return result


def correlate_aws_eic_ssh_ingress(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    creations, ingresses = [], []
    for record in records:
        when = _time(record)
        if when is None:
            continue
        created = _created(record)
        if created is not None:
            creations.append((record, when, created[0], created[1]))
        groups = _ssh_source_groups(record)
        if groups:
            ingresses.append((record, when, groups))
    result = []
    for ingress, when, groups in ingresses:
        for creation, created_at, endpoint_id, endpoint_groups in creations:
            if (creation["recipientAccountId"] != ingress["recipientAccountId"]
                    or creation["awsRegion"] != ingress["awsRegion"]
                    or not created_at - timedelta(minutes=15) <= when <= created_at + timedelta(hours=1)
                    or not groups & endpoint_groups):
                continue
            result.append({
                "cloud.provider": "aws", "event.source": "ec2.amazonaws.com",
                "event.name": "AuthorizeSecurityGroupIngress", "event.outcome": "success",
                "event.id": ingress.get("eventID"), "event.time": ingress.get("eventTime"),
                "account.id": ingress["recipientAccountId"], "actor.id": _actor(ingress),
                "target.id": ingress["requestParameters"]["groupId"],
                "request.eic_endpoint_ssh_ingress": True,
                "related.endpoint_id": endpoint_id,
            })
            break
    return result
