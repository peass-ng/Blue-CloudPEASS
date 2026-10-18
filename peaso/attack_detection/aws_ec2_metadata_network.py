"""Normalize accepted EC2 metadata and security-group ingress changes."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from .aws_security_controls import _arn, _event_time


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+\Z")
_INSTANCE = re.compile(r"i-[0-9a-f]{8}(?:[0-9a-f]{9})?\Z")
_GROUP = re.compile(r"sg-[0-9a-f]{8}(?:[0-9a-f]{9})?\Z")


def _public_ssh(permission: Any) -> bool:
    if not isinstance(permission, Mapping):
        return False
    protocol = permission.get("ipProtocol")
    if protocol == "-1":
        port_allowed = True
    else:
        first, last = permission.get("fromPort"), permission.get("toPort")
        port_allowed = (protocol == "tcp" and type(first) is int and type(last) is int
                        and first <= 22 <= last)
    if not port_allowed:
        return False
    ranges = permission.get("ipRanges")
    items = ranges.get("items") if isinstance(ranges, Mapping) else None
    return bool(isinstance(items, list) and any(isinstance(item, Mapping)
                and item.get("cidrIp") == "0.0.0.0/0" for item in items))


def normalize_aws_ec2_metadata_network(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Report accepted requests, without inferring credential theft or reachability."""
    name = record.get("eventName")
    if (record.get("eventSource") != "ec2.amazonaws.com"
            or name not in {"ModifyInstanceMetadataOptions", "AuthorizeSecurityGroupIngress"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") not in (None, True)
            or record.get("readOnly") not in (None, False)
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request = record.get("requestParameters")
    response = record.get("responseElements")
    identity = record.get("userIdentity")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping) or not isinstance(identity, Mapping):
        return None
    if response.get("errorCode") or response.get("errorMessage"):
        return None
    account = record.get("recipientAccountId")
    region = record.get("awsRegion")
    actor_arn = identity.get("arn")
    actor = _arn(actor_arn)
    event_id = record.get("eventID")
    event_time = _event_time(record.get("eventTime"))
    try:
        UUID(event_id)
    except (TypeError, ValueError, AttributeError):
        return None
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or actor is None or actor[4] != account or identity.get("accountId") != account
            or not isinstance(identity.get("type"), str) or not identity["type"]
            or event_time is None):
        return None
    imdsv1_allowed = hop_limit_at_least_two = public_ssh = False
    if name == "ModifyInstanceMetadataOptions":
        details = request.get("ModifyInstanceMetadataOptionsRequest")
        echoed = response.get("ModifyInstanceMetadataOptionsResponse")
        if not isinstance(details, Mapping) or not isinstance(echoed, Mapping):
            return None
        instance = details.get("InstanceId")
        if not isinstance(instance, str) or not _INSTANCE.fullmatch(instance) or echoed.get("instanceId") != instance:
            return None
        options = echoed.get("instanceMetadataOptions")
        if not isinstance(options, Mapping) or options.get("state") not in {"pending", "applied"}:
            return None
        imdsv1_allowed = (details.get("HttpTokens") == "optional"
                           and options.get("httpTokens") == "optional")
        hop = details.get("HttpPutResponseHopLimit")
        hop_limit_at_least_two = (type(hop) is int and 2 <= hop <= 64
                                  and options.get("httpPutResponseHopLimit") == hop)
        target = f"arn:{actor[1]}:ec2:{region}:{account}:instance/{instance}"
    else:
        group = request.get("groupId")
        if not isinstance(group, str) or not _GROUP.fullmatch(group) or response.get("_return") is not True:
            return None
        permissions = request.get("ipPermissions")
        items = permissions.get("items") if isinstance(permissions, Mapping) else None
        public_ssh = bool(isinstance(items, list) and any(_public_ssh(item) for item in items))
        target = f"arn:{actor[1]}:ec2:{region}:{account}:security-group/{group}"
    if not any((imdsv1_allowed, hop_limit_at_least_two, public_ssh)):
        return None
    return {
        "cloud.provider": "aws", "cloud.region": region,
        "event.source": "ec2.amazonaws.com", "event.name": name,
        "event.outcome": "success", "event.id": event_id, "event.time": event_time,
        "account.id": account, "actor.id": actor_arn, "actor.kind": identity["type"],
        "target.id": target,
        "request.imdsv1_allowed": imdsv1_allowed,
        "request.metadata_hop_limit_at_least_two": hop_limit_at_least_two,
        "request.public_ssh_ingress": public_ssh,
    }
