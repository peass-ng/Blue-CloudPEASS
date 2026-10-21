"""Normalize EC2 EIP and secondary IPv4 reassignment control-plane evidence."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import ipaddress
import re
from typing import Any

_ID = re.compile(r"(?:eipalloc|eipassoc|eni|sg)-[0-9a-f]+\Z")
_ACCOUNT = re.compile(r"\d{12}\Z")


def _valid_id(value: Any, prefix: str) -> bool:
    return isinstance(value, str) and value.startswith(prefix + "-") and _ID.fullmatch(value) is not None


def _base(record: Mapping[str, Any], names: set[str]) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    if (record.get("eventSource") != "ec2.amazonaws.com" or record.get("eventName") not in names
            or record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping) or response.get("_return") is not True:
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if not isinstance(account, str) or _ACCOUNT.fullmatch(account) is None or not isinstance(region, str):
        return None
    return request, response


def _actor(record: Mapping[str, Any]) -> str | None:
    identity = record.get("userIdentity")
    return identity.get("arn") if isinstance(identity, Mapping) and isinstance(identity.get("arn"), str) else None


def _normalized(record: Mapping[str, Any], target: str, flag: str) -> dict[str, Any]:
    return {"cloud.provider": "aws", "event.source": "ec2.amazonaws.com",
            "event.name": record["eventName"], "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": record["recipientAccountId"], "actor.id": _actor(record),
            "target.id": target, flag: True}


def _time(record: Mapping[str, Any]) -> datetime | None:
    value = record.get("eventTime")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def _ipset(request: Mapping[str, Any]) -> set[str] | None:
    values = request.get("privateIpAddressesSet")
    values = values.get("items") if isinstance(values, Mapping) else None
    if not isinstance(values, list) or not values:
        return None
    result = set()
    for item in values:
        value = item.get("privateIpAddress") if isinstance(item, Mapping) else None
        try:
            parsed = ipaddress.IPv4Address(value)
        except (TypeError, ValueError, ipaddress.AddressValueError):
            return None
        if not parsed.is_private:
            return None
        result.add(str(parsed))
    return result if len(result) == len(values) else None


def _associate(record: Mapping[str, Any]) -> tuple[str, str, str | None] | None:
    parsed = _base(record, {"AssociateAddress"})
    if parsed is None:
        return None
    request, response = parsed
    allocation, eni, association = request.get("allocationId"), request.get("networkInterfaceId"), response.get("associationId")
    if not (_valid_id(allocation, "eipalloc") and _valid_id(eni, "eni")
            and _valid_id(association, "eipassoc")):
        return None
    return allocation, eni, association


def _ip_change(record: Mapping[str, Any]) -> tuple[str, set[str], bool] | None:
    parsed = _base(record, {"AssignPrivateIpAddresses", "UnassignPrivateIpAddresses"})
    if parsed is None:
        return None
    request, _ = parsed
    eni, ips = request.get("networkInterfaceId"), _ipset(request)
    if not _valid_id(eni, "eni") or not ips:
        return None
    return eni, ips, request.get("allowReassignment") is True


def normalize_aws_address_reassignment(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if name == "AssociateAddress":
        parsed = _associate(record)
        if parsed is not None and record["requestParameters"].get("allowReassociation") is True:
            return _normalized(record, parsed[0], "request.eip_allow_reassociation_requested")
    if name == "DisassociateAddress":
        parsed = _base(record, {"DisassociateAddress"})
        if parsed is not None and _valid_id(parsed[0].get("associationId"), "eipassoc"):
            return _normalized(record, parsed[0]["associationId"], "request.eip_disassociated")
    if name in {"AssignPrivateIpAddresses", "UnassignPrivateIpAddresses"}:
        parsed = _ip_change(record)
        if parsed is not None:
            eni, _, reassignment = parsed
            if name == "UnassignPrivateIpAddresses":
                return _normalized(record, eni, "request.secondary_private_ip_unassigned")
            if reassignment:
                return _normalized(record, eni, "request.secondary_private_ip_reassignment_requested")
    return None


def _sg_allowlisted_ips(record: Mapping[str, Any]) -> set[str]:
    parsed = _base(record, {"AuthorizeSecurityGroupIngress"})
    if parsed is None or not _valid_id(parsed[0].get("groupId"), "sg"):
        return set()
    permissions = parsed[0].get("ipPermissions")
    permissions = permissions.get("items") if isinstance(permissions, Mapping) else None
    if not isinstance(permissions, list):
        return set()
    ips = set()
    for permission in permissions:
        if not isinstance(permission, Mapping):
            continue
        ranges = permission.get("ipRanges")
        ranges = ranges.get("items") if isinstance(ranges, Mapping) else None
        if not isinstance(ranges, list):
            continue
        for entry in ranges:
            cidr = entry.get("cidrIp") if isinstance(entry, Mapping) else None
            try:
                net = ipaddress.IPv4Network(cidr, strict=True)
            except (TypeError, ValueError):
                continue
            if net.prefixlen == 32 and net.network_address.is_private:
                ips.add(str(net.network_address))
    return ips


def correlate_aws_address_reassignment(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    associations = []
    unassignments = []
    assignments = []
    allowlists = []
    for record in records:
        when = _time(record)
        if when is None:
            continue
        account, region = record.get("recipientAccountId"), record.get("awsRegion")
        if not isinstance(account, str) or not isinstance(region, str):
            continue
        parsed = _associate(record)
        if parsed is not None:
            associations.append((when, account, region, parsed[0], parsed[1], record))
        ip_change = _ip_change(record)
        if ip_change is not None:
            row = (when, account, region, ip_change[0], ip_change[1], record)
            if record.get("eventName") == "UnassignPrivateIpAddresses":
                unassignments.append(row)
            else:
                assignments.append(row)
        ips = _sg_allowlisted_ips(record)
        if ips:
            allowlists.append((when, account, region, ips))
    result = []
    window = timedelta(minutes=30)
    for when, account, region, allocation, eni, record in associations:
        if any(a == account and g == region and alloc == allocation and prev_eni != eni
               and prev_time < when <= prev_time + window
               for prev_time, a, g, alloc, prev_eni, _ in associations):
            result.append(_normalized(record, allocation, "request.eip_moved_between_interfaces"))
    for when, account, region, eni, ips, record in assignments:
        moved = any(a == account and g == region and prev_eni != eni and bool(ips & prev_ips)
                    and prev_time < when <= prev_time + window
                    for prev_time, a, g, prev_eni, prev_ips, _ in unassignments + assignments)
        if moved:
            result.append(_normalized(record, eni, "request.secondary_private_ip_moved_between_interfaces"))
            if any(a == account and g == region and bool(ips & allowed)
                   and allow_time <= when <= allow_time + window
                   for allow_time, a, g, allowed in allowlists):
                result.append(_normalized(record, eni, "request.allowlisted_secondary_private_ip_moved"))
    return result
