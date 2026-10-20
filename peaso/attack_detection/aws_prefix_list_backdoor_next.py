"""Recognize customer-managed prefix list changes referenced by security groups."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import ipaddress
import re
from typing import Any


_PREFIX_ID = re.compile(r"pl-[0-9a-f]+\Z")
_PREFIX_ARN = re.compile(r"arn:aws:ec2:([a-z0-9-]+):(\d{12}):prefix-list/(pl-[0-9a-f]+)\Z")


def _items(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    if isinstance(value, Mapping):
        if "Cidr" in value:
            return [value]
        if "items" in value:
            return _items(value["items"])
        if "item" in value:
            return _items(value["item"])
    return []


def _cidrs(value: Any, family: str) -> list[str] | None:
    entries = _items(value)
    if not entries:
        return []
    result = []
    for entry in entries:
        cidr = entry.get("Cidr")
        try:
            network = ipaddress.ip_network(cidr, strict=True)
        except (TypeError, ValueError):
            return None
        if (family == "IPv4" and network.version != 4) or (family == "IPv6" and network.version != 6):
            return None
        result.append(str(network))
    return result if len(result) == len(set(result)) else None


def _modified(record: Mapping[str, Any]) -> tuple[str, str, str, list[str], list[str]] | None:
    if (record.get("eventSource") != "ec2.amazonaws.com"
            or record.get("eventName") != "ModifyManagedPrefixList"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    request = request.get("ModifyManagedPrefixListRequest")
    response = response.get("ModifyManagedPrefixListResponse")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    result = response.get("prefixList")
    if not isinstance(result, Mapping):
        return None
    prefix_id, account, region = request.get("PrefixListId"), record.get("recipientAccountId"), record.get("awsRegion")
    arn = result.get("prefixListArn")
    match = _PREFIX_ARN.fullmatch(arn) if isinstance(arn, str) else None
    family = result.get("addressFamily")
    if (not isinstance(prefix_id, str) or _PREFIX_ID.fullmatch(prefix_id) is None
            or not match or match.group(1) != region or match.group(2) != account
            or match.group(3) != prefix_id or result.get("prefixListId") != prefix_id
            or family not in {"IPv4", "IPv6"}
            or result.get("state") not in {"modify-in-progress", "modify-complete"}):
        return None
    added = _cidrs(request.get("AddEntry"), family)
    removed = _cidrs(request.get("RemoveEntry"), family)
    if added is None or removed is None or not (added or removed):
        return None
    return prefix_id, arn, account, added, removed


def _actor(record: Mapping[str, Any]) -> str | None:
    identity = record.get("userIdentity")
    return identity.get("arn") if isinstance(identity, Mapping) and isinstance(identity.get("arn"), str) else None


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result if result.tzinfo else None


def normalize_aws_prefix_list_backdoor(record: Mapping[str, Any]) -> dict[str, Any] | None:
    parsed = _modified(record)
    if parsed is None:
        return None
    _, arn, account, added, removed = parsed
    return {
        "cloud.provider": "aws", "event.source": "ec2.amazonaws.com",
        "event.name": "ModifyManagedPrefixList", "event.outcome": "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": _actor(record), "target.id": arn,
        "request.prefix_list_entry_added": bool(added),
        "request.prefix_list_world_cidr_added": any(cidr in {"0.0.0.0/0", "::/0"} for cidr in added),
        "request.prefix_list_entry_replaced": bool(added and removed),
    }


def _references(record: Mapping[str, Any]) -> set[str]:
    if (record.get("eventSource") != "ec2.amazonaws.com"
            or record.get("eventName") not in {"AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return set()
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or response.get("_return") is not True):
        return set()
    permissions = request.get("ipPermissions")
    permissions = permissions.get("items") if isinstance(permissions, Mapping) else None
    if not isinstance(permissions, list):
        return set()
    result = set()
    for permission in permissions:
        if not isinstance(permission, Mapping):
            continue
        prefix_lists = permission.get("prefixListIds")
        entries = prefix_lists.get("items") if isinstance(prefix_lists, Mapping) else None
        if not isinstance(entries, list):
            continue
        for item in entries:
            prefix_id = item.get("prefixListId") if isinstance(item, Mapping) else None
            if isinstance(prefix_id, str) and _PREFIX_ID.fullmatch(prefix_id):
                result.add(prefix_id)
    return result


def correlate_aws_prefix_list_sg_reference(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    references = []
    modifications = []
    for record in records:
        when = _time(record.get("eventTime"))
        account, region = record.get("recipientAccountId"), record.get("awsRegion")
        if when is None or not isinstance(account, str) or not isinstance(region, str):
            continue
        for prefix_id in _references(record):
            references.append((when, account, region, prefix_id))
        parsed = _modified(record)
        if parsed is not None and parsed[3]:
            modifications.append((when, account, region, parsed[0], parsed[1], record))
    result = []
    for when, account, region, prefix_id, arn, record in modifications:
        if not any((ref_account, ref_region, ref_id) == (account, region, prefix_id)
                   and ref_time <= when <= ref_time + timedelta(minutes=30)
                   for ref_time, ref_account, ref_region, ref_id in references):
            continue
        result.append({
            "cloud.provider": "aws", "event.source": "ec2.amazonaws.com",
            "event.name": "ModifyManagedPrefixList", "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": _actor(record), "target.id": arn,
            "request.prefix_list_sg_referenced_entry_added": True,
        })
    return result
