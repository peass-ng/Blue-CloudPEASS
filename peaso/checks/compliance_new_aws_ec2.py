"""Signed EC2 configuration predicates over complete same-Region snapshots."""
from __future__ import annotations

import ipaddress

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects, optional
from .fixtures import CASES


def _instance(item, index):
    complete_items(index, "instance")
    state = get(item, "State.Name", str)
    if state == "terminated":
        return None
    if state not in {"running", "stopped"}:
        raise Unavailable("instance is not in a stable running or stopped state")
    provenance = get(item, "_provenance", dict)
    if provenance.get("operation") != "ec2:DescribeInstances" or provenance.get("native_response_complete") is not True:
        raise Unavailable("complete native DescribeInstances response not proven")
    interfaces = list_of_objects(get(item, "NetworkInterfaces", list))
    if not interfaces:
        raise Unavailable("instance network interfaces unavailable")
    return interfaces


@register("aws_cis_ec2_default_security_group_not_attached", "aws", "hardening", "instance",
          "EC2 instance uses no default security group on attached interfaces",
          "medium", "SC-7",
          "Replace any attached default security group with approved application security groups after reviewing required traffic.",
          dependencies=["instance", "security_group"])
def no_default_group(item, index):
    interfaces = _instance(item, index)
    if interfaces is None:
        return "NOT_APPLICABLE", {"reason": "terminated instance"}
    instance_id = get(item, "InstanceId", str)
    vpc_id = get(item, "VpcId", str)
    groups = {}
    for group in complete_items(index, "security_group"):
        key = (get(group, "VpcId", str), get(group, "GroupId", str))
        if key in groups:
            raise Unavailable("duplicate security group identity")
        groups[key] = get(group, "GroupName", str)
    attached = set()
    for interface in interfaces:
        if get(interface, "VpcId", str) != vpc_id:
            raise Unavailable("attached interface VPC differs from instance")
        values = list_of_objects(get(interface, "Groups", list))
        if not values:
            raise Unavailable("attached interface group list empty")
        for value in values:
            attached.add(get(value, "GroupId", str))
    if not attached:
        raise Unavailable("no attached security-group identities")
    missing = [group_id for group_id in attached if (vpc_id, group_id) not in groups]
    if missing:
        return unknown("attached group missing from complete same-Region security-group inventory",
                       instance_id=instance_id, missing_group_ids=sorted(missing))
    defaults = sorted(group_id for group_id in attached if groups[(vpc_id, group_id)] == "default")
    return result(bool(defaults), instance_id=instance_id, vpc_id=vpc_id,
                  default_group_ids=defaults, attached_group_count=len(attached))


@register("aws_g6_ec2_instance_no_public_ipv6", "aws", "exposure", "instance",
          "EC2 instance has no globally routable IPv6 address assigned",
          "high", "SC-7",
          "Review each assigned global IPv6 address and remove unneeded assignments after checking dependent traffic.",
          dependencies=["instance"])
def no_global_ipv6(item, index):
    interfaces = _instance(item, index)
    if interfaces is None:
        return "NOT_APPLICABLE", {"reason": "terminated instance"}
    instance_id = get(item, "InstanceId", str)
    globally_routable = []
    for interface in interfaces:
        interface_id = get(interface, "NetworkInterfaceId", str)
        # DescribeInstances is a complete native response; EC2 can omit this
        # optional list when an interface has no IPv6 assignment.
        addresses = list_of_objects(optional(interface, "Ipv6Addresses", [], list))
        for row in addresses:
            literal = get(row, "Ipv6Address", str)
            try:
                parsed = ipaddress.IPv6Address(literal)
            except ipaddress.AddressValueError as exc:
                raise Unavailable("malformed assigned IPv6 address") from exc
            if parsed.is_global:
                globally_routable.append({"network_interface_id": interface_id, "ipv6_address": literal})
    return result(bool(globally_routable), instance_id=instance_id,
                  globally_routable_ipv6=globally_routable,
                  semantics="Address allocation only; ingress and listener reachability are separate checks")


def _ec2_row(group_id="sg-app", ipv6=()):
    return {"InstanceId": "i-inert", "State": {"Name": "running"}, "VpcId": "vpc-1",
        "NetworkInterfaces": [{"NetworkInterfaceId": "eni-1", "VpcId": "vpc-1",
            "Groups": [{"GroupId": group_id}],
            "Ipv6Addresses": [{"Ipv6Address": address} for address in ipv6]}],
        "_provenance": {"operation": "ec2:DescribeInstances", "native_response_complete": True}}


def _ec2_index(row, groups=()):
    scope = "111111111111/us-east-1"
    return {"collections": {
        "instance": [{"type": "instance", "scope": scope, "status": "collected", "items": [row]}],
        "security_group": [{"type": "security_group", "scope": scope, "status": "collected",
            "items": list(groups)}]},
        "instance": [{"type": "instance", "scope": scope, "data": row}],
        "security_group": [{"type": "security_group", "scope": scope, "data": group}
            for group in groups]}


_app_group = {"GroupId": "sg-app", "GroupName": "application", "VpcId": "vpc-1"}
_default_group = {"GroupId": "sg-default", "GroupName": "default", "VpcId": "vpc-1"}
_clean, _default = _ec2_row(), _ec2_row("sg-default")
CASES["aws_cis_ec2_default_security_group_not_attached"] = {
    "pass": _clean, "pass_index": _ec2_index(_clean, [_app_group]),
    "fail": _default, "fail_index": _ec2_index(_default, [_default_group]),
    "unknown": _clean, "unknown_index": _ec2_index(_clean, []),
    "index": _ec2_index(_clean, [_app_group]),
}
_private, _public = _ec2_row(ipv6=("fd00::1",)), _ec2_row(ipv6=("2600:1f18:abcd::1",))
CASES["aws_g6_ec2_instance_no_public_ipv6"] = {
    "pass": _private, "pass_index": _ec2_index(_private),
    "fail": _public, "fail_index": _ec2_index(_public),
    "unknown": {**_private, "_provenance": {"operation": "ec2:DescribeInstances",
        "native_response_complete": False}},
    "index": _ec2_index(_private),
}
