"""Accepted launch-template, Auto Scaling, and VPC peering changes."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


_EVENTS = {
    ("ec2.amazonaws.com", "CreateLaunchTemplateVersion"): "launch_template_version_created",
    ("ec2.amazonaws.com", "ModifyLaunchTemplate"): "launch_template_default_changed",
    ("autoscaling.amazonaws.com", "UpdateAutoScalingGroup"): "asg_launch_template_version_changed",
    ("ec2.amazonaws.com", "CreateVpcPeeringConnection"): "vpc_peering_requested",
    ("ec2.amazonaws.com", "AcceptVpcPeeringConnection"): "vpc_peering_accepted",
    ("ec2.amazonaws.com", "CreateRoute"): "vpc_peering_route_created",
    ("ec2.amazonaws.com", "ModifyVpcPeeringConnectionOptions"): "vpc_peering_dns_enabled",
}


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _id(value: Any, prefix: str) -> bool:
    return isinstance(value, str) and value.startswith(prefix) and len(value) > len(prefix)


def normalize_aws_ec2_persistence_batch98(record: Mapping[str, Any]) -> dict[str, Any] | None:
    source, name = record.get("eventSource"), record.get("eventName")
    if not isinstance(source, str) or not isinstance(name, str):
        return None
    flag = _EVENTS.get((source, name))
    if flag is None:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    account = record.get("recipientAccountId")
    if not isinstance(account, str) or len(account) != 12 or not account.isdigit():
        return None
    request = _map(record.get("requestParameters"))
    response = _map(record.get("responseElements"))
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or response.get("errorCode") or response.get("errorMessage"))
    accepted = False
    target = None
    if not failed:
        if name == "CreateLaunchTemplateVersion":
            req = _map(request.get("CreateLaunchTemplateVersionRequest"))
            resp = _map(_map(response.get("CreateLaunchTemplateVersionResponse")).get("launchTemplateVersion"))
            data = _map(req.get("LaunchTemplateData"))
            target = req.get("LaunchTemplateId")
            accepted = (_id(target, "lt-") and resp.get("launchTemplateId") == target
                        and isinstance(resp.get("versionNumber"), int)
                        and resp["versionNumber"] > 1
                        and any(key in data for key in ("UserData", "ImageId", "KeyName")))
        elif name == "ModifyLaunchTemplate":
            req = _map(request.get("ModifyLaunchTemplateRequest"))
            resp = _map(_map(response.get("ModifyLaunchTemplateResponse")).get("launchTemplate"))
            target = req.get("LaunchTemplateId")
            version = req.get("SetDefaultVersion")
            accepted = (_id(target, "lt-") and resp.get("launchTemplateId") == target
                        and str(resp.get("defaultVersionNumber")) == str(version)
                        and isinstance(version, (str, int)) and str(version).isdigit())
        elif name == "UpdateAutoScalingGroup":
            target = request.get("autoScalingGroupName")
            template = _map(request.get("launchTemplate"))
            version = template.get("version")
            accepted = (isinstance(target, str) and bool(target)
                        and _id(template.get("launchTemplateId"), "lt-")
                        and isinstance(version, str) and version.isdigit())
        elif name == "CreateVpcPeeringConnection":
            peer = _map(response.get("vpcPeeringConnection"))
            target = peer.get("vpcPeeringConnectionId")
            accepted = (_id(request.get("vpcId"), "vpc-")
                        and _id(request.get("peerVpcId"), "vpc-")
                        and _id(target, "pcx-")
                        and _map(peer.get("requesterVpcInfo")).get("vpcId") == request.get("vpcId")
                        and _map(peer.get("accepterVpcInfo")).get("vpcId") == request.get("peerVpcId"))
        elif name == "AcceptVpcPeeringConnection":
            target = request.get("vpcPeeringConnectionId")
            peer = _map(response.get("vpcPeeringConnection"))
            accepted = _id(target, "pcx-") and peer.get("vpcPeeringConnectionId") == target
        elif name == "CreateRoute":
            target = request.get("routeTableId")
            accepted = (_id(target, "rtb-")
                        and _id(request.get("vpcPeeringConnectionId"), "pcx-")
                        and isinstance(request.get("destinationCidrBlock"), str)
                        and response.get("_return") is True)
        elif name == "ModifyVpcPeeringConnectionOptions":
            req = _map(request.get("ModifyVpcPeeringConnectionOptionsRequest"))
            resp = _map(response.get("ModifyVpcPeeringConnectionOptionsResponse"))
            target = req.get("VpcPeeringConnectionId")
            dns = _map(req.get("RequesterPeeringConnectionOptions"))
            accepted = (_id(target, "pcx-")
                        and dns.get("AllowDnsResolutionFromRemoteVpc") is True
                        and _map(resp.get("requesterPeeringConnectionOptions")).get("allowDnsResolutionFromRemoteVpc") is True)
    identity = _map(record.get("userIdentity"))
    return {
        "cloud.provider": "aws", "event.source": source, "event.name": name,
        "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": target,
        "request." + flag: bool(accepted),
    }
