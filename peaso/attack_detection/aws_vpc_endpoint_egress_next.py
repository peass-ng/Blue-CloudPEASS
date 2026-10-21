"""CloudTrail signals for service paths opened through VPC endpoints."""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any


_ID = re.compile(r"(?:vpce|vpc|rtb|subnet)-[0-9a-f]{8,17}\Z")


def _id(value: Any, prefix: str) -> bool:
    return isinstance(value, str) and value.startswith(prefix + "-") and _ID.fullmatch(value) is not None


def _items(value: Any, prefix: str) -> bool:
    if isinstance(value, str):
        return _id(value, prefix)
    if not isinstance(value, Mapping) or not _id(value.get("content"), prefix):
        return False
    return True


def _broad_s3_policy(value: Any) -> bool:
    if value is None:
        return True  # AWS attaches its full-access default policy.
    if not isinstance(value, str):
        return False
    try:
        document = json.loads(value)
    except ValueError:
        return False
    statements = document.get("Statement") if isinstance(document, Mapping) else None
    if isinstance(statements, Mapping):
        statements = [statements]
    if not isinstance(statements, list):
        return False
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        if statement.get("Principal") not in ("*", {"AWS": "*"}):
            continue
        actions, resources = statement.get("Action"), statement.get("Resource")
        if isinstance(actions, list):
            actions = set(actions) if all(isinstance(a, str) for a in actions) else set()
        if isinstance(resources, list):
            resources = set(resources) if all(isinstance(r, str) for r in resources) else set()
        if ((actions in ("*", "s3:*") or isinstance(actions, set) and actions & {"*", "s3:*"})
                and (resources == "*" or isinstance(resources, set) and "*" in resources)):
            return True
    return False


def normalize_aws_vpc_endpoint_egress(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "ec2.amazonaws.com"
            or name not in {"CreateVpcEndpoint", "ModifyVpcEndpoint"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if (not isinstance(account, str) or re.fullmatch(r"\d{12}", account) is None
            or not isinstance(region, str) or not region):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    req, res = request.get(name + "Request"), response.get(name + "Response")
    if not isinstance(req, Mapping) or not isinstance(res, Mapping):
        return None
    create = name == "CreateVpcEndpoint"
    endpoint = res.get("vpcEndpoint") if create else None
    if create:
        if not isinstance(endpoint, Mapping):
            return None
        target = endpoint.get("vpcEndpointId")
        accepted = (_id(target, "vpce") and _id(req.get("VpcId"), "vpc")
                    and endpoint.get("vpcId") == req["VpcId"]
                    and endpoint.get("ownerId") == account
                    and endpoint.get("serviceName") == req.get("ServiceName")
                    and endpoint.get("vpcEndpointType") == req.get("VpcEndpointType"))
    else:
        target = req.get("VpcEndpointId")
        accepted = _id(target, "vpce") and res.get("return") is True
    if not accepted:
        return None
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "ec2.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": target,
        "request.vpc_s3_gateway_egress_created": bool(
            create and req.get("ServiceName") == f"com.amazonaws.{region}.s3"
            and req.get("VpcEndpointType") == "Gateway"
            and _items(req.get("RouteTableId"), "rtb")
            and _broad_s3_policy(req.get("PolicyDocument"))),
        "request.vpc_endpoint_route_table_added": bool(
            not create and _items(req.get("AddRouteTableId"), "rtb")),
        "request.vpc_endpoint_private_dns_enabled": bool(
            not create and req.get("PrivateDnsEnabled") is True),
        "request.vpc_endpoint_subnet_added": bool(
            not create and _items(req.get("AddSubnetId"), "subnet")),
    }
