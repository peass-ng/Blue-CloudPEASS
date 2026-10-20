"""Lightsail access, public port, and bucket-control signals.

The Lightsail CreateBucketAccessKey CloudTrail response can include a secret.
Only checked booleans and public resource names enter canonical evidence.
"""
from __future__ import annotations
from collections.abc import Mapping
import re
from typing import Any

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{1,254}\Z")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9-]{1,52}[a-z0-9]\Z")


def _world(port: Any) -> bool:
    return (isinstance(port, Mapping) and isinstance(port.get("fromPort"), int)
            and isinstance(port.get("toPort"), int)
            and 0 <= port["fromPort"] <= port["toPort"] <= 65535
            and port.get("protocol") in {"tcp", "udp", "all"}
            and ("0.0.0.0/0" in (port.get("cidrs") or [])
                 or "::/0" in (port.get("ipv6Cidrs") or [])))


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    flags = {"GetInstanceAccessDetails": "request.lightsail_instance_access_details_read",
             "CreateBucketAccessKey": "request.lightsail_bucket_access_key_created",
             "OpenInstancePublicPorts": "request.lightsail_public_port_opened",
             "PutInstancePublicPorts": "request.lightsail_public_ports_replaced_with_world_open",
             "SetResourceAccessForBucket": "request.lightsail_bucket_instance_access_granted",
             "UpdateBucket": "request.lightsail_bucket_public_get_enabled"}
    if (record.get("eventSource") != "lightsail.amazonaws.com" or name not in flags
            or record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name == "GetInstanceAccessDetails")
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region, identity, request = (record.get("recipientAccountId"), record.get("awsRegion"),
                                          record.get("userIdentity"), record.get("requestParameters"))
    if (not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account)
            or not isinstance(region, str) or not region
            or not isinstance(identity, Mapping) or not isinstance(identity.get("arn"), str)
            or identity.get("accountId") not in (None, account)
            or not isinstance(request, Mapping)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str) or not record["eventTime"]):
        return None
    response = record.get("responseElements")
    response = response if isinstance(response, Mapping) else {}
    target = None
    accepted = False
    if name == "GetInstanceAccessDetails":
        target = request.get("instanceName")
        accepted = (isinstance(target, str) and bool(_NAME.fullmatch(target))
                    and request.get("protocol") in (None, "ssh", "rdp"))
    elif name == "CreateBucketAccessKey":
        target = request.get("bucketName")
        key = response.get("accessKey")
        accepted = (isinstance(target, str) and bool(_BUCKET.fullmatch(target))
                    and isinstance(key, Mapping) and isinstance(key.get("accessKeyId"), str)
                    and bool(key["accessKeyId"]) and key.get("status") == "Active")
    elif name in {"OpenInstancePublicPorts", "PutInstancePublicPorts"}:
        target = request.get("instanceName")
        operation = response.get("operation")
        ports = ([request.get("portInfo")] if name == "OpenInstancePublicPorts"
                 else request.get("portInfos"))
        accepted = (isinstance(target, str) and bool(_NAME.fullmatch(target))
                    and isinstance(ports, list) and any(_world(p) for p in ports)
                    and isinstance(operation, Mapping)
                    and operation.get("resourceName") == target
                    and operation.get("status") == "Succeeded")
    elif name == "SetResourceAccessForBucket":
        target, resource = request.get("bucketName"), request.get("resourceName")
        operations = response.get("operations")
        accepted = (isinstance(target, str) and bool(_BUCKET.fullmatch(target))
                    and isinstance(resource, str) and bool(_NAME.fullmatch(resource))
                    and request.get("access") == "allow"
                    and isinstance(operations, list)
                    and any(isinstance(op, Mapping) and op.get("resourceName") == target
                            and op.get("status") == "Succeeded" for op in operations)
                    and any(isinstance(op, Mapping) and op.get("resourceName") == resource
                            and op.get("status") == "Succeeded" for op in operations))
    elif name == "UpdateBucket":
        target, rules = request.get("bucketName"), request.get("accessRules")
        result = response.get("bucket")
        accepted = (isinstance(target, str) and bool(_BUCKET.fullmatch(target))
                    and isinstance(rules, Mapping) and rules.get("getObject") == "public"
                    and isinstance(result, Mapping) and result.get("name") == target
                    and isinstance(result.get("accessRules"), Mapping)
                    and result["accessRules"].get("getObject") == "public")
    if not accepted:
        return None
    return {"cloud.provider": "aws", "event.source": "lightsail.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record["eventTime"],
            "account.id": account, "actor.id": identity["arn"], "target.id": target,
            flags[name]: True}
