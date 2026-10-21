"""Additional Global Accelerator management signals and endpoint replacement."""

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any


def _obj(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _common(record: Mapping[str, Any]) -> tuple | None:
    name = record.get("eventName")
    read = name == "ListCustomRoutingPortMappings"
    if (record.get("eventSource") != "globalaccelerator.amazonaws.com"
            or name not in {"UpdateListener", "UpdateEndpointGroup", "UpdateAcceleratorAttributes",
                            "ListCustomRoutingPortMappings", "AllowCustomRoutingTraffic",
                            "DenyCustomRoutingTraffic"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not read
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity = _obj(record.get("userIdentity"))
    actor = identity.get("arn")
    if (not isinstance(account, str) or len(account) != 12 or not account.isdigit()
            or identity.get("accountId") != account
            or region != "us-west-2" or not isinstance(actor, str) or not actor
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    key = "listenerArn" if name == "UpdateListener" else "acceleratorArn" if name in {
        "UpdateAcceleratorAttributes", "ListCustomRoutingPortMappings"} else "endpointGroupArn"
    target = request.get(key)
    if (not isinstance(target, str)
            or not target.startswith(f"arn:aws:globalaccelerator::{account}:accelerator/")):
        return None
    response = _obj(record.get("responseElements"))
    if response.get("errorCode") or response.get("errorMessage"):
        return None
    return name, account, actor, target, request, response


def _same_endpoints(request: Any, response: Any) -> set[str] | None:
    if not isinstance(request, list) or not isinstance(response, list) or not request or not response:
        return None
    requested = {}
    for value in request:
        if not isinstance(value, Mapping): return None
        endpoint, weight = value.get("endpointId"), value.get("weight")
        if (not isinstance(endpoint, str) or not endpoint
                or not isinstance(weight, int) or isinstance(weight, bool)
                or not 0 <= weight <= 255): return None
        requested[endpoint] = weight
    returned = {}
    for value in response:
        if not isinstance(value, Mapping): return None
        endpoint, weight = value.get("endpointId"), value.get("weight")
        if not isinstance(endpoint, str) or not isinstance(weight, int): return None
        returned[endpoint] = weight
    return set(requested) if requested == returned and len(requested) == len(request) == len(response) else None


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    parsed = _common(record)
    if parsed is None:return None
    name, account, actor, target, request, response = parsed
    listener = _obj(response.get("listener"))
    group = _obj(response.get("endpointGroup"))
    attrs = _obj(response.get("acceleratorAttributes"))
    endpoints = (_same_endpoints(request.get("endpointConfigurations"), group.get("endpointDescriptions"))
                 if name == "UpdateEndpointGroup" and group.get("endpointGroupArn") == target else None)
    flags = {
        "request.ga_source_ip_affinity": name == "UpdateListener"
            and listener.get("listenerArn") == target
            and request.get("clientAffinity") == "SOURCE_IP"
            and listener.get("clientAffinity") == "SOURCE_IP",
        "request.ga_endpoint_weight_zero": name == "UpdateEndpointGroup"
            and endpoints is not None
            and any(x.get("weight") == 0 for x in request.get("endpointConfigurations", [])),
        "request.ga_flow_logs_disabled": name == "UpdateAcceleratorAttributes"
            and request.get("flowLogsEnabled") is False
            and attrs.get("flowLogsEnabled") is False,
        "request.ga_custom_mappings_read": name == "ListCustomRoutingPortMappings"
            and isinstance(request.get("endpointGroupArn"), str)
            and request["endpointGroupArn"].startswith(f"arn:aws:globalaccelerator::{account}:accelerator/")
            and not response,
        "request.ga_custom_allow_all": name == "AllowCustomRoutingTraffic"
            and isinstance(request.get("endpointId"), str)
            and request["endpointId"].startswith("subnet-")
            and request.get("allowAllTrafficToEndpoint") is True
            and not response,
        "request.ga_custom_deny_all": name == "DenyCustomRoutingTraffic"
            and isinstance(request.get("endpointId"), str)
            and request["endpointId"].startswith("subnet-")
            and request.get("denyAllTrafficToEndpoint") is True
            and not response,
    }
    if not any(flags.values()):return None
    return {"cloud.provider": "aws", "event.source": record["eventSource"],
            "event.name": name, "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": actor, "target.id": target, **flags}


def correlate_replacement(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    writes = []
    for record in records:
        parsed = _common(record)
        if parsed is None or parsed[0] != "UpdateEndpointGroup":continue
        _, account, actor, target, request, response = parsed
        group = _obj(response.get("endpointGroup"))
        if group.get("endpointGroupArn") != target:continue
        endpoints = _same_endpoints(request.get("endpointConfigurations"), group.get("endpointDescriptions"))
        if endpoints is None:continue
        try:
            raw = record.get("eventTime")
            when = datetime.fromisoformat(raw.replace("Z", "+00:00")) if isinstance(raw, str) else None
            if when is None or when.tzinfo is None:continue
            when = when.astimezone(timezone.utc)
        except ValueError:continue
        writes.append((when, account, actor, target, endpoints, record))
    result=[]
    previous={}
    for when,account,actor,target,endpoints,record in sorted(writes,key=lambda x:x[0]):
        key=(account,actor,target)
        old=previous.get(key)
        if old and timedelta(0) < when-old[0] <= timedelta(hours=1) and old[1].isdisjoint(endpoints):
            result.append({"cloud.provider":"aws", "event.source":"globalaccelerator.amazonaws.com",
                           "event.name":"GlobalAcceleratorEndpointGroupReplaced", "event.outcome":"success",
                           "event.id":record["eventID"], "event.time":record.get("eventTime"),
                           "account.id":account, "actor.id":actor, "target.id":target,
                           "request.ga_endpoint_group_replaced":True,
                           "correlation_evidence":{"source_event_id":old[2]}})
        previous[key]=(when,endpoints,record["eventID"])
    return result
