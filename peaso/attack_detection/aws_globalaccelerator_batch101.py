"""Successful Global Accelerator configuration changes from management events."""

from collections.abc import Mapping
from typing import Any


def _obj(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _port_range(value: Any) -> bool:
    return (isinstance(value, list) and bool(value)
            and all(isinstance(x, Mapping) and isinstance(x.get("fromPort"), int)
                    and not isinstance(x.get("fromPort"), bool)
                    and isinstance(x.get("toPort"), int)
                    and not isinstance(x.get("toPort"), bool)
                    and 1 <= x["fromPort"] <= x["toPort"] <= 65535 for x in value))


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "globalaccelerator.amazonaws.com"
            or name not in {"UpdateEndpointGroup", "UpdateListener", "UpdateAccelerator"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    obj_name = {"UpdateEndpointGroup": "endpointGroup", "UpdateListener": "listener",
                "UpdateAccelerator": "accelerator"}[name]
    result = _obj(response.get(obj_name))
    target_key = {"UpdateEndpointGroup": "endpointGroupArn", "UpdateListener": "listenerArn",
                  "UpdateAccelerator": "acceleratorArn"}[name]
    target = request.get(target_key)
    if (not isinstance(target, str) or not target.startswith("arn:")
            or result.get(target_key) != target
            or response.get("errorCode") or response.get("errorMessage")):
        return None
    region = record.get("awsRegion")
    account = record.get("recipientAccountId")
    identity = _obj(record.get("userIdentity"))
    actor = identity.get("arn")
    if (not isinstance(region, str) or not region
            or not isinstance(account, str) or len(account) != 12 or not account.isdigit()
            or identity.get("accountId") != account
            or not isinstance(actor, str) or not actor):
        return None
    flags = {
        "request.ga_traffic_dial_zero": name == "UpdateEndpointGroup"
            and request.get("trafficDialPercentage") == 0
            and not isinstance(request.get("trafficDialPercentage"), bool)
            and result.get("trafficDialPercentage") == 0,
        "request.ga_health_port_changed": name == "UpdateEndpointGroup"
            and isinstance(request.get("healthCheckPort"), int)
            and not isinstance(request.get("healthCheckPort"), bool)
            and 1 <= request["healthCheckPort"] <= 65535
            and result.get("healthCheckPort") == request["healthCheckPort"],
        "request.ga_port_override_added": name == "UpdateEndpointGroup"
            and isinstance(request.get("portOverrides"), list)
            and bool(request.get("portOverrides"))
            and request.get("portOverrides") == result.get("portOverrides")
            and all(isinstance(x, Mapping) and isinstance(x.get("listenerPort"), int)
                    and isinstance(x.get("endpointPort"), int)
                    and not isinstance(x.get("listenerPort"), bool)
                    and not isinstance(x.get("endpointPort"), bool)
                    and 1 <= x["listenerPort"] <= 65535
                    and 1 <= x["endpointPort"] <= 65535
                    and x["listenerPort"] != x["endpointPort"]
                    for x in request.get("portOverrides", [])),
        "request.ga_listener_ports_updated": name == "UpdateListener"
            and _port_range(request.get("portRanges"))
            and request.get("portRanges") == result.get("portRanges"),
        "request.ga_listener_udp_selected": name == "UpdateListener"
            and request.get("protocol") == "UDP" and result.get("protocol") == "UDP",
        "request.ga_accelerator_disabled": name == "UpdateAccelerator"
            and request.get("enabled") is False and result.get("enabled") is False,
    }
    if not any(flags.values()):
        return None
    return {"cloud.provider": "aws", "event.source": record["eventSource"],
            "event.name": name, "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": actor, "target.id": target,
            **flags}
