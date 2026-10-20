"""Private API Gateway execute-api VPC endpoint creation precursor."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_ENDPOINT = re.compile(r"vpce-[0-9a-f]{8,32}\Z")


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "ec2.amazonaws.com"
            or record.get("eventName") != "CreateVpcEndpoint"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    req, res = request.get("CreateVpcEndpointRequest"), response.get("CreateVpcEndpointResponse")
    if not isinstance(req, Mapping) or not isinstance(res, Mapping):
        return None
    endpoint = res.get("vpcEndpoint")
    if not isinstance(endpoint, Mapping):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    endpoint_id = endpoint.get("vpcEndpointId")
    if (not isinstance(account, str) or not account.isdigit() or len(account) != 12
            or not isinstance(region, str) or not region
            or not isinstance(endpoint_id, str) or not _ENDPOINT.fullmatch(endpoint_id)):
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or res.get("errorCode") or res.get("errorMessage"))
    service = f"com.amazonaws.{region}.execute-api"
    selected = (not failed and req.get("ServiceName") == service
                and req.get("VpcEndpointType") == "Interface"
                and isinstance(req.get("VpcId"), str) and bool(req["VpcId"])
                and endpoint.get("vpcId") == req["VpcId"]
                and endpoint.get("serviceName") == service
                and endpoint.get("vpcEndpointType") == "Interface"
                and endpoint.get("ownerId") == account)
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": "ec2.amazonaws.com",
            "event.name": "CreateVpcEndpoint", "event.outcome": "failure" if failed else "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity.get("arn"),
            "target.id": endpoint_id,
            "request.apigateway_execute_api_vpc_endpoint_created": selected}
