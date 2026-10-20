"""API Gateway HTTP proxy integration and bulk REST key-value reads."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse


def _http_uri(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 2048:
        return False
    parsed = urlparse(value)
    return (parsed.scheme in {"http", "https"} and bool(parsed.hostname)
            and not parsed.username and not parsed.password and not parsed.fragment)


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "apigateway.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"UpdateIntegration", "GetApiKeys"}:
        return None
    is_read = name == "GetApiKeys"
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not is_read):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    response = record.get("responseElements")
    target = record.get("recipientAccountId")
    integration_changed = False
    bulk_value_read = False
    if name == "UpdateIntegration":
        if not isinstance(response, Mapping):
            return None
        api_id, integration_id, uri = (request.get("apiId"), request.get("integrationId"),
                                       request.get("integrationUri"))
        if not isinstance(api_id, str) or not api_id or not isinstance(integration_id, str) or not integration_id:
            return None
        target = f"{api_id}/{integration_id}"
        integration_changed = (not failed and _http_uri(uri)
                               and response.get("integrationId") == integration_id
                               and response.get("integrationType") == "HTTP_PROXY"
                               and response.get("integrationUri") == uri)
    else:
        bulk_value_read = not failed and request.get("includeValues") is True
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": "apigateway.amazonaws.com",
            "event.name": name, "event.outcome": "failure" if failed else "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": record.get("recipientAccountId"), "actor.id": identity.get("arn"),
            "target.id": target,
            "request.apigateway_http_proxy_integration_uri_updated": integration_changed,
            "request.apigateway_rest_bulk_key_values_requested": bulk_value_read}
