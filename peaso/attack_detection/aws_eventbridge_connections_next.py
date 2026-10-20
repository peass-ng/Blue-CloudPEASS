"""Accepted EventBridge connection and API destination changes."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def normalize_aws_eventbridge_connections(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "events.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"UpdateApiDestination", "UpdateConnection", "DeauthorizeConnection"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    target = request.get("name")
    if not isinstance(target, str) or not target:
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if not isinstance(account, str) or len(account) != 12 or not account.isdigit():
        return None
    if not isinstance(region, str) or not region:
        return None
    expected_arn = f"arn:aws:events:{region}:{account}:"
    arn = response.get("apiDestinationArn" if name == "UpdateApiDestination" else "connectionArn")
    arn_prefix = expected_arn + ("api-destination/" if name == "UpdateApiDestination" else "connection/") + target + "/"
    if not isinstance(arn, str) or not arn.startswith(arn_prefix) or not arn[len(arn_prefix):]:
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or response.get("errorCode") or response.get("errorMessage"))
    endpoint = request.get("invocationEndpoint")
    auth = request.get("authParameters")
    auth_changed = (name == "UpdateConnection" and request.get("authorizationType") in
                    {"API_KEY", "BASIC", "OAUTH_CLIENT_CREDENTIALS"}
                    and isinstance(auth, Mapping) and bool(auth))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "events.amazonaws.com", "event.name": name,
        "event.outcome": "failure" if failed else "success", "event.id": record.get("eventID"),
        "event.time": record.get("eventTime"), "account.id": account,
        "actor.id": identity.get("arn"), "target.id": arn,
        "request.eventbridge_api_destination_endpoint_updated": (
            not failed and name == "UpdateApiDestination" and isinstance(endpoint, str)
            and endpoint.startswith("https://") and response.get("apiDestinationState") == "ACTIVE"),
        "request.eventbridge_connection_credential_updated": (
            not failed and auth_changed and response.get("connectionState") == "AUTHORIZED"),
        "request.eventbridge_connection_deauthorization_started": (
            not failed and name == "DeauthorizeConnection"
            and response.get("connectionState") in {"DEAUTHORIZING", "DEAUTHORIZED"}),
    }
