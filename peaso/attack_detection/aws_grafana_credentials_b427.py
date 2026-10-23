"""Sensitive Amazon Managed Grafana credential creation events."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_WORKSPACE = re.compile(r"g-[a-z0-9]{8,32}\Z")


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Avoid copying one-time bearer keys from CloudTrail responseElements."""
    name = record.get("eventName")
    if (record.get("eventSource") != "grafana.amazonaws.com"
            or name not in {"CreateWorkspaceApiKey", "CreateWorkspaceServiceAccount",
                            "CreateWorkspaceServiceAccountToken"}
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request, response = (record.get("userIdentity"),
                                   record.get("requestParameters"), record.get("responseElements"))
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or identity.get("type") == "AWSService"
            or not isinstance(identity.get("arn"), str) or not identity["arn"]
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None
    workspace = request.get("workspaceId")
    if (not isinstance(workspace, str) or not _WORKSPACE.fullmatch(workspace)
            or response.get("workspaceId") != workspace):
        return None
    signal = None
    if name == "CreateWorkspaceApiKey":
        if (request.get("keyRole") != "ADMIN"
                or not isinstance(request.get("keyName"), str)
                or response.get("keyName") != request["keyName"]):
            return None
        signal = "request.grafana_admin_api_key_created"
    elif name == "CreateWorkspaceServiceAccount":
        if (request.get("grafanaRole") != "ADMIN"
                or response.get("grafanaRole") != "ADMIN"
                or not isinstance(response.get("id"), str)
                or not response["id"]):
            return None
        signal = "request.grafana_admin_service_account_created"
    else:
        token = response.get("serviceAccountToken")
        if (not isinstance(request.get("serviceAccountId"), str)
                or not request["serviceAccountId"]
                or response.get("serviceAccountId") != request["serviceAccountId"]
                or not isinstance(token, Mapping)
                or not isinstance(token.get("id"), str) or not token["id"]):
            return None
        signal = "request.grafana_service_account_token_created"
    target = "sha256:" + hashlib.sha256(
        f"{account}:{region}:{workspace}".encode()).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "grafana.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": target,
        signal: True,
    }
