"""Managed Grafana customer-managed workspace role update requests."""

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
    """CloudTrail masks the submitted role ARN, so report only the update."""
    if (record.get("eventSource") != "grafana.amazonaws.com"
            or record.get("eventName") != "UpdateWorkspace"
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
            or not isinstance(response.get("workspace"), Mapping)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None
    workspace = request.get("workspaceId")
    target = response["workspace"]
    if (not isinstance(workspace, str) or not _WORKSPACE.fullmatch(workspace)
            or target.get("id") != workspace
            or "workspaceRoleArn" not in request
            or not isinstance(request["workspaceRoleArn"], str)
            or not request["workspaceRoleArn"]
            or target.get("permissionType") != "CUSTOMER_MANAGED"
            or target.get("status") not in {"UPDATING", "ACTIVE"}):
        return None
    hashed = "sha256:" + hashlib.sha256(
        f"{account}:{region}:{workspace}".encode()).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "grafana.amazonaws.com",
        "event.name": "UpdateWorkspace", "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": hashed,
        "request.grafana_workspace_role_update_submitted": True,
    }
