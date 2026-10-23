"""Small, privacy preserving CloudTrail signals for private HealthOmics workflows."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")


def _valid_time(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Describe the API action, never its presigned URL or workflow definition."""
    name = record.get("eventName")
    if (record.get("eventSource") != "omics.amazonaws.com"
            or name not in {"GetWorkflow", "GetWorkflowVersion", "CreateWorkflowVersion",
                            "DeleteWorkflow", "DeleteWorkflowVersion"}
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request = record.get("userIdentity"), record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or identity.get("type") == "AWSService"
            or not isinstance(identity.get("arn"), str) or not identity["arn"]
            or not isinstance(request, Mapping)
            or not isinstance(request.get("id"), str) or not request["id"]
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not _valid_time(record.get("eventTime"))):
        return None
    workflow_id = request["id"]
    if name in {"GetWorkflow", "GetWorkflowVersion"}:
        if (record.get("readOnly") is not True or request.get("type") != "PRIVATE"
                or not isinstance(request.get("export"), str)
                or "DEFINITION" not in {part.strip() for part in request["export"].split(",")}
                or (name == "GetWorkflowVersion" and
                    (not isinstance(request.get("versionName"), str)
                     or not request["versionName"]))):
            return None
    elif name == "CreateWorkflowVersion":
        response = record.get("responseElements")
        if (record.get("readOnly") is not False
                or not isinstance(request.get("versionName"), str)
                or not request["versionName"]
                or not isinstance(response, Mapping)
                or response.get("workflowId") != workflow_id
                or response.get("versionName") != request["versionName"]
                or response.get("status") not in {"CREATING", "ACTIVE"}
                or not isinstance(response.get("arn"), str)
                or not response["arn"].startswith(f"arn:aws:omics:{region}:{account}:workflow/")):
            return None
    else:
        if (record.get("readOnly") is not False
                or (name == "DeleteWorkflowVersion" and
                    (not isinstance(request.get("versionName"), str)
                     or not request["versionName"]))):
            return None
    target = "sha256:" + hashlib.sha256(f"{account}:{region}:{workflow_id}".encode()).hexdigest()[:24]
    event = {
        "cloud.provider": "aws", "event.source": "omics.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": target,
    }
    if name == "CreateWorkflowVersion":
        event["request.healthomics_workflow_version_created"] = True
    elif name in {"GetWorkflow", "GetWorkflowVersion"}:
        event["request.healthomics_definition_exported"] = True
    else:
        event["request.healthomics_workflow_deletion_accepted"] = True
    return event
