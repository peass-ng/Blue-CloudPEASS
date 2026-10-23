"""Read access to HealthOmics workflow and task logs in CloudWatch Logs."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "logs.amazonaws.com"
            or record.get("eventName") != "GetLogEvents"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not True
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
            or request.get("logGroupName") != "/aws/omics/WorkflowLog"
            or not isinstance(request.get("logStreamName"), str)
            or not request["logStreamName"] or len(request["logStreamName"]) > 512
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str)):
        return None
    try:
        if datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00")).tzinfo is None:
            return None
    except ValueError:
        return None
    target = "sha256:" + hashlib.sha256(
        f"{account}:{region}:{request['logStreamName']}".encode()).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "logs.amazonaws.com",
        "event.name": "GetLogEvents", "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": target,
        "request.healthomics_workflow_log_read": True,
    }
