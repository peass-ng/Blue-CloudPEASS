"""CloudTrail run metadata, logging suppression and cancellation signals."""

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
    name = record.get("eventName")
    if (record.get("eventSource") != "omics.amazonaws.com"
            or name not in {"StartRun", "GetRun", "CancelRun", "DeleteRun"}
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name == "GetRun")
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
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not _valid_time(record.get("eventTime"))):
        return None
    if name == "StartRun":
        response = record.get("responseElements")
        if (request.get("logLevel") != "OFF"
                or not isinstance(request.get("workflowId"), str) or not request["workflowId"]
                or request.get("workflowType") != "PRIVATE"
                or not isinstance(request.get("roleArn"), str)
                or not request["roleArn"].startswith(f"arn:aws:iam::{account}:role/")
                or not isinstance(request.get("outputUri"), str)
                or not request["outputUri"].startswith("s3://")
                or not isinstance(response, Mapping)
                or response.get("status") not in {"PENDING", "STARTING", "RUNNING"}
                or not isinstance(response.get("id"), str) or not response["id"]
                or not isinstance(response.get("arn"), str)
                or not response["arn"].startswith(f"arn:aws:omics:{region}:{account}:run/")):
            return None
        run_id = response["id"]
        marker = "request.healthomics_run_logging_disabled"
    else:
        run_id = request.get("id")
        if not isinstance(run_id, str) or not run_id:
            return None
        marker = {"GetRun": "request.healthomics_run_metadata_read",
                  "CancelRun": "request.healthomics_run_cancel_accepted",
                  "DeleteRun": "request.healthomics_run_delete_accepted"}[name]
    target = "sha256:" + hashlib.sha256(
        f"{account}:{region}:run:{run_id}".encode()).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "omics.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": target,
        marker: True,
    }
