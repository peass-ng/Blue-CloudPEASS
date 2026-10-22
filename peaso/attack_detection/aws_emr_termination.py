"""Confirm accepted EMR cluster termination requests from CloudTrail."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_CLUSTER = re.compile(r"j-[A-Z0-9]{8,32}\Z")


def normalize_aws_emr_termination(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Emit a fixed signal for a successful TerminateJobFlows API request."""
    if (record.get("eventSource") != "elasticmapreduce.amazonaws.com"
            or record.get("eventName") != "TerminateJobFlows"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request = record.get("userIdentity"), record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or not isinstance(identity.get("arn"), str)
            or not isinstance(request, Mapping)
            or not isinstance(request.get("jobFlowIds"), list)
            or not 1 <= len(request["jobFlowIds"]) <= 10
            or not all(isinstance(item, str) and _CLUSTER.fullmatch(item)
                           for item in request["jobFlowIds"])
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    stamp = record.get("eventTime")
    if not isinstance(stamp, str):
        return None
    try:
        if datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
            return None
    except ValueError:
        return None
    target = hashlib.sha256(
        f"emr-termination:{account}:{region}:{','.join(sorted(request['jobFlowIds']))}".encode("utf-8")
    ).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "elasticmapreduce.amazonaws.com",
        "event.name": "TerminateJobFlows", "event.outcome": "success",
        "event.id": record["eventID"], "event.time": stamp,
        "account.id": account, "actor.id": identity["arn"],
        "target.id": "sha256:" + target,
        "request.emr_clusters_termination_requested": True,
        "correlation_evidence": {"cluster_count": len(request["jobFlowIds"])},
    }
