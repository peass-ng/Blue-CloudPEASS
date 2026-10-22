"""Classify accepted EMR termination protection and idle-policy changes."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_CLUSTER = re.compile(r"j-[A-Z0-9]{8,32}\Z")
_ACTIONS = frozenset({"SetTerminationProtection", "RemoveAutoTerminationPolicy"})


def normalize_aws_emr_lifecycle(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Emit fixed indicators without exposing cluster IDs."""
    action = record.get("eventName")
    if (record.get("eventSource") != "elasticmapreduce.amazonaws.com"
            or action not in _ACTIONS
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
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    enabled = disabled = idle_removed = False
    if action == "SetTerminationProtection":
        clusters = request.get("jobFlowIds")
        state = request.get("terminationProtected")
        if (not isinstance(clusters, list) or not 1 <= len(clusters) <= 256
                or not all(isinstance(item, str) and _CLUSTER.fullmatch(item)
                           for item in clusters)
                or type(state) is not bool):
            return None
        enabled, disabled = state, not state
    else:
        cluster = request.get("clusterId")
        if not isinstance(cluster, str) or not _CLUSTER.fullmatch(cluster):
            return None
        clusters = [cluster]
        idle_removed = True
    stamp = record.get("eventTime")
    if not isinstance(stamp, str):
        return None
    try:
        if datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
            return None
    except ValueError:
        return None
    target = hashlib.sha256(
        f"emr-lifecycle:{account}:{region}:{','.join(sorted(clusters))}".encode("utf-8")
    ).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "elasticmapreduce.amazonaws.com",
        "event.name": action, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": stamp,
        "account.id": account, "actor.id": identity["arn"],
        "target.id": "sha256:" + target,
        "request.emr_termination_protection_enabled": enabled,
        "request.emr_termination_protection_disabled": disabled,
        "request.emr_auto_termination_policy_removed": idle_removed,
    }
