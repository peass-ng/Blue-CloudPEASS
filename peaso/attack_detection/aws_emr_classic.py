"""Validate EMR classic cluster/profile and command-runner step requests."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_CLUSTER = re.compile(r"j-[A-Z0-9]{8,32}\Z")
_IAM_NAME = re.compile(r"[A-Za-z0-9_+=,.@-]{1,64}\Z")
_STEP = re.compile(r"s-[A-Z0-9]{8,32}\Z")


def _same_account_role(value: Any, account: str, kind: str) -> bool:
    if not isinstance(value, str):
        return False
    if _IAM_NAME.fullmatch(value):
        return True
    return bool(re.fullmatch(
        rf"arn:aws:iam::{account}:{kind}/[A-Za-z0-9_+=,.@/-]{{1,128}}", value
    ))


def normalize_aws_emr_classic(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Emit fixed indicators without role names, step arguments or script paths."""
    action = record.get("eventName")
    if (record.get("eventSource") != "elasticmapreduce.amazonaws.com"
            or action not in {"RunJobFlow", "AddJobFlowSteps"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity = record.get("userIdentity")
    request, response = record.get("requestParameters"), record.get("responseElements")
    stamp, event_id = record.get("eventTime"), record.get("eventID")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or not isinstance(identity.get("arn"), str)
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or not isinstance(stamp, str) or not isinstance(event_id, str) or not event_id):
        return None
    try:
        if datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
            return None
    except ValueError:
        return None
    role_selected = False
    command_runner_added = False
    if action == "RunJobFlow":
        cluster_id = response.get("jobFlowId")
        cluster_arn = f"arn:aws:elasticmapreduce:{region}:{account}:cluster/{cluster_id}"
        if (not isinstance(cluster_id, str) or not _CLUSTER.fullmatch(cluster_id)
                or response.get("clusterArn") != cluster_arn
                or not _same_account_role(request.get("jobFlowRole"), account, "instance-profile")
                or not _same_account_role(request.get("serviceRole"), account, "role")
                or not isinstance(request.get("instances"), Mapping)):
            return None
        role_selected = True
    else:
        cluster_id = request.get("jobFlowId")
        steps = request.get("steps")
        step_ids = response.get("stepIds")
        if (not isinstance(cluster_id, str) or not _CLUSTER.fullmatch(cluster_id)
                or not isinstance(steps, list) or not 1 <= len(steps) <= 256
                or not isinstance(step_ids, list) or len(step_ids) != len(steps)
                or not all(isinstance(step_id, str) and _STEP.fullmatch(step_id)
                           for step_id in step_ids)):
            return None
        command_runner_added = any(
            isinstance(step, Mapping)
            and isinstance(step.get("hadoopJarStep"), Mapping)
            and step["hadoopJarStep"].get("jar") == "command-runner.jar"
            for step in steps
        )
        if not command_runner_added:
            return None
    target = f"arn:aws:elasticmapreduce:{region}:{account}:cluster/{cluster_id}"
    return {
        "cloud.provider": "aws", "event.source": "elasticmapreduce.amazonaws.com",
        "event.name": action, "event.outcome": "success",
        "event.id": event_id, "event.time": stamp, "account.id": account,
        "actor.id": identity["arn"],
        "target.id": "sha256:" + hashlib.sha256(target.encode("utf-8")).hexdigest()[:24],
        "request.emr_instance_profile_selected": role_selected,
        "request.emr_command_runner_step_added": command_runner_added,
    }
