"""Identify accepted Scheduler targets that write IAM inline policies."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import re
from typing import Any

from .aws_scheduler_controls_next import normalize_aws_scheduler_controls


_ROLE = re.compile(r"arn:(?:aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+\Z")
_TARGET = {
    "arn:aws:scheduler:::aws-sdk:iam:putRolePolicy": "role",
    "arn:aws:scheduler:::aws-sdk:iam:putUserPolicy": "user",
}


def normalize_aws_scheduler_iam_policy_target(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Emit fixed action flags and a hashed schedule target; omit payload."""
    normalized = normalize_aws_scheduler_controls(record)
    if (not normalized or normalized.get("event.outcome") != "success"
            or record.get("eventName") not in {"CreateSchedule", "UpdateSchedule"}
            or not normalized.get("request.scheduler_universal_target")):
        return None
    request = record.get("requestParameters")
    target = request.get("target") if isinstance(request, Mapping) else None
    if not isinstance(target, Mapping):
        return None
    spec = _TARGET.get(target.get("arn"))
    if spec is None:
        return None
    account = record.get("recipientAccountId")
    identity = record.get("userIdentity")
    if (not isinstance(identity, Mapping) or identity.get("accountId") != account
            or not isinstance(identity.get("arn"), str)
            or not isinstance(record.get("eventID"), str)
            or not record["eventID"]
            or not isinstance(record.get("eventTime"), str)):
        return None
    role = _ROLE.fullmatch(target.get("roleArn")) if isinstance(target.get("roleArn"), str) else None
    if not role or role.group(1) != account:
        return None
    # Scheduler omits target.input from the delivered CloudTrail event.
    # The target API is observable; the policy document and recipient are not.
    result = dict(normalized)
    result["target.id"] = "sha256:" + hashlib.sha256(
        normalized["target.id"].encode("utf-8")).hexdigest()[:24]
    result["request.scheduler_iam_put_role_policy_target_requested"] = spec == "role"
    result["request.scheduler_iam_put_user_policy_target_requested"] = spec == "user"
    return result
