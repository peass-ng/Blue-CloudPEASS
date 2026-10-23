"""DLM EBS snapshot policy with a cross-account share rule."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
from typing import Any


def _field(value: Mapping[str, Any], upper: str, lower: str) -> Any:
    return value.get(upper, value.get(lower))


def normalize_aws_dlm_share_b443(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "dlm.amazonaws.com"
            or record.get("eventName") != "CreateLifecyclePolicy"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    account = record.get("recipientAccountId")
    if not isinstance(account, str) or len(account) != 12 or not account.isdigit():
        return None
    role = _field(request, "ExecutionRoleArn", "executionRoleArn")
    policy_id = _field(response, "PolicyId", "policyId")
    details = _field(request, "PolicyDetails", "policyDetails")
    state = _field(request, "State", "state")
    if (not isinstance(role, str) or not role.startswith(f"arn:aws:iam::{account}:role/")
            or not isinstance(policy_id, str) or not policy_id
            or state not in {"ENABLED", "DISABLED"}
            or not isinstance(details, Mapping)):
        return None
    resource_types = _field(details, "ResourceTypes", "resourceTypes")
    schedules = _field(details, "Schedules", "schedules")
    if not isinstance(resource_types, list) or "VOLUME" not in resource_types or not isinstance(schedules, list):
        return None
    cross_account = False
    for schedule in schedules:
        if not isinstance(schedule, Mapping):
            continue
        share_rules = _field(schedule, "ShareRules", "shareRules")
        if not isinstance(share_rules, list):
            continue
        for share in share_rules:
            if not isinstance(share, Mapping):
                continue
            targets = _field(share, "TargetAccounts", "targetAccounts")
            if (isinstance(targets, list)
                    and any(isinstance(target, str) and len(target) == 12
                            and target.isdigit() and target != account for target in targets)):
                cross_account = True
    if not cross_account:
        return None
    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    digest = lambda value: "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "dlm.amazonaws.com",
        "event.name": "CreateLifecyclePolicy", "event.outcome": "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account,
        "actor.id": digest(actor) if isinstance(actor, str) else None,
        "target.id": digest(policy_id),
        "request.dlm_cross_account_share_rule_configured": True,
        "request.dlm_policy_enabled": state == "ENABLED",
    }
