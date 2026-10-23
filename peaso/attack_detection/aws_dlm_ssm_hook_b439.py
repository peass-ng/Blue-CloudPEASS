"""DLM lifecycle policy SSM script configuration and activation facts."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import hashlib
from typing import Any


def _field(obj: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in obj:
            return obj[name]
    return None


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _base(record: Mapping[str, Any], names: set[str]) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    if record.get("eventSource") != "dlm.amazonaws.com" or record.get("eventName") not in names:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request = record.get("requestParameters")
    response = record.get("responseElements")
    response = response if isinstance(response, Mapping) else {}
    if (not isinstance(request, Mapping)
            or response.get("errorCode") or response.get("errorMessage")):
        return None
    return request, response


def _script_hook(request: Mapping[str, Any]) -> bool:
    role = _field(request, "ExecutionRoleArn", "executionRoleArn")
    if not isinstance(role, str) or not role.startswith("arn:aws:iam::") or ":role/" not in role:
        return False
    details = _field(request, "PolicyDetails", "policyDetails")
    if not isinstance(details, Mapping):
        return False
    resource_types = _field(details, "ResourceTypes", "resourceTypes")
    if not isinstance(resource_types, list) or "INSTANCE" not in resource_types:
        return False
    schedules = _field(details, "Schedules", "schedules")
    if not isinstance(schedules, list):
        return False
    for schedule in schedules:
        if not isinstance(schedule, Mapping):
            continue
        create = _field(schedule, "CreateRule", "createRule")
        if not isinstance(create, Mapping):
            continue
        scripts = _field(create, "Scripts", "scripts")
        if not isinstance(scripts, list):
            continue
        for script in scripts:
            if not isinstance(script, Mapping):
                continue
            service = _field(script, "ExecutionHandlerService", "executionHandlerService")
            handler = _field(script, "ExecutionHandler", "executionHandler")
            stages = _field(script, "Stages", "stages")
            if (service == "AWS_SYSTEMS_MANAGER" and isinstance(handler, str) and handler
                    and isinstance(stages, list) and any(stage in {"PRE", "POST"} for stage in stages)):
                return True
    return False


def normalize_aws_dlm_ssm_hook_b439(record: Mapping[str, Any]) -> dict[str, Any] | None:
    parsed = _base(record, {"CreateLifecyclePolicy"})
    if parsed is None:
        return None
    request, response = parsed
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    policy_id = _field(response, "PolicyId", "policyId")
    return {
        "cloud.provider": "aws", "event.source": "dlm.amazonaws.com",
        "event.name": "CreateLifecyclePolicy", "event.outcome": "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId"),
        "actor.id": _hash(identity["arn"]) if isinstance(identity.get("arn"), str) else None,
        "target.id": _hash(policy_id) if isinstance(policy_id, str) and policy_id else None,
        "request.dlm_ssm_hook_policy_created": bool(_script_hook(request)
                                                    and isinstance(policy_id, str) and policy_id),
    }


def correlate_aws_dlm_new_ssm_hook_enabled_b439(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    created: dict[tuple[str, str, str], datetime] = {}
    enabled: list[tuple[datetime, str, str, str, Mapping[str, Any]]] = []
    for record in records:
        parsed = _base(record, {"CreateLifecyclePolicy", "UpdateLifecyclePolicy"})
        if parsed is None:
            continue
        request, response = parsed
        identity = record.get("userIdentity")
        account = record.get("recipientAccountId")
        when = _when(record.get("eventTime"))
        if (not isinstance(identity, Mapping) or not isinstance(identity.get("arn"), str)
                or not isinstance(account, str) or len(account) != 12 or not account.isdigit()
                or when is None):
            continue
        actor = identity["arn"]
        if record["eventName"] == "CreateLifecyclePolicy":
            policy_id = _field(response, "PolicyId", "policyId")
            if _script_hook(request) and isinstance(policy_id, str) and policy_id:
                created[(account, actor, policy_id)] = when
        else:
            policy_id = _field(request, "PolicyId", "policyId")
            state = _field(request, "State", "state")
            if isinstance(policy_id, str) and policy_id and state == "ENABLED":
                enabled.append((when, account, actor, policy_id, record))
    result = []
    for when, account, actor, policy_id, record in enabled:
        start = created.get((account, actor, policy_id))
        if start is None or not start <= when <= start + timedelta(hours=2):
            continue
        result.append({
            "cloud.provider": "aws", "event.source": "dlm.amazonaws.com",
            "event.name": "UpdateLifecyclePolicy", "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": _hash(actor), "target.id": _hash(policy_id),
            "request.dlm_new_ssm_hook_policy_enabled": True,
        })
    return result
