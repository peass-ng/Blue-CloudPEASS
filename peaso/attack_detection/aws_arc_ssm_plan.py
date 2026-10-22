"""Detect accepted ARC Region Switch plans containing an SSM command step."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import re
from typing import Any

from .aws_raw_cloudtrail import normalize as normalize_raw


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_ROLE = re.compile(r"arn:(?:aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}\Z")
_PLAN = re.compile(r"arn:(?:aws|aws-us-gov|aws-cn):arc-region-switch::([0-9]{12}):plan/[A-Za-z0-9-]{1,64}:[a-z0-9]{6}\Z")


def _ssm_step(steps: Any, depth: int = 0) -> bool:
    if not isinstance(steps, list) or len(steps) > 100 or depth > 3:
        return False
    for step in steps:
        if not isinstance(step, Mapping):
            continue
        config = step.get("executionBlockConfiguration")
        if not isinstance(config, Mapping):
            continue
        if step.get("executionBlockType") == "SSMSendCommand":
            ssm = config.get("ssmSendCommandConfig")
            documents = ssm.get("regionDocuments") if isinstance(ssm, Mapping) else None
            if isinstance(documents, Mapping) and 0 < len(documents) <= 2:
                if any(isinstance(document, Mapping)
                       and isinstance(document.get("documentArn"), str)
                       and document["documentArn"].startswith("arn:")
                       and isinstance(document.get("targets"), list)
                       and document["targets"]
                       for document in documents.values()):
                    return True
        nested = config.get("parallelConfig")
        if isinstance(nested, Mapping) and _ssm_step(nested.get("steps"), depth + 1):
            return True
    return False


def normalize_aws_arc_ssm_plan(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Emit only a fixed flag and hashed plan ID; never copy commands or role ARNs."""
    name = record.get("eventName")
    if (record.get("eventSource") != "arc-region-switch.amazonaws.com"
            or name not in {"CreatePlan", "UpdatePlan"}
            or record.get("readOnly") is not False):
        return None
    envelope = normalize_raw(record)
    if len(envelope) != 1 or envelope[0].get("resource.type") != "CloudTrail::UnscopedEvent":
        return None
    account = record.get("recipientAccountId")
    identity, request, response = (record.get("userIdentity"), record.get("requestParameters"),
                                   record.get("responseElements"))
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)):
        return None
    role = request.get("executionRole")
    role_match = _ROLE.fullmatch(role) if isinstance(role, str) else None
    workflows = request.get("workflows")
    if (not role_match or role_match.group(1) != account
            or not isinstance(workflows, list) or len(workflows) > 20
            or not any(isinstance(workflow, Mapping)
                       and _ssm_step(workflow.get("steps")) for workflow in workflows)):
        return None
    plan = response.get("plan")
    if not isinstance(plan, Mapping):
        return None
    arn = plan.get("arn")
    plan_match = _PLAN.fullmatch(arn) if isinstance(arn, str) else None
    if (not plan_match or plan_match.group(1) != account
            or plan.get("owner") != account
            or plan.get("executionRole") != role
            or plan.get("workflows") != workflows):
        return None
    if name == "CreatePlan" and plan.get("name") != request.get("name"):
        return None
    if name == "UpdatePlan" and arn != request.get("arn"):
        return None
    result = dict(envelope[0])
    result.pop("__raw_cloudtrail", None)
    result["target.id"] = "sha256:" + hashlib.sha256(arn.encode("utf-8")).hexdigest()[:24]
    result["request.arc_ssm_command_plan_created" if name == "CreatePlan"
           else "request.arc_ssm_command_plan_updated"] = True
    return result
