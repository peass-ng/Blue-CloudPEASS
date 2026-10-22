"""Normalize accepted AWS Budgets actions that can attach IAM policies."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import re
from typing import Any

from .aws_raw_cloudtrail import normalize as normalize_raw


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_ROLE = re.compile(r"arn:aws(?:-cn|-us-gov)?:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+\Z")
_POLICY = re.compile(r"arn:aws(?:-cn|-us-gov)?:iam::(?:[0-9]{12}|aws):policy/[A-Za-z0-9+=,.@_/-]+\Z")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")


def normalize_aws_budgets_iam_action(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "budgets.amazonaws.com"
            or record.get("eventName") != "CreateBudgetAction"
            or record.get("eventCategory") != "Management"
            or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    account = record.get("recipientAccountId")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or request.get("AccountId") != account or response.get("AccountId") != account
            or request.get("ActionType") != "APPLY_IAM_POLICY"
            or request.get("ApprovalModel") not in {"AUTOMATIC", "MANUAL"}):
        return None
    budget_name, action_id = request.get("BudgetName"), response.get("ActionId")
    definition = request.get("Definition")
    iam_definition = definition.get("IamActionDefinition") if isinstance(definition, Mapping) else None
    execution_role = request.get("ExecutionRoleArn")
    if (not isinstance(budget_name, str) or not budget_name or len(budget_name) > 100
            or response.get("BudgetName") != budget_name
            or not isinstance(action_id, str) or not _UUID.fullmatch(action_id)
            or not isinstance(execution_role, str)
            or not (match := _ROLE.fullmatch(execution_role)) or match.group(1) != account
            or not isinstance(iam_definition, Mapping)
            or not isinstance(iam_definition.get("PolicyArn"), str)
            or not _POLICY.fullmatch(iam_definition["PolicyArn"])):
        return None
    targets = [iam_definition.get(key) for key in ("Roles", "Users", "Groups")]
    if not any(isinstance(items, list) and items for items in targets):
        return None
    if any(items is not None and (not isinstance(items, list) or not items
                                  or any(not isinstance(item, str) or not item for item in items))
           for items in targets):
        return None
    envelope = normalize_raw(record)
    if len(envelope) != 1 or envelope[0].get("resource.type") != "CloudTrail::UnscopedEvent":
        return None
    result = dict(envelope[0])
    result.pop("__raw_cloudtrail", None)
    result["target.id"] = "sha256:" + hashlib.sha256(
        f"{account}:{action_id}".encode("utf-8")
    ).hexdigest()[:24]
    result["request.budget_iam_policy_action_created"] = True
    result["request.budget_action_automatic"] = request["ApprovalModel"] == "AUTOMATIC"
    return result
