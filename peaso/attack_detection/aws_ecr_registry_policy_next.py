"""External ECR registry policy grant for replication into the registry."""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any


def _external_replication_policy(value: Any, account: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        policy = json.loads(value)
    except json.JSONDecodeError:
        return False
    statements = policy.get("Statement") if isinstance(policy, Mapping) else None
    statements = [statements] if isinstance(statements, Mapping) else statements
    if not isinstance(statements, list):
        return False
    if any(isinstance(s, Mapping) and s.get("Effect") == "Deny" for s in statements):
        return False
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        if statement.get("Condition") or "NotAction" in statement or "NotPrincipal" in statement:
            continue
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        if not isinstance(actions, list) or not {"ecr:ReplicateImage", "ecr:*", "*"}.intersection(actions):
            continue
        principal = statement.get("Principal")
        principal = principal.get("AWS") if isinstance(principal, Mapping) else principal
        principals = principal if isinstance(principal, list) else [principal]
        for item in principals:
            if item == "*":
                return True
            if not isinstance(item, str):
                continue
            match = re.fullmatch(r"arn:aws:iam::(\d{12}):(?:root|user/[A-Za-z0-9+=,.@_/-]+|role/[A-Za-z0-9+=,.@_/-]+)", item)
            if match and match.group(1) != account:
                return True
    return False


def _canonical_policy(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, str):
        return None
    try:
        policy = json.loads(value)
    except json.JSONDecodeError:
        return None
    if not isinstance(policy, dict):
        return None
    statements = policy.get("Statement")
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list):
        return None
    policy["Statement"] = statements
    for statement in statements:
        if not isinstance(statement, dict):
            return None
        for field in ("Action", "Resource"):
            if isinstance(statement.get(field), str):
                statement[field] = [statement[field]]
    return policy


def normalize_aws_ecr_registry_policy(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "ecr.amazonaws.com" or record.get("eventName") != "PutRegistryPolicy":
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    account = record.get("recipientAccountId")
    if not isinstance(account, str) or re.fullmatch(r"\d{12}", account) is None:
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    request_policy, response_policy = request.get("policyText"), response.get("policyText")
    same_policy = (_canonical_policy(request_policy) is not None
                   and _canonical_policy(request_policy) == _canonical_policy(response_policy)
                   and response.get("registryId") == account)
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "ecr.amazonaws.com",
        "event.name": "PutRegistryPolicy", "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": account,
        "request.ecr_external_replication_registry_grant": (
            not failed and same_policy and _external_replication_policy(request_policy, account)
        ),
    }
