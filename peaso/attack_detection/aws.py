"""Normalize the CloudTrail fields needed by the first IAM detection rules."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any
from urllib.parse import unquote


def _policy_document(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if not isinstance(value, str):
        return None
    try:
        decoded = json.loads(unquote(value))
    except (ValueError, TypeError):
        return None
    return decoded if isinstance(decoded, Mapping) else None


def _unconditional_admin_grant(value: Any) -> bool:
    document = _policy_document(value)
    if document is None:
        return False
    statements = document.get("Statement", [])
    if isinstance(statements, Mapping):
        statements = [statements]
    if not isinstance(statements, list):
        return False
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        if statement.get("Condition") or "NotAction" in statement or "NotResource" in statement:
            continue
        actions = statement.get("Action")
        resources = statement.get("Resource")
        if actions == "*" or isinstance(actions, list) and "*" in actions:
            if resources == "*" or isinstance(resources, list) and "*" in resources:
                return True
    return False


def normalize_aws_cloudtrail(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return flat canonical fields for an IAM CloudTrail record, or None.

    Missing, malformed, denied, or conditional policy evidence never becomes a
    positive privilege grant. The event itself is retained for investigation.
    """
    if record.get("eventSource") != "iam.amazonaws.com":
        return None
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    request = record.get("requestParameters")
    request = request if isinstance(request, Mapping) else {}
    response = record.get("responseElements")
    response = response if isinstance(response, Mapping) else {}
    actor_kind = identity.get("type")
    actor_user = identity.get("userName") if actor_kind == "IAMUser" else None
    target_user = request.get("userName")
    account_id = record.get("recipientAccountId") or identity.get("accountId")
    return {
        "cloud.provider": "aws",
        "event.name": record.get("eventName"),
        "event.source": record.get("eventSource"),
        "event.outcome": "failure" if record.get("errorCode") or response.get("errorCode") else "success",
        "event.id": record.get("eventID"),
        "event.time": record.get("eventTime"),
        "account.id": account_id,
        "actor.id": identity.get("arn"),
        "actor.kind": actor_kind,
        "actor.user_name": actor_user,
        "target.id": target_user or request.get("policyArn"),
        "request.user_name": target_user,
        "request.policy_arn": request.get("policyArn"),
        "request.set_as_default": request.get("setAsDefault") is True or request.get("setAsDefault") == "true",
        "request.unconditional_admin_grant": _unconditional_admin_grant(request.get("policyDocument")),
        "request.self_user": isinstance(actor_user, str) and bool(actor_user) and target_user == actor_user,
        "request.other_user": isinstance(actor_user, str) and bool(actor_user) and isinstance(target_user, str) and bool(target_user) and target_user != actor_user,
    }
