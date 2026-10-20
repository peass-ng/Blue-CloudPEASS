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
    if any(isinstance(statement, Mapping) and statement.get("Effect") == "Deny" for statement in statements):
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
    target_role = request.get("roleName")
    session = identity.get("sessionContext")
    session = session if isinstance(session, Mapping) else {}
    issuer = session.get("sessionIssuer")
    issuer = issuer if isinstance(issuer, Mapping) else {}
    issuer_arn = issuer.get("arn")
    actor_arn = identity.get("arn")
    identity_account = identity.get("accountId")
    issuer_parts = issuer_arn.split(":", 5) if isinstance(issuer_arn, str) else []
    assumed_role_prefix = (
        f"arn:{issuer_parts[1]}:sts::{account_id}:assumed-role/{target_role}/"
        if len(issuer_parts) == 6 and isinstance(account_id, str) and isinstance(target_role, str)
        else ""
    )
    session_name = actor_arn[len(assumed_role_prefix):] if (
        isinstance(actor_arn, str) and assumed_role_prefix and actor_arn.startswith(assumed_role_prefix)
    ) else ""
    self_role = (
        actor_kind == "AssumedRole"
        and isinstance(target_role, str) and bool(target_role)
        and issuer.get("type") == "Role" and issuer.get("userName") == target_role
        and len(issuer_parts) == 6 and issuer_parts[0] == "arn"
        and issuer_parts[1] in {"aws", "aws-us-gov", "aws-cn"}
        and issuer_parts[2] == "iam" and issuer_parts[3] == ""
        and issuer_parts[5].startswith("role/") and issuer_parts[5].rsplit("/", 1)[-1] == target_role
        and isinstance(account_id, str) and record.get("recipientAccountId") == account_id
        and issuer_parts[4] == account_id
        and issuer.get("accountId", account_id) == account_id
        and identity_account == account_id
        and bool(session_name) and "/" not in session_name
    )
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or response.get("errorCode") or response.get("errorMessage"))
    self_role_admin_policy_attach = (
        record.get("eventName") == "AttachRolePolicy"
        and not failed and self_role
        and request.get("policyArn") == f"arn:{issuer_parts[1]}:iam::aws:policy/AdministratorAccess"
    )
    return {
        "cloud.provider": "aws",
        "event.name": record.get("eventName"),
        "event.source": record.get("eventSource"),
        "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"),
        "event.time": record.get("eventTime"),
        "account.id": account_id,
        "actor.id": identity.get("arn"),
        "actor.kind": actor_kind,
        "actor.user_name": actor_user,
        "target.id": target_user or target_role or request.get("policyArn"),
        "request.user_name": target_user,
        "request.policy_arn": request.get("policyArn"),
        "request.status": request.get("status"),
        "request.role_name": target_role,
        "request.max_session_duration": request.get("maxSessionDuration") if isinstance(request.get("maxSessionDuration"), int) and not isinstance(request.get("maxSessionDuration"), bool) else None,
        "request.set_as_default": request.get("setAsDefault") is True or request.get("setAsDefault") == "true",
        "request.unconditional_admin_grant": _unconditional_admin_grant(request.get("policyDocument")),
        "request.self_user": isinstance(actor_user, str) and bool(actor_user) and target_user == actor_user,
        "request.self_role": self_role,
        "request.self_role_admin_policy_attach": self_role_admin_policy_attach,
        "request.other_user": isinstance(actor_user, str) and bool(actor_user) and isinstance(target_user, str) and bool(target_user) and target_user != actor_user,
    }
