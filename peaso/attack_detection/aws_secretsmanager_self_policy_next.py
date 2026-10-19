"""Secrets Manager policy grants a caller access to a secret's value."""

from __future__ import annotations

from collections.abc import Mapping
import json
from typing import Any


def _self_read(value: Any, principal: str, secret_arn: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        policy = json.loads(value)
    except (TypeError, ValueError):
        return False
    if not isinstance(policy, Mapping):
        return False
    statements = policy.get("Statement")
    statements = [statements] if isinstance(statements, Mapping) else statements
    if not isinstance(statements, list):
        return False
    if any(isinstance(s, Mapping) and s.get("Effect") == "Deny" for s in statements):
        return False
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        if statement.get("Condition") or "NotAction" in statement or "NotResource" in statement:
            continue
        policy_principal = statement.get("Principal")
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        resources = statement.get("Resource")
        resources = [resources] if isinstance(resources, str) else resources
        if (isinstance(policy_principal, Mapping) and policy_principal.get("AWS") == principal
                and isinstance(actions, list) and "secretsmanager:GetSecretValue" in actions
                and isinstance(resources, list) and secret_arn in resources):
            return True
    return False


def _public_read(value: Any, secret_arn: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        policy = json.loads(value)
    except (TypeError, ValueError):
        return False
    statements = policy.get("Statement") if isinstance(policy, Mapping) else None
    statements = [statements] if isinstance(statements, Mapping) else statements
    if not isinstance(statements, list):
        return False
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        if statement.get("Condition") or "NotAction" in statement or "NotResource" in statement:
            continue
        principal = statement.get("Principal")
        actions, resources = statement.get("Action"), statement.get("Resource")
        actions = [actions] if isinstance(actions, str) else actions
        resources = [resources] if isinstance(resources, str) else resources
        if ((principal == "*" or isinstance(principal, Mapping) and principal.get("AWS") == "*")
                and isinstance(actions, list)
                and "secretsmanager:GetSecretValue" in actions
                and isinstance(resources, list) and secret_arn in resources):
            return True
    return False


def normalize_aws_secret_self_read_grant(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "secretsmanager.amazonaws.com"
            or record.get("eventName") != "PutResourcePolicy"):
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    identity = record.get("userIdentity")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping) or not isinstance(identity, Mapping):
        return None
    secret_arn = request.get("secretId")
    account = record.get("recipientAccountId")
    if (not isinstance(secret_arn, str) or response.get("arn") != secret_arn
            or not isinstance(account, str) or f":{account}:secret:" not in secret_arn):
        return None
    session = identity.get("sessionContext")
    issuer = session.get("sessionIssuer") if isinstance(session, Mapping) else None
    actor_principal = (identity.get("arn") if identity.get("type") == "IAMUser"
                       else issuer.get("arn") if identity.get("type") == "AssumedRole" and isinstance(issuer, Mapping)
                       else None)
    self_actor = isinstance(actor_principal, str) and f"::{account}:" in actor_principal
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or response.get("errorCode") or response.get("errorMessage"))
    return {
        "cloud.provider": "aws", "event.source": "secretsmanager.amazonaws.com",
        "event.name": "PutResourcePolicy", "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": secret_arn,
        "request.secretsmanager_self_read_grant": (
            not failed and self_actor and _self_read(request.get("resourcePolicy"), actor_principal, secret_arn)
        ),
        "request.secret_public_read_policy_accepted": (
            not failed and _public_read(request.get("resourcePolicy"), secret_arn)
        ),
    }
