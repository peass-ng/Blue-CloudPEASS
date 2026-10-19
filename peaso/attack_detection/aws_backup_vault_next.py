"""AWS Backup vault policy self-grant observation."""

from __future__ import annotations

from collections.abc import Mapping
import json
from typing import Any


def _self_delete_grant(value: Any, principal: str) -> bool:
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
        if (isinstance(policy_principal, Mapping) and policy_principal.get("AWS") == principal
                and isinstance(actions, list) and "backup:DeleteRecoveryPoint" in actions
                and statement.get("Resource") == "*"):
            return True
    return False


def normalize_aws_backup_self_grant(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "backup.amazonaws.com"
            or record.get("eventName") != "PutBackupVaultAccessPolicy"):
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("readOnly") is not False or record.get("managementEvent") is not True):
        return None
    request = record.get("requestParameters")
    identity = record.get("userIdentity")
    if not isinstance(request, Mapping) or not isinstance(identity, Mapping):
        return None
    vault = request.get("backupVaultName")
    if not isinstance(vault, str) or not vault:
        return None
    account = record.get("recipientAccountId")
    issuer = identity.get("sessionContext")
    issuer = issuer.get("sessionIssuer") if isinstance(issuer, Mapping) else None
    actor_principal = (identity.get("arn") if identity.get("type") == "IAMUser"
                       else issuer.get("arn") if identity.get("type") == "AssumedRole" and isinstance(issuer, Mapping)
                       else None)
    if not isinstance(account, str) or not isinstance(actor_principal, str):
        return None
    if f"::{account}:" not in actor_principal:
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    return {
        "cloud.provider": "aws", "event.source": "backup.amazonaws.com",
        "event.name": "PutBackupVaultAccessPolicy",
        "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": vault,
        "request.backup_self_delete_grant": (
            not failed and _self_delete_grant(request.get("policy"), actor_principal)
        ),
    }
