"""High-impact KMS grant and policy writes observable in CloudTrail."""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any


def _external_principal(value: Any, account: str) -> bool:
    principals = value if isinstance(value, list) else [value]
    for principal in principals:
        if not isinstance(principal, str):
            continue
        if re.fullmatch(r"\d{12}", principal) and principal != account:
            return True
        match = re.fullmatch(r"arn:aws:iam::(\d{12}):(?:root|user/[A-Za-z0-9+=,.@_/-]+|role/[A-Za-z0-9+=,.@_/-]+)", principal)
        if match and match.group(1) != account:
            return True
    return False


def _external_key_policy(value: Any, account: str) -> bool:
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
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        if statement.get("Condition") or "NotAction" in statement or "NotPrincipal" in statement:
            continue
        principal = statement.get("Principal")
        principal = principal.get("AWS") if isinstance(principal, Mapping) else principal
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        if (_external_principal(principal, account) and isinstance(actions, list)
                and any(a in {"kms:*", "kms:Decrypt", "kms:CreateGrant"} for a in actions)):
            return True
    return False


def normalize_aws_kms_standing_access(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "kms.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"CreateGrant", "PutKeyPolicy"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    account = record.get("recipientAccountId")
    if not isinstance(account, str) or re.fullmatch(r"\d{12}", account) is None:
        return None
    key = request.get("keyId")
    if not isinstance(key, str) or not key:
        return None
    response = record.get("responseElements")
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")))
    operations = request.get("operations")
    grantee = request.get("granteePrincipal")
    returned_key = response.get("keyId") if isinstance(response, Mapping) else None
    same_key = (returned_key == key or isinstance(returned_key, str)
                and returned_key.endswith(":key/" + key))
    grant_created = (name == "CreateGrant" and isinstance(response, Mapping)
                     and isinstance(response.get("grantId"), str) and bool(response["grantId"])
                     and same_key)
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "kms.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": key,
        "request.kms_grantee_can_create_grants": (
            not failed and grant_created and isinstance(grantee, str) and bool(grantee)
            and isinstance(operations, list) and "CreateGrant" in operations
        ),
        "request.kms_external_key_policy_grant": (
            not failed and name == "PutKeyPolicy"
            and _external_key_policy(request.get("policy"), account)
        ),
    }


def normalize_aws_kms_key_deletion(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "kms.amazonaws.com" or record.get("eventName") != "ScheduleKeyDeletion":
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    key, returned = request.get("keyId"), response.get("keyId")
    if not isinstance(key, str) or not isinstance(returned, str):
        return None
    same_key = returned == key or returned.endswith(":key/" + key)
    state = response.get("keyState")
    deletion_confirmed = (state == "PendingDeletion"
                          and isinstance(response.get("deletionDate"), str))
    replica_deletion_confirmed = (
        state == "PendingReplicaDeletion" and response.get("deletionDate") is None
        and isinstance(request.get("pendingWindowInDays"), int)
        and 7 <= request["pendingWindowInDays"] <= 30
        and response.get("pendingWindowInDays") == request["pendingWindowInDays"]
    )
    accepted = (not record.get("errorCode") and not record.get("errorMessage")
                and same_key and (deletion_confirmed or replica_deletion_confirmed))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "kms.amazonaws.com",
        "event.name": "ScheduleKeyDeletion",
        "event.outcome": "failure" if record.get("errorCode") or record.get("errorMessage") else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId"), "actor.id": identity.get("arn"),
        "target.id": returned, "request.kms_key_deletion_scheduled": accepted,
    }


def normalize_aws_kms_key_disabled(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "kms.amazonaws.com" or record.get("eventName") != "DisableKey":
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    key, returned = request.get("keyId"), response.get("keyId")
    if not isinstance(key, str) or not isinstance(returned, str):
        return None
    same_key = returned == key or returned.endswith(":key/" + key)
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "kms.amazonaws.com",
        "event.name": "DisableKey", "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId"), "actor.id": identity.get("arn"),
        "target.id": returned, "request.kms_key_disabled": not failed and same_key,
    }
