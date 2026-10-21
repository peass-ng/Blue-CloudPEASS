"""Correlate cross-Region Secrets Manager replica promotion and scoped reads."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import json
import re
from typing import Any


_SECRET = re.compile(r"arn:aws:secretsmanager:([a-z0-9-]+):(\d{12}):secret:([A-Za-z0-9/_+=.@-]+)\Z")
_KMS_KEY = re.compile(r"arn:aws:kms:([a-z0-9-]+):(\d{12}):key/[0-9a-f-]{36}\Z")
_ROLE = re.compile(r"arn:aws:iam::(\d{12}):role/[A-Za-z0-9_+=,.@/\-]+\Z")


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result if result.tzinfo else None


def _base(record: Mapping[str, Any], name: str, *, read_only: bool = False) -> Mapping[str, Any] | None:
    if (record.get("eventSource") != "secretsmanager.amazonaws.com"
            or record.get("eventName") != name
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not read_only
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request = record.get("requestParameters")
    return request if isinstance(request, Mapping) else None


def _scope(secret: Any, record: Mapping[str, Any]) -> tuple[str, str, str] | None:
    match = _SECRET.fullmatch(secret) if isinstance(secret, str) else None
    if (not match or match.group(1) != record.get("awsRegion")
            or match.group(2) != record.get("recipientAccountId")):
        return None
    return match.group(1), match.group(2), match.group(3)


def _actor(record: Mapping[str, Any]) -> str | None:
    identity = record.get("userIdentity")
    return identity.get("arn") if isinstance(identity, Mapping) and isinstance(identity.get("arn"), str) else None


def _scoped_role(policy_value: Any, target: str, account: str) -> str | None:
    if not isinstance(policy_value, str):
        return None
    try:
        policy = json.loads(policy_value)
    except (TypeError, ValueError):
        return None
    statements = policy.get("Statement") if isinstance(policy, Mapping) else None
    statements = [statements] if isinstance(statements, Mapping) else statements
    if not isinstance(statements, list) or any(
        isinstance(statement, Mapping) and statement.get("Effect") == "Deny"
        for statement in statements
    ):
        return None
    for statement in statements:
        if (not isinstance(statement, Mapping) or statement.get("Effect") != "Allow"
                or statement.get("Condition") or "NotAction" in statement
                or "NotResource" in statement):
            continue
        principal = statement.get("Principal")
        role = principal.get("AWS") if isinstance(principal, Mapping) else None
        match = _ROLE.fullmatch(role) if isinstance(role, str) else None
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        resources = statement.get("Resource")
        resources = [resources] if isinstance(resources, str) else resources
        if (match and match.group(1) == account and isinstance(actions, list)
                and "secretsmanager:GetSecretValue" in actions
                and isinstance(resources, list) and ("*" in resources or target in resources)):
            return role
    return None


def normalize_aws_secretsmanager_replica_chain(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if name not in {"ReplicateSecretToRegions", "PutResourcePolicy"}:
        return None
    request = _base(record, name)
    if request is None:
        return None
    target = request.get("secretId")
    scope = _scope(target, record)
    response = record.get("responseElements")
    if scope is None or not isinstance(response, Mapping) or response.get("arn") != target:
        return None
    region, account, _ = scope
    custom = False
    role = None
    if name == "ReplicateSecretToRegions":
        regions = request.get("addReplicaRegions")
        if not isinstance(regions, list):
            return None
        for item in regions:
            if not isinstance(item, Mapping):
                continue
            destination, key = item.get("region"), item.get("kmsKeyId")
            key_match = _KMS_KEY.fullmatch(key) if isinstance(key, str) else None
            if (isinstance(destination, str) and destination != region and key_match
                    and key_match.group(1) == destination and key_match.group(2) == account):
                custom = True
        if not custom:
            return None
    else:
        role = _scoped_role(request.get("resourcePolicy"), target, account)
        if role is None:
            return None
    return {
        "cloud.provider": "aws", "event.source": "secretsmanager.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": _actor(record), "target.id": target,
        "request.secretsmanager_custom_kms_replication": custom,
        "request.secretsmanager_scoped_role_read_grant": role is not None,
    }


def correlate_aws_secretsmanager_replica_chain(
    records: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    replicated = []
    promoted = []
    granted = []
    reads = []
    for record in records:
        name = record.get("eventName")
        if name not in {"ReplicateSecretToRegions", "StopReplicationToReplica",
                        "PutResourcePolicy", "GetSecretValue"}:
            continue
        request = _base(record, name, read_only=name == "GetSecretValue")
        if request is None:
            continue
        target = request.get("secretId")
        scope = _scope(target, record)
        when = _time(record.get("eventTime"))
        if scope is None or when is None:
            continue
        region, account, suffix = scope
        response = record.get("responseElements")
        if name != "GetSecretValue" and (not isinstance(response, Mapping)
                                         or response.get("arn") != target):
            continue
        if name == "ReplicateSecretToRegions":
            regions = request.get("addReplicaRegions")
            if not isinstance(regions, list):
                continue
            for item in regions:
                if not isinstance(item, Mapping):
                    continue
                destination, key = item.get("region"), item.get("kmsKeyId")
                key_match = _KMS_KEY.fullmatch(key) if isinstance(key, str) else None
                if (isinstance(destination, str) and destination != region and key_match
                        and key_match.group(1) == destination and key_match.group(2) == account):
                    replicated.append((when, account, destination, suffix, record))
        elif name == "StopReplicationToReplica":
            promoted.append((when, account, region, suffix, record))
        elif name == "PutResourcePolicy":
            role = _scoped_role(request.get("resourcePolicy"), target, account)
            if role:
                granted.append((when, account, region, suffix, role, record))
        else:
            identity = record.get("userIdentity")
            session = identity.get("sessionContext") if isinstance(identity, Mapping) else None
            issuer = session.get("sessionIssuer") if isinstance(session, Mapping) else None
            role = issuer.get("arn") if isinstance(issuer, Mapping) else None
            if (isinstance(identity, Mapping) and identity.get("type") == "AssumedRole"
                    and isinstance(role, str) and _ROLE.fullmatch(role)):
                reads.append((when, account, region, suffix, role, record))
    result = []
    for when, account, region, suffix, role, record in granted:
        prior_promotions = [p for p in promoted if p[1:4] == (account, region, suffix)
                            and p[0] <= when <= p[0] + timedelta(minutes=30)]
        if not prior_promotions:
            continue
        target = record["requestParameters"]["secretId"]
        result.append({
            "cloud.provider": "aws", "event.source": "secretsmanager.amazonaws.com",
            "event.name": "PutResourcePolicy", "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": _actor(record), "target.id": target,
            "request.secretsmanager_promoted_replica_role_granted": True,
        })
        if not any(p[1:4] == (account, region, suffix)
                   and p[0] <= prior_promotions[0][0]
                   and prior_promotions[0][0] <= p[0] + timedelta(minutes=30)
                   for p in replicated):
            continue
        for read_time, read_account, read_region, read_suffix, read_role, read_record in reads:
            if ((read_account, read_region, read_suffix, read_role) != (account, region, suffix, role)
                    or not when <= read_time <= when + timedelta(minutes=30)):
                continue
            result.append({
                "cloud.provider": "aws", "event.source": "secretsmanager.amazonaws.com",
                "event.name": "GetSecretValue", "event.outcome": "success",
                "event.id": read_record.get("eventID"), "event.time": read_record.get("eventTime"),
                "account.id": account, "actor.id": _actor(read_record), "target.id": target,
                "request.secretsmanager_cross_region_cmk_replica_read": True,
            })
    return result
