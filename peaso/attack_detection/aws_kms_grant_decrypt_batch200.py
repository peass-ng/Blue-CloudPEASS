"""Correlate a successful KMS Decrypt with a recent explicit grant to its actor."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_KEY = re.compile(r"(?:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}|mrk-[0-9a-f]{32})\Z")
_PRINCIPAL = re.compile(r"arn:aws:iam::[0-9]{12}:(?:user|role)/[^\s]{1,512}\Z")
_WINDOW = timedelta(minutes=15)


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else None
    except ValueError:
        return None


def _key_id(value: Any, account: str, region: str) -> str | None:
    if not isinstance(value, str):
        return None
    if value.startswith(f"arn:aws:kms:{region}:{account}:key/"):
        value = value.rsplit("/", 1)[-1]
    return value if _KEY.fullmatch(value) else None


def _principal(record: Mapping[str, Any]) -> str | None:
    identity = record.get("userIdentity")
    if not isinstance(identity, Mapping) or identity.get("invokedBy") or identity.get("type") == "AWSService":
        return None
    session = identity.get("sessionContext")
    issuer = session.get("sessionIssuer") if isinstance(session, Mapping) else None
    arn = issuer.get("arn") if isinstance(issuer, Mapping) else identity.get("arn")
    return arn if isinstance(arn, str) and _PRINCIPAL.fullmatch(arn) else None


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Emit on Decrypt, without asserting that the grant authorized the call."""
    ordered = []
    for record in records:
        name = record.get("eventName")
        if (record.get("eventSource") != "kms.amazonaws.com"
                or name not in {"CreateGrant", "Decrypt", "RevokeGrant"}
                or record.get("eventType") != "AwsApiCall"
                or record.get("eventCategory") != "Management"
                or record.get("managementEvent") is not True
                or record.get("readOnly") is not (name == "Decrypt")
                or record.get("errorCode") or record.get("errorMessage")):
            continue
        account, region = record.get("recipientAccountId"), record.get("awsRegion")
        request, response = record.get("requestParameters"), record.get("responseElements")
        when = _time(record.get("eventTime"))
        if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
                or not isinstance(region, str) or not _REGION.fullmatch(region)
                or not isinstance(request, Mapping) or when is None
                or not isinstance(record.get("eventID"), str)
                or not _principal(record)):
            continue
        key = _key_id(request.get("keyId"), account, region)
        if key is None:
            continue
        ordered.append((when, {"CreateGrant": 0, "Decrypt": 1, "RevokeGrant": 2}[name], key, record))
    ordered.sort(key=lambda item: (item[0], item[1]))
    grants: dict[tuple[str, str, str, str], list[tuple[datetime, str, str]]] = {}
    result: list[dict[str, Any]] = []
    for when, _, key, record in ordered:
        name = record["eventName"]
        account, region = record["recipientAccountId"], record["awsRegion"]
        request, response = record["requestParameters"], record.get("responseElements")
        if name == "CreateGrant":
            principal = request.get("granteePrincipal")
            operations = request.get("operations")
            if (not isinstance(principal, str) or not _PRINCIPAL.fullmatch(principal)
                    or not isinstance(operations, list) or "Decrypt" not in operations
                    or not isinstance(response, Mapping)
                    or not isinstance(response.get("grantId"), str) or not response["grantId"]
                    or _key_id(response.get("keyId"), account, region) != key):
                continue
            grants.setdefault((account, region, key, principal), []).append(
                (when, response["grantId"], record["eventID"]))
        elif name == "RevokeGrant":
            grant_id = request.get("grantId")
            if isinstance(grant_id, str):
                for scope in list(grants):
                    if scope[:3] == (account, region, key):
                        grants[scope] = [entry for entry in grants[scope] if entry[1] != grant_id]
        else:
            actor = _principal(record)
            active = grants.get((account, region, key, actor), [])
            paired = next((entry for entry in reversed(active) if timedelta(0) <= when - entry[0] <= _WINDOW), None)
            if paired is None:
                continue
            result.append({
                "cloud.provider": "aws", "event.source": "kms.amazonaws.com",
                "event.name": "Decrypt", "event.outcome": "success",
                "event.id": record["eventID"], "event.time": record["eventTime"],
                "account.id": account, "actor.id": actor,
                "target.id": "sha256:" + hashlib.sha256(
                    f"{account}:{region}:{key}".encode()).hexdigest()[:24],
                "request.kms_recent_grantee_decrypt": True,
                "correlation_evidence": {"paired_grant_event_id": paired[2]},
            })
    return result
