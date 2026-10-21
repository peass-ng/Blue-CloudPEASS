"""Detect Step Functions TestState access to HTTP connection credentials."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any


_ROLE = re.compile(r"arn:aws:iam::(\d{12}):role/[A-Za-z0-9_+=,.@\-/]+\Z")
_SECRET = re.compile(
    r"arn:aws:secretsmanager:([a-z0-9-]+):(\d{12}):secret:events!connection/[A-Za-z0-9_+=,.@/\-]+\Z"
)


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result if result.tzinfo else None


def _test_state(record: Mapping[str, Any]) -> tuple[str, str, str] | None:
    if (record.get("eventSource") != "states.amazonaws.com"
            or record.get("eventName") != "TestState"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    role = request.get("roleArn")
    match = _ROLE.fullmatch(role) if isinstance(role, str) else None
    if (not match or not isinstance(account, str) or account != match.group(1)
            or not isinstance(region, str) or request.get("inspectionLevel") != "TRACE"
            or request.get("definition") != "HIDDEN_DUE_TO_SECURITY_REASONS"
            or response.get("status") != "SUCCEEDED"):
        return None
    return role, account, region


def normalize_aws_sfn_reveal_secrets(record: Mapping[str, Any]) -> dict[str, Any] | None:
    parsed = _test_state(record)
    request = record.get("requestParameters")
    if parsed is None or request.get("revealSecrets") is not True:
        return None
    role, account, _ = parsed
    identity = record.get("userIdentity")
    return {
        "cloud.provider": "aws", "event.source": "states.amazonaws.com",
        "event.name": "TestState", "event.outcome": "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account,
        "actor.id": identity.get("arn") if isinstance(identity, Mapping) else None,
        "target.id": role, "request.sfn_reveal_connection_secrets": True,
    }


def correlate_aws_sfn_connection_secret_read(
    records: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    tests = []
    reads = []
    for record in records:
        parsed = _test_state(record)
        if parsed is not None:
            when = _time(record.get("eventTime"))
            if when is not None:
                tests.append((when, parsed, record))
            continue
        if (record.get("eventSource") != "secretsmanager.amazonaws.com"
                or record.get("eventName") != "GetSecretValue"
                or record.get("eventCategory") != "Management"
                or record.get("eventType") != "AwsApiCall"
                or record.get("managementEvent") is not True
                or record.get("errorCode") or record.get("errorMessage")):
            continue
        request, identity = record.get("requestParameters"), record.get("userIdentity")
        if not isinstance(request, Mapping) or not isinstance(identity, Mapping):
            continue
        secret = request.get("secretId")
        match = _SECRET.fullmatch(secret) if isinstance(secret, str) else None
        session = identity.get("sessionContext")
        issuer = session.get("sessionIssuer") if isinstance(session, Mapping) else None
        when = _time(record.get("eventTime"))
        if (not match or when is None or identity.get("type") != "AssumedRole"
                or identity.get("invokedBy") != "states.amazonaws.com"
                or not isinstance(issuer, Mapping) or not isinstance(issuer.get("arn"), str)
                or record.get("recipientAccountId") != match.group(2)
                or record.get("awsRegion") != match.group(1)):
            continue
        reads.append((when, issuer["arn"], match.group(2), match.group(1), secret))
    result = []
    for when, (role, account, region), record in tests:
        matched = next((secret for read_time, read_role, read_account, read_region, secret in reads
                        if read_role == role and read_account == account and read_region == region
                        and abs(read_time - when) <= timedelta(seconds=10)), None)
        if matched is None:
            continue
        identity = record.get("userIdentity")
        result.append({
            "cloud.provider": "aws", "event.source": "states.amazonaws.com",
            "event.name": "TestState", "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account,
            "actor.id": identity.get("arn") if isinstance(identity, Mapping) else None,
            "target.id": matched, "request.sfn_http_connection_secret_read": True,
        })
    return result
