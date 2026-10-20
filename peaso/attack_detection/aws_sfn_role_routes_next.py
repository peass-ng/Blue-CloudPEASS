"""Recognize Step Functions delegated state execution and role changes."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any


_MACHINE = re.compile(r"arn:aws:states:([a-z0-9-]+):(\d{12}):stateMachine:([A-Za-z0-9+!@_.-]+)\Z")


def _base(record: Mapping[str, Any], names: set[str]) -> tuple[Mapping[str, Any], str, str] | None:
    if (record.get("eventSource") != "states.amazonaws.com"
            or record.get("eventName") not in names
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region, request = (record.get("recipientAccountId"), record.get("awsRegion"),
                                record.get("requestParameters"))
    if (not isinstance(account, str) or re.fullmatch(r"\d{12}", account) is None
            or not isinstance(region, str) or not isinstance(request, Mapping)):
        return None
    return request, region, account


def _role(value: Any, account: str) -> bool:
    return (isinstance(value, str)
            and re.fullmatch(rf"arn:aws:iam::{account}:role/[A-Za-z0-9_+=,.@\-/]+", value) is not None)


def _actor(record: Mapping[str, Any]) -> str | None:
    identity = record.get("userIdentity")
    return identity.get("arn") if isinstance(identity, Mapping) and isinstance(identity.get("arn"), str) else None


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result if result.tzinfo else None


def normalize_aws_sfn_role_routes(record: Mapping[str, Any]) -> dict[str, Any] | None:
    parsed = _base(record, {"TestState", "UpdateStateMachine"})
    if parsed is None:
        return None
    request, region, account = parsed
    response = record.get("responseElements")
    response = response if isinstance(response, Mapping) else {}
    name = record["eventName"]
    role = request.get("roleArn")
    if not _role(role, account):
        return None
    if name == "TestState":
        if (request.get("definition") != "HIDDEN_DUE_TO_SECURITY_REASONS"
                or response.get("status") != "SUCCEEDED"):
            return None
        target = role
        flag = "sfn_teststate_passed_role"
    else:
        target = request.get("stateMachineArn")
        match = _MACHINE.fullmatch(target) if isinstance(target, str) else None
        if (not match or match.group(1) != region or match.group(2) != account
                or not isinstance(response.get("revisionId"), str)):
            return None
        flag = "sfn_role_specified_in_update"
    return {
        "cloud.provider": "aws", "event.source": "states.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": _actor(record), "target.id": target,
        f"request.{flag}": True,
    }


def correlate_aws_sfn_new_machine_start(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    created: dict[tuple[str, str, str], tuple[datetime, Mapping[str, Any]]] = {}
    starts: list[tuple[datetime, str, str, str, Mapping[str, Any]]] = []
    for record in records:
        parsed = _base(record, {"CreateStateMachine", "StartExecution"})
        if parsed is None:
            continue
        request, region, account = parsed
        response = record.get("responseElements")
        response = response if isinstance(response, Mapping) else {}
        actor, when = _actor(record), _time(record.get("eventTime"))
        if not actor or when is None:
            continue
        if record["eventName"] == "CreateStateMachine":
            arn = response.get("stateMachineArn")
            match = _MACHINE.fullmatch(arn) if isinstance(arn, str) else None
            if (not match or match.group(1) != region or match.group(2) != account
                    or match.group(3) != request.get("name")
                    or not _role(request.get("roleArn"), account)
                    or request.get("definition") != "HIDDEN_DUE_TO_SECURITY_REASONS"):
                continue
            created[(account, arn, actor)] = when, record
        else:
            arn = request.get("stateMachineArn")
            match = _MACHINE.fullmatch(arn) if isinstance(arn, str) else None
            execution = response.get("executionArn")
            if (not match or match.group(1) != region or match.group(2) != account
                    or not isinstance(execution, str)
                    or not execution.startswith(f"arn:aws:states:{region}:{account}:execution:{match.group(3)}:")):
                continue
            starts.append((when, account, arn, actor, record))
    result = []
    for when, account, arn, actor, record in starts:
        previous = created.get((account, arn, actor))
        if previous is None or not previous[0] <= when <= previous[0] + timedelta(minutes=15):
            continue
        result.append({
            "cloud.provider": "aws", "event.source": "states.amazonaws.com",
            "event.name": "StartExecution", "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": actor, "target.id": arn,
            "request.sfn_new_machine_started_with_role": True,
        })
    return result
