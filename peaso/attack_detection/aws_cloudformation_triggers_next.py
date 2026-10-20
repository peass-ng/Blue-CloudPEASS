"""CloudFormation signaling and stored-role change-set precursors."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any


_NAME = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,127}\Z")


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result if result.tzinfo is not None else None


def _base(record: Mapping[str, Any]) -> tuple[str, str, str, Mapping[str, Any], Mapping[str, Any] | None] | None:
    if (record.get("eventSource") != "cloudformation.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response = record.get("requestParameters"), record.get("responseElements")
    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    if (not isinstance(account, str) or len(account) != 12 or not account.isdigit()
            or not isinstance(region, str) or not region
            or not isinstance(actor, str) or not actor.startswith("arn:")
            or not isinstance(request, Mapping)):
        return None
    if isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")):
        return None
    return account, region, actor, request, response if isinstance(response, Mapping) else None


def _stack_id(value: Any, account: str, region: str, name: str) -> bool:
    return (isinstance(value, str)
            and value.startswith(f"arn:aws:cloudformation:{region}:{account}:stack/{name}/"))


def _change_id(value: Any, account: str, region: str, name: str) -> bool:
    return (isinstance(value, str)
            and value.startswith(f"arn:aws:cloudformation:{region}:{account}:changeSet/{name}/"))


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if name not in {"SignalResource", "UpdateStack"}:
        return None
    base = _base(record)
    if base is None:
        return None
    account, region, actor, request, response = base
    stack = request.get("stackName")
    if not isinstance(stack, str) or not _NAME.fullmatch(stack):
        return None
    if name == "SignalResource":
        logical, unique = request.get("logicalResourceId"), request.get("uniqueId")
        selected = (request.get("status") == "SUCCESS"
                    and isinstance(logical, str) and bool(_NAME.fullmatch(logical))
                    and isinstance(unique, str) and bool(unique))
        target = stack
        field = "request.cfn_success_signal_submitted"
    else:
        role = request.get("roleARN")
        selected = (isinstance(role, str)
                    and role.startswith(f"arn:aws:iam::{account}:role/")
                    and response is not None
                    and _stack_id(response.get("stackId"), account, region, stack))
        target = response.get("stackId") if response else None
        field = "request.cfn_update_stack_service_role_passed"
    if not selected:
        return None
    return {"cloud.provider": "aws", "event.source": "cloudformation.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": actor, "target.id": target,
            field: True}


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    selected = []
    for record in records:
        name = record.get("eventName")
        if name not in {"CreateStack", "CreateChangeSet", "ExecuteChangeSet"}:
            continue
        base = _base(record)
        if base is None:
            continue
        when = _when(record.get("eventTime"))
        event_id = record.get("eventID")
        if when is None or not isinstance(event_id, str) or not event_id:
            continue
        selected.append((when, event_id, name, *base, record))
    selected.sort(key=lambda item: (item[0], item[1]))
    stacks: dict[tuple[str, str, str], tuple[datetime, str]] = {}
    changes: dict[tuple[str, str, str], tuple[datetime, str]] = {}
    out: list[dict[str, Any]] = []
    for when, event_id, name, account, region, actor, request, response, record in selected:
        stack = request.get("stackName")
        if name == "CreateStack":
            if (not isinstance(stack, str) or not _NAME.fullmatch(stack)
                    or response is None or not _stack_id(response.get("stackId"), account, region, stack)
                    or not isinstance(request.get("roleARN"), str)
                    or not request["roleARN"].startswith(f"arn:aws:iam::{account}:role/")):
                continue
            stacks[(account, region, stack)] = (when, actor)
        elif name == "CreateChangeSet":
            change = request.get("changeSetName")
            if (not isinstance(stack, str) or not _NAME.fullmatch(stack)
                    or not isinstance(change, str) or not _NAME.fullmatch(change)
                    or response is None or not _change_id(response.get("id"), account, region, change)):
                continue
            change_id = response["id"]
            changes[(account, region, change_id)] = (when, actor)
            prior = stacks.get((account, region, stack))
            if (prior is not None and prior[1] != actor
                    and timedelta(0) <= when - prior[0] <= timedelta(hours=1)
                    and not request.get("roleARN")):
                out.append({"cloud.provider": "aws", "event.source": "cloudformation.amazonaws.com",
                            "event.name": "CloudFormationCrossActorStoredRoleChangeSetCreated",
                            "event.outcome": "success", "event.id": event_id,
                            "event.time": record.get("eventTime"), "account.id": account,
                            "actor.id": actor, "target.id": change_id,
                            "request.cfn_cross_actor_stored_role_change_set_created": True})
        else:
            change_id = request.get("changeSetName")
            if not isinstance(change_id, str):
                continue
            prior = changes.pop((account, region, change_id), None)
            if (prior is None or prior[1] == actor
                    or not timedelta(0) <= when - prior[0] <= timedelta(hours=1)):
                continue
            out.append({"cloud.provider": "aws", "event.source": "cloudformation.amazonaws.com",
                        "event.name": "CloudFormationCrossActorChangeSetExecuted",
                        "event.outcome": "success", "event.id": event_id,
                        "event.time": record.get("eventTime"), "account.id": account,
                        "actor.id": actor, "target.id": change_id,
                        "request.cfn_cross_actor_change_set_executed": True})
    return out
