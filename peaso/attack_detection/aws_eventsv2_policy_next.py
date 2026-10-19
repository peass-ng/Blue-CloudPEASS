"""Unconditional external grant in an enhanced EventBridge bus policy."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

_BUS = re.compile(r"arn:aws:events:([a-z0-9-]+):(\d{12}):event-busv2/([A-Za-z0-9._-]+)/([a-z0-9]{25})\Z")
_PRINCIPAL = re.compile(r"arn:aws:iam::(\d{12}):(?:root|role/[A-Za-z0-9+=,.@_/-]+|user/[A-Za-z0-9+=,.@_/-]+)\Z")
_ACTIONS = {"events:PutEvents", "events:PutRawEvents", "events:CreateSubscriber"}


def _external_grant(document: Any, bus: str, owner: str) -> bool:
    if not isinstance(document, str):
        return False
    try:
        parsed = json.loads(document)
    except json.JSONDecodeError:
        return False
    statements = parsed.get("Statement") if isinstance(parsed, Mapping) else None
    statements = [statements] if isinstance(statements, Mapping) else statements
    if not isinstance(statements, list):
        return False
    for item in statements:
        if not isinstance(item, Mapping) or item.get("Effect") != "Allow":
            continue
        if item.get("Condition") or "NotAction" in item or "NotPrincipal" in item or "NotResource" in item:
            continue
        principal = item.get("Principal")
        principal = principal.get("AWS") if isinstance(principal, Mapping) else principal
        principals = principal if isinstance(principal, list) else [principal]
        external = any(isinstance(p, str) and (match := _PRINCIPAL.fullmatch(p))
                       and match.group(1) != owner for p in principals)
        actions = item.get("Action")
        actions = actions if isinstance(actions, list) else [actions]
        resources = item.get("Resource")
        resources = resources if isinstance(resources, list) else [resources]
        if external and bus in resources and any(a in _ACTIONS for a in actions):
            return True
    return False


def normalize_aws_eventsv2_policy(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "eventsv2.amazonaws.com"
            or record.get("eventName") != "PutResourcePolicy"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    bus = request.get("resourceArn")
    match = _BUS.fullmatch(bus) if isinstance(bus, str) else None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if not match or match.group(1) != region or match.group(2) != account:
        return None
    if (request.get("policyName", "default") != "default"
            or response.get("policyName") != "default"
            or response.get("resourceArn") != bus
            or not isinstance(response.get("revisionId"), str)
            or not response["revisionId"]):
        return None
    resources = record.get("resources")
    if not isinstance(resources, list) or not any(isinstance(item, Mapping)
            and item.get("accountId") == account and item.get("ARN") == bus
            for item in resources):
        return None
    accepted = not record.get("errorCode") and not record.get("errorMessage")
    granted = accepted and _external_grant(request.get("policyDocument"), bus, account)
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": "eventsv2.amazonaws.com",
            "event.name": "PutResourcePolicy",
            "event.outcome": "success" if accepted else "failure",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity.get("arn"), "target.id": bus,
            "request.eventsv2_external_bus_grant": granted}
