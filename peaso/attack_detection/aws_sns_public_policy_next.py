"""Normalize accepted unconditional public SNS topic policy grants."""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any


def _public_actions(value: Any, topic_arn: str) -> tuple[bool, bool]:
    if not isinstance(value, str):
        return False, False
    try:
        policy = json.loads(value)
    except ValueError:
        return False, False
    if not isinstance(policy, Mapping):
        return False, False
    statements = policy.get("Statement")
    statements = [statements] if isinstance(statements, Mapping) else statements
    if not isinstance(statements, list):
        return False, False
    # A deny can override an allow. Without policy evaluation context, stay conservative.
    if any(isinstance(s, Mapping) and str(s.get("Effect", "")).lower() == "deny" for s in statements):
        return False, False
    publish = subscribe = False
    for statement in statements:
        if not isinstance(statement, Mapping) or str(statement.get("Effect", "")).lower() != "allow":
            continue
        if statement.get("Principal") not in ("*", {"AWS": "*"}):
            continue
        if statement.get("Condition") or "NotAction" in statement or "NotPrincipal" in statement:
            continue
        resources = statement.get("Resource")
        resources = [resources] if isinstance(resources, str) else resources
        if not isinstance(resources, list) or topic_arn not in resources:
            continue
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        if not isinstance(actions, list):
            continue
        names = {x.lower() for x in actions if isinstance(x, str)}
        publish |= bool(names.intersection({"sns:publish", "sns:*", "*"}))
        subscribe |= bool(names.intersection({"sns:subscribe", "sns:*", "*"}))
    return publish, subscribe


def normalize_aws_sns_public_policy(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "sns.amazonaws.com"
            or record.get("eventName") != "SetTopicAttributes"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping) or request.get("attributeName") != "Policy":
        return None
    arn = request.get("topicArn")
    account = record.get("recipientAccountId")
    region = record.get("awsRegion")
    if (not isinstance(arn, str) or not isinstance(account, str)
            or not isinstance(region, str) or not re.fullmatch(r"\d{12}", account)
            or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", region)):
        return None
    if not re.fullmatch(rf"arn:aws:sns:{re.escape(region)}:{re.escape(account)}:[A-Za-z0-9_-]+(?:\.fifo)?", arn):
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    publish, subscribe = _public_actions(request.get("attributeValue"), arn)
    actor = record.get("userIdentity")
    actor = actor if isinstance(actor, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "sns.amazonaws.com",
        "event.name": "SetTopicAttributes", "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": actor.get("arn"), "target.id": arn,
        "request.sns_public_publish_grant": publish and not failed,
        "request.sns_public_subscribe_grant": subscribe and not failed,
    }
