"""Normalize unconditional public SQS queue policy grants."""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any


_QUEUE_URL = re.compile(
    r"https://sqs\.([a-z]{2}(?:-[a-z]+)+-[0-9])\.amazonaws\.com/([0-9]{12})/([A-Za-z0-9_-]{1,80}(?:\.fifo)?)\Z"
)


def _public_actions(value: Any, queue_arn: str) -> tuple[bool, bool]:
    if not isinstance(value, str):
        return False, False
    try:
        policy = json.loads(value)
    except (TypeError, ValueError):
        return False, False
    if not isinstance(policy, Mapping):
        return False, False
    statements = policy.get("Statement")
    statements = [statements] if isinstance(statements, Mapping) else statements
    if not isinstance(statements, list):
        return False, False
    if any(isinstance(s, Mapping) and s.get("Effect") == "Deny" for s in statements):
        return False, False
    send = receive = False
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        if (statement.get("Principal") not in ("*", {"AWS": "*"})
                or statement.get("Condition") or "NotAction" in statement
                or "NotPrincipal" in statement):
            continue
        resources = statement.get("Resource")
        resources = [resources] if isinstance(resources, str) else resources
        if not isinstance(resources, list) or queue_arn not in resources:
            continue
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        if not isinstance(actions, list):
            continue
        normalized = {x.lower() for x in actions if isinstance(x, str)}
        send |= bool(normalized.intersection({"sqs:sendmessage", "sqs:*", "*"}))
        receive |= bool(normalized.intersection({"sqs:receivemessage", "sqs:*", "*"}))
    return send, receive


def normalize_aws_sqs_public_policy(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "sqs.amazonaws.com"
            or record.get("eventName") != "SetQueueAttributes"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    queue_url = request.get("queueUrl")
    if not isinstance(queue_url, str):
        return None
    match = _QUEUE_URL.fullmatch(queue_url)
    if not match:
        return None
    region, account, queue = match.groups()
    if record.get("awsRegion") != region or record.get("recipientAccountId") != account:
        return None
    attrs = request.get("attributes")
    if not isinstance(attrs, Mapping):
        return None
    target = f"arn:aws:sqs:{region}:{account}:{queue}"
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    send, receive = _public_actions(attrs.get("Policy"), target)
    actor = record.get("userIdentity")
    actor = actor if isinstance(actor, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": record["eventSource"],
        "event.name": "SetQueueAttributes", "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": actor.get("arn"), "target.id": target,
        "request.sqs_public_send_grant": send and not failed,
        "request.sqs_public_receive_grant": receive and not failed,
    }
