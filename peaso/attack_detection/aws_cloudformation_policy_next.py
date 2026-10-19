"""CloudFormation stack policy that explicitly allows every update."""

from __future__ import annotations

from collections.abc import Mapping
import json
from typing import Any


def normalize_aws_cloudformation_stack_policy(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "cloudformation.amazonaws.com"
            or record.get("eventName") != "SetStackPolicy"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    stack = request.get("stackName")
    body = request.get("stackPolicyBody")
    if not isinstance(stack, str) or not stack or not isinstance(body, str):
        return None
    try:
        policy = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    statement = policy.get("Statement") if isinstance(policy, Mapping) else None
    if isinstance(statement, Mapping):
        statement = [statement]
    broad_allow = False
    if isinstance(statement, list) and len(statement) == 1 and isinstance(statement[0], Mapping):
        item = statement[0]
        actions = item.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        resources = item.get("Resource")
        resources = [resources] if isinstance(resources, str) else resources
        broad_allow = (item.get("Effect") == "Allow" and item.get("Principal") == "*"
                       and isinstance(actions, list) and "Update:*" in actions
                       and isinstance(resources, list) and "*" in resources
                       and not item.get("Condition") and "NotAction" not in item and "NotResource" not in item)
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    return {
        "cloud.provider": "aws", "event.source": "cloudformation.amazonaws.com",
        "event.name": "SetStackPolicy", "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId") or identity.get("accountId"),
        "actor.id": identity.get("arn"), "target.id": stack,
        "request.stack_policy_all_updates_allowed": not failed and broad_allow,
    }
