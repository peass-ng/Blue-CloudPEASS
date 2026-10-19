"""Recognize accepted SNS configuration changes with explicit risky values."""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any


def _object(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if not isinstance(value, str):
        return None
    try:
        parsed = json.loads(value)
    except ValueError:
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _org_subscribe_grant(value: Any, topic_arn: str) -> bool:
    policy = _object(value)
    if policy is None:
        return False
    statements = policy.get("Statement", [])
    if isinstance(statements, Mapping):
        statements = [statements]
    if not isinstance(statements, list):
        return False
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        if statement.get("Principal") not in ("*", {"AWS": "*"}):
            continue
        action = statement.get("Action")
        actions = [action] if isinstance(action, str) else action
        if not isinstance(actions, list) or not any(isinstance(a, str) and a.lower() in ("sns:subscribe", "sns:*") for a in actions):
            continue
        resource = statement.get("Resource")
        resources = [resource] if isinstance(resource, str) else resource
        if not isinstance(resources, list) or topic_arn not in resources:
            continue
        condition = statement.get("Condition")
        if not isinstance(condition, Mapping):
            continue
        terms = condition.get("StringEquals")
        org = terms.get("aws:PrincipalOrgID") if isinstance(terms, Mapping) else None
        if isinstance(org, str) and re.fullmatch(r"o-[a-z0-9]{10,32}", org):
            return True
    return False


def _replay_requested(value: Any) -> bool:
    policy = _object(value)
    if policy is None or policy.get("PointType") != "Timestamp":
        return False
    start = policy.get("StartingPoint")
    return isinstance(start, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z", start) is not None


def normalize_aws_sns_topic_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    source, name = record.get("eventSource"), record.get("eventName")
    if source != "sns.amazonaws.com" or name not in {"SetTopicAttributes", "SetSubscriptionAttributes", "PutDataProtectionPolicy", "Subscribe"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    account = record.get("recipientAccountId")
    if not isinstance(request, Mapping) or not isinstance(account, str) or not re.fullmatch(r"\d{12}", account):
        return None
    arn = request.get("subscriptionArn") if name == "SetSubscriptionAttributes" else request.get("topicArn") or request.get("resourceArn")
    suffix = r":[a-f0-9-]+" if name == "SetSubscriptionAttributes" else ""
    if not isinstance(arn, str) or not re.fullmatch(rf"arn:aws:sns:[a-z0-9-]+:{re.escape(account)}:[A-Za-z0-9_-]+(?:\.fifo)?{suffix}", arn):
        return None
    response = record.get("responseElements")
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")))
    attr = request.get("attributeName")
    value = request.get("attributeValue")
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": source, "event.name": name,
        "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": arn,
        "request.sns_kms_key_cleared": not failed and name == "SetTopicAttributes" and attr == "KmsMasterKeyId" and value == "",
        "request.sns_filter_cleared": not failed and name == "SetSubscriptionAttributes" and attr == "FilterPolicy" and _object(value) == {},
        "request.sns_org_wildcard_subscribe_grant": not failed and name == "SetTopicAttributes" and attr == "Policy" and _org_subscribe_grant(value, arn),
        "request.sns_data_protection_cleared": not failed and name == "PutDataProtectionPolicy" and request.get("dataProtectionPolicy") == "",
        "request.sns_replay_subscribe_requested": not failed and name == "Subscribe" and isinstance(request.get("attributes"), Mapping) and _replay_requested(request["attributes"].get("ReplayPolicy")),
        "request.sns_replay_policy_set": not failed and name == "SetSubscriptionAttributes" and attr == "ReplayPolicy" and _replay_requested(value),
        "request.sns_archive_cleared": not failed and name == "SetTopicAttributes" and attr == "ArchivePolicy" and _object(value) == {},
    }
