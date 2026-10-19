"""WAF ACL updates that explicitly bypass or remove block behavior."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def _allow_before_same_block(rules: list[Any]) -> bool:
    for allow in rules:
        if not isinstance(allow, Mapping) or not isinstance(allow.get("action"), Mapping):
            continue
        if "allow" not in allow["action"] or not isinstance(allow.get("priority"), int):
            continue
        statement = allow.get("statement")
        if not isinstance(statement, Mapping):
            continue
        for block in rules:
            if (isinstance(block, Mapping) and isinstance(block.get("action"), Mapping)
                    and "block" in block["action"] and isinstance(block.get("priority"), int)
                    and allow["priority"] < block["priority"]
                    and block.get("statement") == statement):
                return True
    return False


def _all_count_with_default_allow(request: Mapping[str, Any], rules: list[Any]) -> bool:
    default = request.get("defaultAction")
    return (isinstance(default, Mapping) and "allow" in default and bool(rules)
            and all(isinstance(rule, Mapping) and isinstance(rule.get("action"), Mapping)
                    and "count" in rule["action"] for rule in rules))


def _managed_group_count_unblocked(request: Mapping[str, Any], rules: list[Any]) -> bool:
    default = request.get("defaultAction")
    if not isinstance(default, Mapping) or "allow" not in default or not rules:
        return False
    managed = False
    for rule in rules:
        if not isinstance(rule, Mapping):
            return False
        action = rule.get("action")
        override = rule.get("overrideAction")
        if isinstance(action, Mapping) and ("block" in action or "captcha" in action or "challenge" in action):
            return False
        if isinstance(override, Mapping) and "count" in override:
            statement = rule.get("statement")
            if isinstance(statement, Mapping) and "managedRuleGroupStatement" in statement:
                managed = True
    return managed


def normalize_aws_waf_web_acl(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "wafv2.amazonaws.com" or record.get("eventName") != "UpdateWebACL":
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    acl_id, name, rules = request.get("id"), request.get("name"), request.get("rules")
    if (not isinstance(acl_id, str) or re.fullmatch(r"[0-9a-f-]{36}", acl_id) is None
            or not isinstance(name, str) or not name or not isinstance(rules, list)):
        return None
    accepted = (not record.get("errorCode") and not record.get("errorMessage")
                and isinstance(response.get("nextLockToken"), str)
                and bool(response["nextLockToken"]))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "wafv2.amazonaws.com",
        "event.name": "UpdateWebACL", "event.outcome": "success" if accepted else "failure",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId"), "actor.id": identity.get("arn"),
        "target.id": acl_id,
        "request.waf_allow_overrides_same_block": accepted and _allow_before_same_block(rules),
        "request.waf_all_rules_count_default_allow": accepted and _all_count_with_default_allow(request, rules),
        "request.waf_managed_group_count_unblocked": accepted and _managed_group_count_unblocked(request, rules),
    }
