"""CloudWatch dashboard, tag and Contributor Insights management signals.

Dashboard bodies, Contributor Insights definitions and tag values are excluded
from normalized evidence.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any


_SOURCE = "monitoring.amazonaws.com"
_FLAGS = {
    "GetDashboard": "request.cloudwatch_dashboard_body_read",
    "PutDashboard": "request.cloudwatch_dashboard_body_written",
    "TagResource": "request.cloudwatch_resource_tag_added",
    "UntagResource": "request.cloudwatch_resource_tag_removed",
    "PutInsightRule": "request.cloudwatch_insight_rule_definition_written",
    "EnableInsightRules": "request.cloudwatch_insight_rules_enabled",
    "DisableInsightRules": "request.cloudwatch_insight_rules_disabled",
    "DeleteInsightRules": "request.cloudwatch_insight_rules_deleted",
}
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,255}\Z")


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != _SOURCE:
        return None
    name = record.get("eventName")
    if not isinstance(name, str) or name not in _FLAGS:
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity = record.get("userIdentity")
    if (not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account)
            or not isinstance(region, str) or not region
            or not isinstance(identity, Mapping) or not isinstance(identity.get("arn"), str)
            or identity.get("accountId") not in (None, account)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str) or not record["eventTime"]
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name == "GetDashboard")
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping):
        return None
    response = response if isinstance(response, Mapping) else {}
    target = None
    if name in {"GetDashboard", "PutDashboard"}:
        target = request.get("dashboardName")
        if not isinstance(target, str) or not _NAME.fullmatch(target):
            return None
        if name == "PutDashboard":
            body = request.get("dashboardBody")
            if not isinstance(body, str) or not body or len(body) > 1_000_000:
                return None
            if body != "HIDDEN_DUE_TO_SECURITY_REASONS":
                try:
                    parsed = json.loads(body)
                except ValueError:
                    return None
                if not isinstance(parsed, Mapping) or not isinstance(parsed.get("widgets"), list):
                    return None
            if response.get("dashboardValidationMessages"):
                return None
    elif name in {"TagResource", "UntagResource"}:
        target = request.get("resourceARN")
        if (not isinstance(target, str) or not target.startswith("arn:aws:cloudwatch:")
                or f":{account}:" not in target):
            return None
        if name == "TagResource":
            tags = request.get("tags")
            if (not isinstance(tags, list) or not tags
                    or not all(isinstance(x, Mapping) and isinstance(x.get("key"), str)
                               and x["key"] for x in tags)):
                return None
        else:
            keys = request.get("tagKeys")
            if (not isinstance(keys, list) or not keys
                    or not all(isinstance(x, str) and x for x in keys)):
                return None
    elif name == "PutInsightRule":
        target, definition = request.get("ruleName"), request.get("ruleDefinition")
        if not isinstance(target, str) or not _NAME.fullmatch(target) or not isinstance(definition, str):
            return None
        try:
            parsed = json.loads(definition)
        except ValueError:
            return None
        if (not isinstance(parsed, Mapping) or not isinstance(parsed.get("Schema"), Mapping)
                or parsed["Schema"].get("Name") != "CloudWatchLogRule"
                or parsed["Schema"].get("Version") != 1):
            return None
    else:
        names = request.get("ruleNames")
        if (not isinstance(names, list) or not names
                or not all(isinstance(x, str) and _NAME.fullmatch(x) for x in names)
                or response.get("failures")):
            return None
        target = names[0] if len(names) == 1 else None
    return {"cloud.provider": "aws", "event.source": _SOURCE,
            "event.name": name, "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record["eventTime"],
            "account.id": account, "actor.id": identity["arn"], "target.id": target,
            _FLAGS[name]: True}
