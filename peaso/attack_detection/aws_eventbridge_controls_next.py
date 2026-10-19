"""EventBridge bus permission and rule-disable requests."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_eventbridge_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "events.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"PutPermission", "DisableRule"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    account = record.get("recipientAccountId")
    if not isinstance(account, str) or re.fullmatch(r"\d{12}", account) is None:
        return None
    target = request.get("eventBusName" if name == "PutPermission" else "name")
    if not isinstance(target, str) or not target:
        return None
    principal = request.get("principal")
    external = (principal == "*" or isinstance(principal, str)
                and re.fullmatch(r"\d{12}", principal) is not None and principal != account)
    response = record.get("responseElements")
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "events.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": target,
        "request.eventbridge_nonowner_put_events_grant": (
            not failed and name == "PutPermission" and external
            and request.get("action") == "events:PutEvents"
            and isinstance(request.get("statementId"), str) and bool(request["statementId"])
        ),
        "request.eventbridge_rule_disable_observed": not failed and name == "DisableRule",
    }
