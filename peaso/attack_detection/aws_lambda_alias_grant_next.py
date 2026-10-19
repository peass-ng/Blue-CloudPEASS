"""Qualified Lambda invoke permissions granted to an AWS account."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_lambda_qualified_grant(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "lambda.amazonaws.com"
            or record.get("eventName") != "AddPermission20150331v2"):
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    qualifier = request.get("qualifier")
    principal = request.get("principal")
    action = request.get("action")
    function = request.get("functionName")
    qualified_account_grant = (
        isinstance(qualifier, str) and bool(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", qualifier))
        and isinstance(principal, str) and re.fullmatch(r"\d{12}", principal) is not None
        and action in {"lambda:InvokeFunction", "lambda:*", "*"}
        and isinstance(function, str) and bool(function)
    )
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    return {
        "cloud.provider": "aws", "event.source": "lambda.amazonaws.com",
        "event.name": "AddPermission20150331v2", "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId") or identity.get("accountId"),
        "actor.id": identity.get("arn"),
        "target.id": f"{function}:{qualifier}" if isinstance(function, str) and isinstance(qualifier, str) else function,
        "request.lambda_qualified_account_invoke_grant": not failed and qualified_account_grant,
    }
