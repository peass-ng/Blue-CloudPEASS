"""Normalize explicit Lambda control-plane changes visible in CloudTrail."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from .aws_security_controls import _arn, _event_time


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+\Z")
_FUNCTION = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_NAMES = {
    "PutFunctionConcurrency20171031", "PutFunctionRecursionConfig",
    "CreateFunctionUrlConfig", "UpdateFunctionUrlConfig",
    "AddPermission20150331v2", "DeleteFunction20150331",
}


def _function_arn(value: Any, account: str, region: str, partition: str) -> str | None:
    if isinstance(value, str) and _FUNCTION.fullmatch(value):
        return f"arn:{partition}:lambda:{region}:{account}:function:{value}"
    parts = _arn(value)
    if (parts and parts[1] == partition and parts[2] == "lambda"
            and parts[3] == region and parts[4] == account
            and parts[5].startswith("function:")):
        name = parts[5][len("function:"):]
        if _FUNCTION.fullmatch(name):
            return value
    return None


def normalize_aws_lambda_control(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Report accepted writes, without inferring previous state or actual use."""
    name = record.get("eventName")
    if (record.get("eventSource") != "lambda.amazonaws.com" or name not in _NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") not in (None, True)
            or record.get("readOnly") not in (None, False)
            or record.get("errorCode") or record.get("errorMessage")
            or "responseElements" not in record):
        return None
    request = record.get("requestParameters")
    response = record.get("responseElements")
    identity = record.get("userIdentity")
    if (not isinstance(request, Mapping) or not isinstance(identity, Mapping)
            or response is not None and not isinstance(response, Mapping)
            or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage"))):
        return None
    account = record.get("recipientAccountId")
    region = record.get("awsRegion")
    actor_arn = identity.get("arn")
    actor = _arn(actor_arn)
    event_id = record.get("eventID")
    event_time = _event_time(record.get("eventTime"))
    try:
        UUID(event_id)
    except (TypeError, ValueError, AttributeError):
        return None
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or actor is None or actor[4] != account or identity.get("accountId") != account
            or not isinstance(identity.get("type"), str) or not identity["type"]
            or event_time is None):
        return None
    function_arn = _function_arn(request.get("functionName"), account, region, actor[1])
    if function_arn is None:
        return None
    zero_concurrency = (name == "PutFunctionConcurrency20171031"
                        and type(request.get("reservedConcurrentExecutions")) is int
                        and request["reservedConcurrentExecutions"] == 0)
    recursion_allowed = name == "PutFunctionRecursionConfig" and request.get("recursiveLoop") == "Allow"
    unauthenticated_url = (name in {"CreateFunctionUrlConfig", "UpdateFunctionUrlConfig"}
                           and request.get("authType") == "NONE")
    public_url_grant = (name == "AddPermission20150331v2"
                        and request.get("principal") == "*"
                        and request.get("action") == "lambda:InvokeFunctionUrl"
                        and request.get("functionUrlAuthType") == "NONE")
    deleted_function = name == "DeleteFunction20150331"
    if not any((zero_concurrency, recursion_allowed, unauthenticated_url,
                public_url_grant, deleted_function)):
        return None
    return {
        "cloud.provider": "aws", "cloud.region": region,
        "event.source": "lambda.amazonaws.com", "event.name": name,
        "event.outcome": "success", "event.id": event_id, "event.time": event_time,
        "account.id": account, "actor.id": actor_arn, "actor.kind": identity["type"],
        "target.id": function_arn,
        "request.zero_reserved_concurrency": zero_concurrency,
        "request.recursive_loop_allowed": recursion_allowed,
        "request.function_url_auth_none": unauthenticated_url,
        "request.public_function_url_grant": public_url_grant,
        "request.function_deleted": deleted_function,
    }
