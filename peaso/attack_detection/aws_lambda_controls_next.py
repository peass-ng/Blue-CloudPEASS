"""Lambda concurrency, recursion, URL, and deletion requests."""

from __future__ import annotations

from collections.abc import Mapping
import json
from typing import Any


def _public_url_statement(value: Any, request: Mapping[str, Any], account: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        statement = json.loads(value)
    except ValueError:
        return False
    if not isinstance(statement, Mapping):
        return False
    resource = statement.get("Resource")
    return (statement.get("Effect") == "Allow" and statement.get("Principal") == "*"
            and statement.get("Action") == "lambda:InvokeFunctionUrl"
            and statement.get("Sid") == request.get("statementId")
            and isinstance(resource, str) and f":{account}:function:{request.get('functionName')}" in resource)


def normalize_aws_lambda_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "lambda.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"PutFunctionConcurrency20171031", "PutFunctionRecursionConfig",
                    "CreateFunctionUrlConfig", "UpdateFunctionUrlConfig", "AddPermission20150331v2",
                    "DeleteFunction20150331"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    function = request.get("functionName")
    if not isinstance(function, str) or not function:
        return None
    response = record.get("responseElements")
    account = record.get("recipientAccountId")
    if not isinstance(account, str):
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "lambda.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": function,
        "request.zero_reserved_concurrency": (
            not failed and name == "PutFunctionConcurrency20171031"
            and type(request.get("reservedConcurrentExecutions")) is int
            and request["reservedConcurrentExecutions"] == 0
        ),
        "request.recursive_loop_allowed": (
            not failed and name == "PutFunctionRecursionConfig"
            and request.get("recursiveLoop") == "Allow"
            and isinstance(response, Mapping) and response.get("recursiveLoop") == "Allow"
        ),
        "request.function_url_auth_none": (
            not failed and name in {"CreateFunctionUrlConfig", "UpdateFunctionUrlConfig"}
            and request.get("authType") == "NONE" and isinstance(response, Mapping)
            and response.get("authType") == "NONE"
            and isinstance(response.get("functionArn"), str)
            and f":{account}:function:{function}" in response["functionArn"]
        ),
        "request.public_function_url_grant": (
            not failed and name == "AddPermission20150331v2"
            and request.get("principal") == "*" and request.get("action") == "lambda:InvokeFunctionUrl"
            and request.get("functionUrlAuthType") == "NONE" and isinstance(response, Mapping)
            and _public_url_statement(response.get("statement"), request, account)
        ),
        "request.function_deleted": not failed and name == "DeleteFunction20150331",
    }
