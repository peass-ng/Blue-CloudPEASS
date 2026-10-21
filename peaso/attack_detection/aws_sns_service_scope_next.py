"""Recognize SNS service delivery and invoke grants without precise source scope."""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any


_QUEUE_URL = re.compile(
    r"https://sqs\.([a-z]{2}(?:-[a-z]+)+-[0-9])\.amazonaws\.com/([0-9]{12})/([A-Za-z0-9_-]{1,80}(?:\.fifo)?)\Z"
)


def _statements(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, str):
        return []
    try:
        policy = json.loads(value)
    except ValueError:
        return []
    if not isinstance(policy, Mapping):
        return []
    statements = policy.get("Statement")
    statements = [statements] if isinstance(statements, Mapping) else statements
    if not isinstance(statements, list):
        return []
    return [x for x in statements if isinstance(x, Mapping)]


def _actions(statement: Mapping[str, Any]) -> set[str]:
    actions = statement.get("Action")
    actions = [actions] if isinstance(actions, str) else actions
    return {x.lower() for x in actions if isinstance(x, str)} if isinstance(actions, list) else set()


def _queue_scope(value: Any, queue_arn: str, account: str) -> tuple[bool, bool]:
    statements = _statements(value)
    if any(s.get("Effect") == "Deny" for s in statements):
        return False, False
    unscoped = account_wide = False
    for statement in statements:
        if (statement.get("Effect") != "Allow"
                or statement.get("Principal") != {"Service": "sns.amazonaws.com"}
                or "NotAction" in statement or "NotPrincipal" in statement):
            continue
        resources = statement.get("Resource")
        resources = [resources] if isinstance(resources, str) else resources
        if not isinstance(resources, list) or queue_arn not in resources:
            continue
        if not _actions(statement).intersection({"sqs:sendmessage", "sqs:*", "*"}):
            continue
        condition = statement.get("Condition")
        if condition in (None, {}):
            unscoped = True
        elif condition == {"StringEquals": {"aws:SourceAccount": account}}:
            account_wide = True
    return unscoped, account_wide


def normalize_aws_sqs_sns_scope(record: Mapping[str, Any]) -> dict[str, Any] | None:
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
    url = request.get("queueUrl")
    match = _QUEUE_URL.fullmatch(url) if isinstance(url, str) else None
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
    unscoped, account_wide = _queue_scope(attrs.get("Policy"), target, account)
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "sqs.amazonaws.com",
        "event.name": "SetQueueAttributes", "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": target,
        "request.sqs_sns_unscoped_send_grant": unscoped and not failed,
        "request.sqs_sns_account_wide_send_grant": account_wide and not failed,
    }


def normalize_aws_lambda_sns_scope(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "lambda.amazonaws.com"
            or record.get("eventName") != "AddPermission20150331v2"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (not isinstance(account, str) or not re.fullmatch(r"\d{12}", account)
            or not isinstance(region, str) or not isinstance(request, Mapping)
            or not isinstance(response, Mapping)):
        return None
    name = request.get("functionName")
    if not isinstance(name, str):
        return None
    if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
        target = f"arn:aws:lambda:{region}:{account}:function:{name}"
    elif re.fullmatch(rf"arn:aws:lambda:{re.escape(region)}:{account}:function:[A-Za-z0-9_-]{{1,64}}", name):
        target = name
    else:
        return None
    raw_statement = response.get("statement")
    try:
        statement = json.loads(raw_statement) if isinstance(raw_statement, str) else raw_statement
    except ValueError:
        statement = None
    statement = statement if isinstance(statement, Mapping) else {}
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    unscoped = (
        request.get("principal") == "sns.amazonaws.com"
        and request.get("action") == "lambda:InvokeFunction"
        and not request.get("sourceArn") and not request.get("sourceAccount")
        and not request.get("principalOrgID")
        and statement.get("Sid") == request.get("statementId")
        and statement.get("Effect") == "Allow"
        and statement.get("Principal") == {"Service": "sns.amazonaws.com"}
        and statement.get("Action") == "lambda:InvokeFunction"
        and statement.get("Resource") == target
        and not statement.get("Condition")
    )
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "lambda.amazonaws.com",
        "event.name": "AddPermission20150331v2", "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": target,
        "request.lambda_sns_unscoped_invoke_grant": unscoped and not failed,
    }
