"""Normalize accepted SQS queue redrive and broad org policy changes."""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any


def _json_object(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if not isinstance(value, str):
        return None
    try:
        parsed = json.loads(value)
    except ValueError:
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _org_receive_grant(value: Any, target_arn: str) -> bool:
    policy = _json_object(value)
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
        if not isinstance(actions, list) or not any(a in ("sqs:ReceiveMessage", "sqs:*") for a in actions):
            continue
        resource = statement.get("Resource")
        resources = [resource] if isinstance(resource, str) else resource
        if not isinstance(resources, list) or target_arn not in resources:
            continue
        condition = statement.get("Condition")
        if not isinstance(condition, Mapping):
            continue
        for operator in ("StringEquals", "ForAnyValue:StringEquals"):
            terms = condition.get(operator)
            if isinstance(terms, Mapping):
                org = terms.get("aws:PrincipalOrgID")
                values = [org] if isinstance(org, str) else org
                if isinstance(values, list) and any(isinstance(v, str) and re.fullmatch(r"o-[a-z0-9]{10,32}", v) for v in values):
                    return True
    return False


def normalize_aws_sqs_redrive(record: Mapping[str, Any]) -> dict[str, Any] | None:
    source, name = record.get("eventSource"), record.get("eventName")
    if source != "sqs.amazonaws.com" or name not in {"SetQueueAttributes", "StartMessageMoveTask"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    account = record.get("recipientAccountId")
    request = record.get("requestParameters")
    if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account) or not isinstance(request, Mapping):
        return None
    response = record.get("responseElements")
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    target = None
    redrive_max_one = allow_all = org_receive = custom_move = False
    if name == "SetQueueAttributes":
        url = request.get("queueUrl")
        match = re.fullmatch(rf"https://sqs\.([a-z0-9-]+)\.amazonaws\.com/{re.escape(account)}/([A-Za-z0-9_-]+(?:\.fifo)?)", url) if isinstance(url, str) else None
        if match is None:
            return None
        region, queue_name = match.groups()
        target = f"arn:aws:sqs:{region}:{account}:{queue_name}"
        attrs = request.get("attributes")
        attrs = attrs if isinstance(attrs, Mapping) else {}
        policy = _json_object(attrs.get("RedrivePolicy"))
        dlq_arn = policy.get("deadLetterTargetArn") if policy is not None else None
        retry_count = policy.get("maxReceiveCount") if policy is not None else None
        redrive_max_one = (not failed and policy is not None
                           and (retry_count == "1" or type(retry_count) is int and retry_count == 1)
                           and isinstance(dlq_arn, str)
                           and re.fullmatch(rf"arn:aws:sqs:{re.escape(region)}:{re.escape(account)}:[A-Za-z0-9_-]+(?:\.fifo)?", dlq_arn) is not None
                           and dlq_arn != target)
        allow = _json_object(attrs.get("RedriveAllowPolicy"))
        allow_all = not failed and allow is not None and allow.get("redrivePermission") == "allowAll"
        org_receive = not failed and _org_receive_grant(attrs.get("Policy"), target)
    else:
        source_arn = request.get("sourceArn")
        destination_arn = request.get("destinationArn")
        if not isinstance(source_arn, str) or not re.fullmatch(rf"arn:aws:sqs:[a-z0-9-]+:{re.escape(account)}:[A-Za-z0-9_-]+(?:\.fifo)?", source_arn):
            return None
        target = source_arn
        region = source_arn.split(":")[3]
        custom_move = (not failed and isinstance(destination_arn, str)
                       and re.fullmatch(rf"arn:aws:sqs:{re.escape(region)}:{re.escape(account)}:[A-Za-z0-9_-]+(?:\.fifo)?", destination_arn) is not None
                       and destination_arn != source_arn)
    return {
        "cloud.provider": "aws", "event.source": source, "event.name": name,
        "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": target,
        "request.sqs_redrive_max_one": redrive_max_one,
        "request.sqs_redrive_allow_all": allow_all,
        "request.sqs_org_wildcard_receive_grant": org_receive,
        "request.sqs_custom_redrive_started": custom_move,
    }
