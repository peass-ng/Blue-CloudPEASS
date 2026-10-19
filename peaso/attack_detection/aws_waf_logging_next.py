"""WAF logging configurations that drop selected or default traffic."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_ACL_ARN = re.compile(r"arn:aws:wafv2:[a-z0-9-]+:\d{12}:(?:regional|global)/webacl/[A-Za-z0-9_-]+/[0-9a-f-]{36}")


def _drops_logs(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    logging_filter = value.get("loggingFilter")
    if not isinstance(logging_filter, Mapping):
        return False
    if logging_filter.get("defaultBehavior") == "DROP":
        return True
    filters = logging_filter.get("filters")
    return isinstance(filters, list) and any(
        isinstance(item, Mapping) and item.get("behavior") == "DROP" for item in filters)


def _redacts_request_location(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    fields = value.get("redactedFields")
    return isinstance(fields, list) and any(
        isinstance(field, Mapping) and ("uriPath" in field or "queryString" in field)
        for field in fields)


def normalize_aws_waf_logging(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "wafv2.amazonaws.com" or record.get("eventName") != "PutLoggingConfiguration":
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    sent, returned = request.get("loggingConfiguration"), response.get("loggingConfiguration")
    if not isinstance(sent, Mapping) or not isinstance(returned, Mapping):
        return None
    arn = sent.get("resourceArn")
    if not isinstance(arn, str) or _ACL_ARN.fullmatch(arn) is None:
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "wafv2.amazonaws.com",
        "event.name": "PutLoggingConfiguration", "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId"), "actor.id": identity.get("arn"),
        "target.id": arn,
        "request.waf_logging_drops_traffic": (
            not failed and returned.get("resourceArn") == arn
            and _drops_logs(sent) and _drops_logs(returned)
        ),
        "request.waf_logging_redacts_location": (
            not failed and returned.get("resourceArn") == arn
            and _redacts_request_location(sent) and _redacts_request_location(returned)
        ),
    }


def normalize_aws_waf_deletion(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "wafv2.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"DeleteLoggingConfiguration", "DeleteWebACL"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    target = request.get("resourceArn") if name == "DeleteLoggingConfiguration" else request.get("id")
    if name == "DeleteLoggingConfiguration":
        valid_target = isinstance(target, str) and _ACL_ARN.fullmatch(target) is not None
    else:
        valid_target = (isinstance(target, str) and re.fullmatch(r"[0-9a-f-]{36}", target) is not None
                        and isinstance(request.get("name"), str) and bool(request["name"])
                        and request.get("scope") in {"REGIONAL", "CLOUDFRONT"})
    if not valid_target:
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "wafv2.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId"), "actor.id": identity.get("arn"),
        "target.id": target,
        "request.waf_logging_deleted": not failed and name == "DeleteLoggingConfiguration",
        "request.waf_web_acl_deleted": not failed and name == "DeleteWebACL",
    }


def normalize_aws_waf_disassociation(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "wafv2.amazonaws.com" or record.get("eventName") != "DisassociateWebACL":
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    resource = request.get("resourceArn")
    if (not isinstance(resource, str) or re.fullmatch(
            r"arn:aws:apigateway:[a-z0-9-]+::/restapis/[a-z0-9]+/stages/[A-Za-z0-9_-]+",
            resource) is None):
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "wafv2.amazonaws.com",
        "event.name": "DisassociateWebACL", "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId"), "actor.id": identity.get("arn"),
        "target.id": resource,
        "request.waf_api_stage_disassociated": not failed,
    }
