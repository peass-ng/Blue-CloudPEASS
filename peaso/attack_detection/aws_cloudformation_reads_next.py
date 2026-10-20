"""CloudFormation configuration read precursors; values stay out of findings."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_STACK_NAME = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,127}\Z")
_ROUTES = {"DescribeStacks", "GetTemplate", "GetTemplateSummary",
           "ListExports", "DescribeChangeSet"}


def _named_resource(value: Any, account: str, region: str, kind: str) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if kind == "stack" and _STACK_NAME.fullmatch(value):
        return value
    if value.startswith(f"arn:aws:cloudformation:{region}:{account}:{kind}/"):
        return value
    return None


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "cloudformation.amazonaws.com"
            or name not in _ROUTES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not True):
        return None
    request = record.get("requestParameters")
    if name == "ListExports" and request is None:
        request = {}
    if not isinstance(request, Mapping):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if (not isinstance(account, str) or len(account) != 12 or not account.isdigit()
            or not isinstance(region, str) or not region):
        return None
    target = None
    if name != "ListExports":
        target = _named_resource(request.get("stackName"), account, region, "stack")
        if target is None:
            return None
    if name == "DescribeChangeSet":
        change_set = _named_resource(request.get("changeSetName"), account, region, "changeSet")
        if change_set is None and not (isinstance(request.get("changeSetName"), str)
                                       and _STACK_NAME.fullmatch(request["changeSetName"])):
            return None
        target = change_set or request["changeSetName"]
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    response = record.get("responseElements")
    if isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")):
        failed = True
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "cloudformation.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": target,
        "request.cfn_configuration_read": not failed,
    }
