"""ECR repository scanning and wildcard image-read policy changes."""

from __future__ import annotations

from collections.abc import Mapping
import json
from typing import Any


_READ_ACTIONS = {"ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"}


def _wildcard_image_read(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        policy = json.loads(value)
    except (TypeError, ValueError):
        return False
    if not isinstance(policy, Mapping):
        return False
    statements = policy.get("Statement")
    statements = [statements] if isinstance(statements, Mapping) else statements
    if not isinstance(statements, list):
        return False
    if any(isinstance(s, Mapping) and s.get("Effect") == "Deny" for s in statements):
        return False
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        if statement.get("Condition") or "NotAction" in statement or "NotPrincipal" in statement:
            continue
        principal = statement.get("Principal")
        wildcard = principal == "*" or isinstance(principal, Mapping) and principal.get("AWS") == "*"
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        if (wildcard and isinstance(actions, list) and all(isinstance(a, str) for a in actions)
                and _READ_ACTIONS.issubset(set(actions))):
            return True
    return False


def normalize_aws_ecr_policy(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "ecr.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"PutImageScanningConfiguration", "SetRepositoryPolicy"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("readOnly") is not False or record.get("managementEvent") is not True):
        return None
    request = record.get("requestParameters")
    response = record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    repo = request.get("repositoryName")
    account = record.get("recipientAccountId")
    if (not isinstance(repo, str) or not repo or not isinstance(account, str)
            or response.get("repositoryName") != repo or response.get("registryId") != account):
        return None
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or response.get("errorCode") or response.get("errorMessage"))
    scan_request = request.get("imageScanningConfiguration")
    scan_response = response.get("imageScanningConfiguration")
    scan_request = scan_request if isinstance(scan_request, Mapping) else {}
    scan_response = scan_response if isinstance(scan_response, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "ecr.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": repo,
        "request.ecr_scan_on_push_disabled": (
            name == "PutImageScanningConfiguration" and not failed
            and scan_request.get("scanOnPush") is False
            and scan_response.get("scanOnPush") is False
        ),
        "request.ecr_wildcard_image_read_grant": (
            name == "SetRepositoryPolicy" and not failed
            and _wildcard_image_read(request.get("policyText"))
            and _wildcard_image_read(response.get("policyText"))
        ),
    }
