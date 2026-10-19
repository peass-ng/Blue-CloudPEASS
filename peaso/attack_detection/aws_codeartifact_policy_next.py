"""CodeArtifact repository policy granting another account package access."""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any


_PACKAGE_ACTIONS = {"codeartifact:ReadFromRepository", "codeartifact:GetPackageVersionAsset",
                    "codeartifact:PublishPackageVersion", "codeartifact:*", "*"}


def _document(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _external_package_grant(policy: Mapping[str, Any], account: str) -> bool:
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
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        if not isinstance(actions, list) or not _PACKAGE_ACTIONS.intersection(actions):
            continue
        principal = statement.get("Principal")
        principal = principal.get("AWS") if isinstance(principal, Mapping) else principal
        principals = principal if isinstance(principal, list) else [principal]
        for item in principals:
            if item == "*":
                return True
            if not isinstance(item, str):
                continue
            match = re.fullmatch(r"arn:aws:iam::(\d{12}):(?:root|user/[A-Za-z0-9+=,.@_/-]+|role/[A-Za-z0-9+=,.@_/-]+)", item)
            if match and match.group(1) != account:
                return True
    return False


def normalize_aws_codeartifact_policy(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "codeartifact.amazonaws.com"
            or record.get("eventName") != "PutRepositoryPermissionsPolicy"):
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    account, domain, repo = record.get("recipientAccountId"), request.get("domain"), request.get("repository")
    if (not isinstance(account, str) or re.fullmatch(r"\d{12}", account) is None
            or not isinstance(domain, str) or re.fullmatch(r"[a-z][a-z0-9-]{1,49}", domain) is None
            or not isinstance(repo, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,99}", repo) is None):
        return None
    policy_response = response.get("policy")
    if not isinstance(policy_response, Mapping):
        return None
    arn = f"arn:aws:codeartifact:{record.get('awsRegion')}:{account}:repository/{domain}/{repo}"
    submitted = _document(request.get("policyDocument"))
    returned = _document(policy_response.get("document"))
    if submitted is None or returned is None:
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "codeartifact.amazonaws.com",
        "event.name": "PutRepositoryPermissionsPolicy",
        "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": arn,
        "request.codeartifact_external_package_grant": (
            not failed and policy_response.get("resourceArn") == arn
            and submitted == returned and _external_package_grant(submitted, account)
        ),
    }
