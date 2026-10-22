"""Recognize accepted, broadly scoped OpenSearch Serverless data grants."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import json
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_NAME = re.compile(r"[a-z][a-z0-9-]{2,31}\Z")
_PRINCIPAL = re.compile(r"arn:(?:aws|aws-us-gov|aws-cn):iam::([0-9]{12}):(role|user)/[^\s]+\Z")


def _document(value: Any) -> list[Any] | None:
    if not isinstance(value, str) or len(value) > 20480:
        return None
    try:
        parsed = json.loads(value)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, list) and 0 < len(parsed) <= 50 else None


def _broad_principals(document: list[Any], account: str) -> set[str]:
    grants: dict[str, set[str]] = {}
    for statement in document:
        if not isinstance(statement, Mapping):
            return set()
        principals, rules = statement.get("Principal"), statement.get("Rules")
        if not isinstance(principals, list) or not isinstance(rules, list):
            return set()
        for principal in principals:
            match = _PRINCIPAL.fullmatch(principal) if isinstance(principal, str) else None
            if not match or match.group(1) != account:
                continue
            for rule in rules:
                if not isinstance(rule, Mapping):
                    continue
                permissions = rule.get("Permission")
                if not isinstance(permissions, list) or "aoss:*" not in permissions:
                    continue
                kind, resources = rule.get("ResourceType"), rule.get("Resource")
                if not isinstance(resources, list):
                    continue
                if kind == "collection" and "collection/*" in resources:
                    grants.setdefault(principal, set()).add("collection")
                elif kind == "index" and "index/*/*" in resources:
                    grants.setdefault(principal, set()).add("index")
    return {principal for principal, kinds in grants.items() if kinds == {"collection", "index"}}


def normalize_aws_aoss_broad_grant(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Emit a fixed flag and hashed policy target, never the policy document."""
    action = record.get("eventName")
    if (record.get("eventSource") != "aoss.amazonaws.com"
            or action not in {"CreateAccessPolicy", "UpdateAccessPolicy"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)):
        return None
    stamp, event_id = record.get("eventTime"), record.get("eventID")
    if not isinstance(stamp, str) or not isinstance(event_id, str) or not event_id:
        return None
    try:
        if datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
            return None
    except ValueError:
        return None
    identity, request, response = (record.get("userIdentity"), record.get("requestParameters"),
                                   record.get("responseElements"))
    if (not isinstance(identity, Mapping) or identity.get("accountId") != account
            or not isinstance(identity.get("arn"), str)
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or response.get("errorCode") or response.get("errorMessage")):
        return None
    name = request.get("name")
    if (not isinstance(name, str) or not _NAME.fullmatch(name)
            or request.get("type") != "data"):
        return None
    requested = _document(request.get("policy"))
    detail = response.get("accessPolicyDetail")
    if (not requested or not isinstance(detail, Mapping)
            or detail.get("name") != name or detail.get("type") != "data"
            or not isinstance(detail.get("policyVersion"), str)
            or not detail["policyVersion"]):
        return None
    # CloudTrail renders this response field as an AWS map string, not JSON.
    # The accepted request document is the only parseable policy in the event.
    if (not isinstance(detail.get("policy"), str) or not detail["policy"]
            or not _broad_principals(requested, account)):
        return None
    return {
        "cloud.provider": "aws", "event.source": "aoss.amazonaws.com",
        "event.name": action, "event.outcome": "success", "event.id": event_id,
        "event.time": stamp, "account.id": account, "actor.id": identity["arn"],
        "target.id": "sha256:" + hashlib.sha256(
            f"aoss-policy:{region}:{account}:{name}".encode("utf-8")).hexdigest()[:24],
        "request.aoss_broad_access_grant_requested": True,
    }
