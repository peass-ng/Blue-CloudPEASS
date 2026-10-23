"""HealthOmics sequence-store S3 access policies granting direct reads to a role."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import json
import re
from typing import Any
from urllib.parse import unquote


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_ROLE = re.compile(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+\Z")


def _policy(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, str) and 0 < len(value) <= 100_000:
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return None
    return value if isinstance(value, Mapping) else None


def _role_read_grant(policy: Mapping[str, Any], ap: str, account: str, store: str) -> bool:
    statements = policy.get("Statement")
    statements = [statements] if isinstance(statements, Mapping) else statements
    if not isinstance(statements, list):
        return False
    prefix = f"{ap}/object/{account}/sequenceStore/{store}/"
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        role = principal.get("AWS") if isinstance(principal, Mapping) else None
        if not isinstance(role, str) or not _ROLE.fullmatch(role):
            continue
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        resources = statement.get("Resource")
        resources = [resources] if isinstance(resources, str) else resources
        if (not isinstance(actions, list) or "s3:GetObject" not in actions
                or not isinstance(resources, list)
                or not any(isinstance(resource, str) and resource.startswith(prefix)
                           for resource in resources)):
            continue
        return True
    return False


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "omics.amazonaws.com"
            or record.get("eventName") != "PutS3AccessPolicy"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request, response = (record.get("userIdentity"),
                                   record.get("requestParameters"), record.get("responseElements"))
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or identity.get("type") == "AWSService"
            or not isinstance(identity.get("arn"), str) or not identity["arn"]
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str)):
        return None
    try:
        if datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00")).tzinfo is None:
            return None
    except ValueError:
        return None
    raw_ap, store = request.get("s3AccessPointArn"), response.get("storeId")
    ap = unquote(raw_ap) if isinstance(raw_ap, str) else None
    if (not isinstance(ap, str) or not ap.startswith(f"arn:aws:s3:{region}:")
            or ":accesspoint/" not in ap or len(ap) > 1024
            or response.get("s3AccessPointArn") != ap
            or response.get("storeType") != "SEQUENCE_STORE"
            or not isinstance(store, str) or not store.isdigit()
            or not _policy(request.get("s3AccessPolicy"))):
        return None
    policy = _policy(request["s3AccessPolicy"])
    if policy is None or not _role_read_grant(policy, ap, account, store):
        return None
    target = "sha256:" + hashlib.sha256(
        f"{account}:{region}:{store}:{ap}".encode()).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "omics.amazonaws.com",
        "event.name": "PutS3AccessPolicy", "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": target,
        "request.healthomics_s3_role_read_policy_submitted": True,
    }
