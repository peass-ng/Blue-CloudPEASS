"""ECR tag mutability, lifecycle expiry, and repository deletion events."""

from __future__ import annotations

from collections.abc import Mapping
import json
from typing import Any


def _one_image_expiry(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        policy = json.loads(value)
    except ValueError:
        return False
    rules = policy.get("rules") if isinstance(policy, Mapping) else None
    if not isinstance(rules, list):
        return False
    return any(isinstance(rule, Mapping)
               and isinstance(rule.get("selection"), Mapping)
               and rule["selection"].get("tagStatus") == "any"
               and rule["selection"].get("countType") == "imageCountMoreThan"
               and type(rule["selection"].get("countNumber")) is int
               and rule["selection"]["countNumber"] == 1
               and isinstance(rule.get("action"), Mapping)
               and rule["action"].get("type") == "expire"
               for rule in rules)


def normalize_aws_ecr_retention(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "ecr.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"PutImageTagMutability", "PutLifecyclePolicy", "DeleteRepository"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    account = record.get("recipientAccountId")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping) or not isinstance(account, str):
        return None
    repository = request.get("repositoryName")
    if not isinstance(repository, str) or not repository:
        return None
    if name == "DeleteRepository":
        result = response.get("repository")
        if not isinstance(result, Mapping) or result.get("registryId") != account:
            return None
        matched = result.get("repositoryName") == repository
    else:
        matched = response.get("registryId") == account and response.get("repositoryName") == repository
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or response.get("errorCode") or response.get("errorMessage"))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "ecr.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": repository,
        "request.ecr_tags_set_mutable": (
            not failed and matched and name == "PutImageTagMutability"
            and request.get("imageTagMutability") == "MUTABLE"
            and response.get("imageTagMutability") == "MUTABLE"
        ),
        "request.ecr_broad_one_image_expiration_policy": (
            not failed and matched and name == "PutLifecyclePolicy"
            and _one_image_expiry(request.get("lifecyclePolicyText"))
            and _one_image_expiry(response.get("lifecyclePolicyText"))
        ),
        "request.ecr_repository_delete_accepted": not failed and matched and name == "DeleteRepository",
    }
