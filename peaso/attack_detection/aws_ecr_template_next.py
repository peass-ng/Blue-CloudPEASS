"""ECR repository creation template grants for future repositories."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .aws_ecr_policy_next import _wildcard_image_read


def normalize_aws_ecr_template(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "ecr.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"CreateRepositoryCreationTemplate", "UpdateRepositoryCreationTemplate"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    template = response.get("repositoryCreationTemplate")
    if not isinstance(template, Mapping):
        return None
    prefix = request.get("prefix")
    account = record.get("recipientAccountId")
    if (not isinstance(prefix, str) or not prefix
            or template.get("prefix") != prefix or not isinstance(account, str)
            or response.get("registryId") != account):
        return None
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or response.get("errorCode") or response.get("errorMessage"))
    return {
        "cloud.provider": "aws", "event.source": "ecr.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": prefix,
        "request.ecr_template_wildcard_read_grant": (
            not failed and _wildcard_image_read(request.get("repositoryPolicy"))
            and _wildcard_image_read(template.get("repositoryPolicy"))
        ),
    }
