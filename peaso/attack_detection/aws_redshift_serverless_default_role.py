"""Normalize accepted Redshift Serverless default IAM role association."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from .aws_raw_cloudtrail import normalize as normalize_raw


_ROLE_ARN = re.compile(r"arn:aws(?:-[a-z-]+)?:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+\Z")


def normalize_aws_redshift_serverless_default_role(
    record: Mapping[str, Any],
) -> dict[str, Any] | None:
    if (record.get("eventSource") != "redshift-serverless.amazonaws.com"
            or record.get("eventName") != "UpdateNamespace"
            or record.get("eventCategory") != "Management"
            or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    namespace = request.get("namespaceName")
    role, roles = request.get("defaultIamRoleArn"), request.get("iamRoles")
    updated = response.get("namespace")
    if (not isinstance(namespace, str) or not namespace
            or not isinstance(role, str) or not _ROLE_ARN.fullmatch(role)
            or not isinstance(roles, list) or role not in roles
            or not all(isinstance(item, str) and _ROLE_ARN.fullmatch(item) for item in roles)
            or not isinstance(updated, Mapping)
            or updated.get("namespaceName") != namespace
            or updated.get("defaultIamRoleArn") != role):
        return None
    envelope = normalize_raw(record)
    if len(envelope) != 1 or envelope[0].get("resource.type") != "CloudTrail::UnscopedEvent":
        return None
    result = dict(envelope[0])
    result.pop("__raw_cloudtrail", None)
    result["request.redshift_serverless_default_role_set"] = True
    return result
