"""Describe accepted Redshift Serverless namespace credential and role changes."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .aws_raw_cloudtrail import normalize as normalize_raw


def normalize_aws_redshift_serverless_namespace(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "redshift-serverless.amazonaws.com"
            or record.get("eventName") != "UpdateNamespace"
            or record.get("eventCategory") != "Management"
            or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    namespace = request.get("namespaceName")
    updated = response.get("namespace")
    if (not isinstance(namespace, str) or not namespace
            or not isinstance(updated, Mapping) or updated.get("namespaceName") != namespace):
        return None
    flag = None
    default_role, roles = request.get("defaultIamRoleArn"), request.get("iamRoles")
    if (isinstance(default_role, str) and default_role.startswith("arn:aws:iam::")
            and isinstance(roles, list) and default_role in roles
            and updated.get("defaultIamRoleArn") == default_role):
        flag = "request.redshift_serverless_default_role_set"
    elif ("adminUserPassword" in request
          and isinstance(request.get("adminUsername"), str)
          and updated.get("adminUsername") == request["adminUsername"]):
        flag = "request.redshift_serverless_admin_password_reset"
    if flag is None:
        return None
    envelope = normalize_raw(record)
    if len(envelope) != 1 or envelope[0].get("resource.type") != "CloudTrail::UnscopedEvent":
        return None
    result = dict(envelope[0])
    result.pop("__raw_cloudtrail", None)
    result[flag] = True
    return result
