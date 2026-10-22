"""Identify accepted Redshift Serverless public and security group update requests."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from .aws_raw_cloudtrail import normalize as normalize_raw


_SG = re.compile(r"sg-[0-9a-f]+\Z")


def normalize_aws_redshift_serverless_workgroup(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "redshift-serverless.amazonaws.com"
            or record.get("eventName") != "UpdateWorkgroup"
            or record.get("eventCategory") != "Management"
            or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    workgroup, updated = request.get("workgroupName"), response.get("workgroup")
    if (not isinstance(workgroup, str) or not workgroup
            or not isinstance(updated, Mapping) or updated.get("workgroupName") != workgroup):
        return None
    public = request.get("publiclyAccessible") is True
    groups = request.get("securityGroupIds")
    groups_changed = (isinstance(groups, list) and bool(groups)
                      and all(isinstance(group, str) and _SG.fullmatch(group) for group in groups)
                      and len(groups) == len(set(groups)))
    if not public and not groups_changed:
        return None
    envelope = normalize_raw(record)
    if len(envelope) != 1 or envelope[0].get("resource.type") != "CloudTrail::UnscopedEvent":
        return None
    result = dict(envelope[0])
    result.pop("__raw_cloudtrail", None)
    if public:
        result["request.redshift_serverless_public_access_requested"] = True
    if groups_changed:
        result["request.redshift_serverless_security_groups_replaced"] = True
    return result
