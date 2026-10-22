"""Identify an accepted Redshift master password reset without copying secrets."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .aws_raw_cloudtrail import normalize as normalize_raw


def normalize_aws_redshift_password_reset(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "redshift.amazonaws.com"
            or record.get("eventName") != "ModifyCluster"
            or record.get("eventCategory") != "Management"
            or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    cluster = request.get("clusterIdentifier")
    if (not isinstance(cluster, str) or not cluster
            or "masterUserPassword" not in request
            or response.get("clusterIdentifier") != cluster):
        return None
    pending = response.get("pendingModifiedValues")
    if not isinstance(pending, Mapping) or "masterUserPassword" not in pending:
        return None
    envelope = normalize_raw(record)
    if len(envelope) != 1 or envelope[0].get("resource.type") != "CloudTrail::UnscopedEvent":
        return None
    result = dict(envelope[0])
    result.pop("__raw_cloudtrail", None)
    result["request.redshift_master_password_reset"] = True
    return result
