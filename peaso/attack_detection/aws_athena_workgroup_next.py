"""Accepted Athena workgroup override and result encryption changes."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_athena_workgroup(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "athena.amazonaws.com"
            or record.get("eventName") != "UpdateWorkGroup"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    account, region, workgroup = record.get("recipientAccountId"), record.get("awsRegion"), request.get("workGroup")
    if (not isinstance(account, str) or re.fullmatch(r"\d{12}", account) is None
            or not isinstance(region, str)
            or not isinstance(workgroup, str) or re.fullmatch(r"[A-Za-z0-9._-]{1,128}", workgroup) is None):
        return None
    updates = request.get("configurationUpdates")
    updates = updates if isinstance(updates, Mapping) else {}
    result = updates.get("resultConfigurationUpdates")
    result = result if isinstance(result, Mapping) else {}
    location = result.get("outputLocation")
    output_override = (
        updates.get("enforceWorkGroupConfiguration") is True
        and isinstance(location, str)
        and re.fullmatch(r"s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9](?:/[A-Za-z0-9!_.*'()/=-]*)?", location) is not None
        and result.get("removeOutputLocation") is not True
    )
    encryption_removal = result.get("removeEncryptionConfiguration") is True
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": "athena.amazonaws.com",
        "event.name": "UpdateWorkGroup", "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": f"arn:aws:athena:{region}:{account}:workgroup/{workgroup}",
        "request.athena_enforced_output_location": not failed and output_override,
        "request.athena_result_encryption_removed": not failed and encryption_removal}
