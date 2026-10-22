"""Identify accepted Synthetics dry runs that submit replacement code."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from .aws_raw_cloudtrail import normalize as normalize_raw


_NAME = re.compile(r"[0-9a-z_-]{1,255}\Z")
_ROLE = re.compile(r"arn:(?:aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}\Z")


def normalize_aws_synthetics_dryrun(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return a fixed flag without copying source code, bucket or dry-run ID."""
    if (record.get("eventSource") != "synthetics.amazonaws.com"
            or record.get("eventName") != "StartCanaryDryRun"
            or record.get("readOnly") is not False):
        return None
    envelope = normalize_raw(record)
    if len(envelope) != 1 or envelope[0].get("resource.type") != "AWS::Synthetics::Canary":
        return None
    account, identity = record.get("recipientAccountId"), record.get("userIdentity")
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (not isinstance(account, str) or not isinstance(identity, Mapping)
            or identity.get("accountId") != account
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)):
        return None
    name = request.get("name")
    if (not isinstance(name, str) or not _NAME.fullmatch(name)
            or envelope[0].get("__resource_path") != "canary:" + name):
        return None
    code = request.get("Code")
    if not isinstance(code, Mapping):
        return None
    inline = "ZipFile" in code and isinstance(code["ZipFile"], str) and bool(code["ZipFile"])
    s3_code = (all(isinstance(code.get(k), str) and code[k] for k in ("S3Bucket", "S3Key")))
    if not (inline or s3_code):
        return None
    role = request.get("ExecutionRoleArn")
    if role is not None:
        match = _ROLE.fullmatch(role) if isinstance(role, str) else None
        if match is None or match.group(1) != account:
            return None
    dry = response.get("DryRunConfig")
    if (not isinstance(dry, Mapping) or not isinstance(dry.get("DryRunId"), str)
            or not dry["DryRunId"]):
        return None
    result = dict(envelope[0])
    result.pop("__raw_cloudtrail", None)
    result.pop("__resource_path", None)
    result["request.synthetics_dry_run_replacement_code_requested"] = True
    return result
