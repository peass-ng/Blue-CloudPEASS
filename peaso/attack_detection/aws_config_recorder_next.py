"""Accepted stop of an AWS Config customer managed recorder."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_config_recorder_stop(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "config.amazonaws.com"
            or record.get("eventName") != "StopConfigurationRecorder"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    account, region, name = record.get("recipientAccountId"), record.get("awsRegion"), request.get("configurationRecorderName")
    if (not isinstance(account, str) or re.fullmatch(r"\d{12}", account) is None
            or not isinstance(region, str)
            or not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9._-]{1,256}", name) is None):
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": "config.amazonaws.com",
            "event.name": "StopConfigurationRecorder",
            "event.outcome": "failure" if failed else "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity.get("arn"),
            "target.id": name,
            "request.config_recorder_stop": not failed}


def normalize_aws_config_auto_remediation(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "config.amazonaws.com"
            or record.get("eventName") != "PutRemediationConfigurations"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    configurations = request.get("remediationConfigurations")
    if not isinstance(configurations, list):
        return None
    automatic = [x for x in configurations if isinstance(x, Mapping)
        and x.get("automatic") is True and x.get("targetType") == "SSM_DOCUMENT"
        and isinstance(x.get("configRuleName"), str)
        and isinstance(x.get("targetId"), str)]
    account = record.get("recipientAccountId")
    if not isinstance(account, str) or re.fullmatch(r"\d{12}", account) is None:
        return None
    response = record.get("responseElements")
    failed_batches = response.get("failedBatches") if isinstance(response, Mapping) else None
    failed = bool(record.get("errorCode") or record.get("errorMessage") or failed_batches)
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": "config.amazonaws.com",
            "event.name": "PutRemediationConfigurations",
            "event.outcome": "failure" if failed else "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity.get("arn"),
            "target.id": automatic[0]["configRuleName"] if len(automatic) == 1 else None,
            "request.config_auto_ssm_remediation": not failed and bool(automatic)}
