"""Recognize accepted SageMaker Pipeline parameter overrides and retries."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,254}[A-Za-z0-9]\Z|[A-Za-z0-9]\Z")


def _pipeline_arn(value: Any, region: str, account: str) -> str | None:
    if not isinstance(value, str):
        return None
    prefix = f"arn:aws:sagemaker:{region}:{account}:pipeline/"
    name = value[len(prefix):] if value.startswith(prefix) else value
    if not _NAME.fullmatch(name):
        return None
    return prefix + name


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (name not in {"StartPipelineExecution", "RetryPipelineExecution"}
            or record.get("eventSource") != "sagemaker.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    event_id, stamp = record.get("eventID"), record.get("eventTime")
    request = record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(event_id, str) or not event_id
            or not isinstance(stamp, str) or not isinstance(request, Mapping)):
        return None
    try:
        if datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
            return None
    except ValueError:
        return None
    if name == "StartPipelineExecution":
        target = _pipeline_arn(request.get("pipelineName"), region, account)
        parameters = request.get("pipelineParameters")
        if (target is None or not isinstance(parameters, list)
                or not 1 <= len(parameters) <= 200
                or any(not isinstance(item, Mapping)
                       or not isinstance(item.get("name"), str) or not item["name"]
                       or not isinstance(item.get("value"), str)
                       for item in parameters)):
            return None
        synthetic = "SageMakerPipelineParametersOverridden"
        marker = "request.sagemaker_pipeline_parameter_override"
    else:
        execution = request.get("pipelineExecutionArn")
        if not isinstance(execution, str) or len(execution) > 2048:
            return None
        prefix = f"arn:aws:sagemaker:{region}:{account}:pipeline/"
        if not execution.startswith(prefix):
            return None
        suffix = execution[len(prefix):]
        parts = suffix.split("/execution/")
        if (len(parts) != 2 or not _NAME.fullmatch(parts[0])
                or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", parts[1])):
            return None
        target = execution
        synthetic = "SageMakerPipelineExecutionRetried"
        marker = "request.sagemaker_pipeline_execution_retried"
    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    return {
        "cloud.provider": "aws", "event.source": "sagemaker.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": event_id, "event.time": stamp, "account.id": account,
        "actor.id": actor,
        "target.id": "sha256:" + hashlib.sha256(target.encode()).hexdigest()[:24],
        marker: True,
    }
