"""CodePipeline configuration and custom-job read signals.

CloudTrail omits API response bodies for these calls in the observed account.
The signals describe accepted requests; they never claim which variable values,
artifact credentials, or job data were returned to the caller.
"""
from __future__ import annotations
from collections.abc import Mapping
import re
from typing import Any

_NAME = re.compile(r"[A-Za-z0-9.@_-]{1,100}\Z")
_PROVIDER = re.compile(r"[A-Za-z0-9_-]{1,35}\Z")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    flags = {"GetPipeline": "request.pipeline_definition_read",
             "GetPipelineExecution": "request.pipeline_execution_read",
             "ListActionExecutions": "request.pipeline_action_executions_read",
             "PollForJobs": "request.pipeline_custom_jobs_polled",
             "GetJobDetails": "request.pipeline_known_job_details_read"}
    if (record.get("eventSource") != "codepipeline.amazonaws.com" or name not in flags
            or record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name != "PollForJobs")
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region, identity, request = (record.get("recipientAccountId"), record.get("awsRegion"),
                                          record.get("userIdentity"), record.get("requestParameters"))
    if (not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account)
            or not isinstance(region, str) or not region
            or not isinstance(identity, Mapping) or not isinstance(identity.get("arn"), str)
            or identity.get("accountId") not in (None, account)
            or not isinstance(request, Mapping)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str) or not record["eventTime"]):
        return None
    if name == "GetPipeline":
        target = request.get("name")
        valid = isinstance(target, str) and bool(_NAME.fullmatch(target))
    elif name == "GetPipelineExecution":
        target, execution = request.get("pipelineName"), request.get("pipelineExecutionId")
        valid = (isinstance(target, str) and bool(_NAME.fullmatch(target))
                 and isinstance(execution, str) and bool(_UUID.fullmatch(execution)))
    elif name == "ListActionExecutions":
        target = request.get("pipelineName")
        flt = request.get("filter")
        valid = (isinstance(target, str) and bool(_NAME.fullmatch(target))
                 and (flt is None or isinstance(flt, Mapping)))
    elif name == "PollForJobs":
        action_type = request.get("actionTypeId")
        provider = action_type.get("provider") if isinstance(action_type, Mapping) else None
        target = "custom-action-type"
        valid = (isinstance(action_type, Mapping)
                 and action_type.get("category") in {"Build", "Deploy", "Test", "Invoke"}
                 and action_type.get("owner") == "Custom"
                 and isinstance(provider, str) and bool(_PROVIDER.fullmatch(provider))
                 and isinstance(action_type.get("version"), str) and bool(action_type["version"]))
    else:
        job = request.get("jobId")
        target = "custom-action-job"
        valid = isinstance(job, str) and bool(_UUID.fullmatch(job))
    if not valid:
        return None
    return {"cloud.provider": "aws", "event.source": "codepipeline.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record["eventTime"],
            "account.id": account, "actor.id": identity["arn"], "target.id": target,
            flags[name]: True}
