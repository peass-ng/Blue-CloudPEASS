"""CodePipeline role, execution variable, transition, approval and retry signals."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_NAME = re.compile(r"[A-Za-z0-9.@_-]{1,100}\Z")
_UUID = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\Z")


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "codepipeline.amazonaws.com"
            or name not in {"CreatePipeline", "StartPipelineExecution",
                            "EnableStageTransition", "PutApprovalResult", "RetryStageExecution"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request, response = (record.get("userIdentity"), record.get("requestParameters"),
                                   record.get("responseElements"))
    if (not isinstance(account, str) or not re.fullmatch(r"\d{12}", account)
            or not isinstance(region, str) or not region
            or not isinstance(identity, Mapping) or not isinstance(identity.get("arn"), str)
            or not isinstance(request, Mapping)):
        return None
    if isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")):
        return None
    response = response if isinstance(response, Mapping) else {}
    pipeline = request.get("pipeline") if name == "CreatePipeline" else None
    target = pipeline.get("name") if isinstance(pipeline, Mapping) else request.get("name" if name == "StartPipelineExecution" else "pipelineName")
    if not isinstance(target, str) or not _NAME.fullmatch(target):
        return None
    accepted = False
    if name == "CreatePipeline":
        result = response.get("pipeline")
        role = pipeline.get("roleArn") if isinstance(pipeline, Mapping) else None
        accepted = (isinstance(role, str)
                    and role.startswith(f"arn:aws:iam::{account}:role/")
                    and isinstance(result, Mapping)
                    and result.get("name") == target
                    and result.get("roleArn") == role)
    elif name == "StartPipelineExecution":
        variables = request.get("variables")
        accepted = (isinstance(variables, list) and bool(variables)
                    and all(isinstance(item, Mapping)
                            and isinstance(item.get("name"), str) and bool(item["name"])
                            and isinstance(item.get("value"), str)
                            for item in variables)
                    and isinstance(response.get("pipelineExecutionId"), str)
                    and bool(_UUID.fullmatch(response["pipelineExecutionId"])))
    elif name == "EnableStageTransition":
        stage = request.get("stageName")
        accepted = (isinstance(stage, str) and bool(_NAME.fullmatch(stage))
                    and request.get("transitionType") == "Inbound")
    elif name == "PutApprovalResult":
        stage, action, token = (request.get("stageName"), request.get("actionName"),
                                request.get("token"))
        result = request.get("result")
        accepted = (isinstance(stage, str) and bool(_NAME.fullmatch(stage))
                    and isinstance(action, str) and bool(_NAME.fullmatch(action))
                    and isinstance(token, str) and bool(_UUID.fullmatch(token))
                    and isinstance(result, Mapping) and result.get("status") == "Approved"
                    and isinstance(response.get("approvedAt"), (int, float, str))
                    and bool(response.get("approvedAt")))
    else:
        stage, execution = request.get("stageName"), request.get("pipelineExecutionId")
        accepted = (isinstance(stage, str) and bool(_NAME.fullmatch(stage))
                    and isinstance(execution, str) and bool(_UUID.fullmatch(execution))
                    and request.get("retryMode") in {"FAILED_ACTIONS", "ALL_ACTIONS"}
                    and response.get("pipelineExecutionId") == execution)
    if not accepted:
        return None
    fields = {
        "CreatePipeline": "request.pipeline_same_account_role_selected",
        "StartPipelineExecution": "request.pipeline_execution_variables_supplied",
        "EnableStageTransition": "request.pipeline_inbound_transition_enabled",
        "PutApprovalResult": "request.pipeline_manual_approval_submitted",
        "RetryStageExecution": "request.pipeline_failed_stage_retry_submitted",
    }
    return {"cloud.provider": "aws", "event.source": "codepipeline.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity["arn"], "target.id": target,
            fields[name]: True}
