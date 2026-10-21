"""API Gateway REST stage/API and HTTP CORS configuration changes."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse


def _patches(value: Any) -> list[Mapping[str, Any]]:
    patches = value.get("patchOperations") if isinstance(value, Mapping) else None
    return [p for p in patches if isinstance(p, Mapping)] if isinstance(patches, list) else []


def _explicit_origin(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return (parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username
            and not parsed.password and not parsed.path.strip("/") and not parsed.query
            and not parsed.fragment and "*" not in value)


def normalize_aws_apigateway_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "apigateway.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"UpdateStage", "UpdateRestApi", "UpdateApi"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    api_id = request.get("apiId" if name == "UpdateApi" else "restApiId")
    if not isinstance(api_id, str) or not api_id or response.get("apiId" if name == "UpdateApi" else "id", api_id) != api_id:
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or response.get("errorCode") or response.get("errorMessage"))
    stage = request.get("stageName")
    stage_ok = (name == "UpdateStage" and isinstance(stage, str) and bool(stage)
                and response.get("stageName") == stage)
    stage_patches = _patches(request.get("updateStageInput"))
    api_patches = _patches(request.get("updateRestApiInput"))
    method_settings = response.get("methodSettings")
    wildcard_settings = (method_settings.get("*/*", {})
                         if isinstance(method_settings, Mapping) else {})
    if not isinstance(wildcard_settings, Mapping):
        wildcard_settings = {}
    execution_log_off = any(
        p.get("op") == "replace" and p.get("path") == "/*/*/logging/loglevel"
        and p.get("value") == "OFF" for p in stage_patches)
    data_trace_off = any(
        p.get("op") == "replace" and p.get("path") == "/*/*/logging/dataTrace"
        and p.get("value") == "false" for p in stage_patches)
    detailed_metrics_off = any(
        p.get("op") == "replace" and p.get("path") == "/*/*/metrics/enabled"
        and p.get("value") == "false" for p in stage_patches)
    variable = any(p.get("op") in {"add", "replace"} and isinstance(p.get("path"), str)
                   and p["path"].startswith("/variables/") and p["path"] != "/variables/"
                   and isinstance(p.get("value"), str)
                   for p in stage_patches)
    tracing = any(p.get("op") == "replace" and p.get("path") == "/tracingEnabled"
                  and p.get("value") == "false" for p in stage_patches)
    canary_id = next((p.get("value") for p in stage_patches
                      if p.get("op") == "replace" and p.get("path") == "/canarySettings/deploymentId"), None)
    canary_pct = next((p.get("value") for p in stage_patches
                       if p.get("op") == "replace" and p.get("path") == "/canarySettings/percentTraffic"), None)
    canary_result = response.get("canarySettings")
    canary_override = any(
        p.get("op") == "replace" and isinstance(p.get("path"), str)
        and p["path"].startswith("/canarySettings/stageVariableOverrides/")
        and p["path"] != "/canarySettings/stageVariableOverrides/"
        for p in stage_patches)
    try:
        percent = float(canary_pct)
    except (TypeError, ValueError):
        percent = 0
    canary_response_id = canary_result.get("deploymentId") if isinstance(canary_result, Mapping) else None
    canary = (isinstance(canary_response_id, str) and bool(canary_response_id)
              and canary_response_id != response.get("deploymentId")
              and (canary_id is None or canary_response_id == canary_id)
              and 0 < percent <= 100 and canary_result.get("percentTraffic") == percent)
    deployment_id = next((p.get("value") for p in stage_patches
                          if p.get("op") == "replace" and p.get("path") == "/deploymentId"), None)
    deployment_changed = (isinstance(deployment_id, str) and bool(deployment_id)
                          and response.get("deploymentId") == deployment_id)
    endpoint = any(p.get("op") == "replace" and p.get("path") == "/disableExecuteApiEndpoint"
                   and p.get("value") == "false" for p in api_patches)
    key_source = any(p.get("op") == "replace" and p.get("path") == "/apiKeySource"
                     and p.get("value") == "AUTHORIZER" for p in api_patches)
    cors_req, cors_res = request.get("corsConfiguration"), response.get("corsConfiguration")
    cors = (isinstance(cors_req, Mapping) and isinstance(cors_res, Mapping)
            and cors_req.get("allowCredentials") is True and cors_res.get("allowCredentials") is True
            and isinstance(cors_req.get("allowOrigins"), list)
            and bool(cors_req["allowOrigins"])
            and all(_explicit_origin(x) for x in cors_req["allowOrigins"])
            and set(cors_req["allowOrigins"]) == set(cors_res.get("allowOrigins", [])))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "apigateway.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId"), "actor.id": identity.get("arn"),
        "target.id": api_id,
        "request.apigateway_stage_variable_changed": not failed and stage_ok and variable,
        "request.apigateway_stage_tracing_disabled": (
            not failed and stage_ok and tracing and response.get("tracingEnabled") is False
        ),
        "request.apigateway_canary_traffic_redirected": not failed and stage_ok and canary,
        "request.apigateway_canary_stage_variable_override_changed": (
            not failed and stage_ok and canary_override and isinstance(canary_result, Mapping)
            and isinstance(canary_result.get("stageVariableOverrides"), Mapping)
        ),
        "request.apigateway_execution_logging_off": (
            not failed and stage_ok and execution_log_off
            and wildcard_settings.get("loggingLevel") == "OFF"
        ),
        "request.apigateway_data_trace_disabled": (
            not failed and stage_ok and data_trace_off
            and wildcard_settings.get("dataTraceEnabled") is False
        ),
        "request.apigateway_detailed_metrics_disabled": (
            not failed and stage_ok and detailed_metrics_off
            and wildcard_settings.get("metricsEnabled") is False
        ),
        "request.apigateway_stage_deployment_changed": (
            not failed and stage_ok and deployment_changed
        ),
        "request.apigateway_default_endpoint_enabled": (
            not failed and name == "UpdateRestApi" and endpoint
            and response.get("id") == api_id and response.get("disableExecuteApiEndpoint") is False
        ),
        "request.apigateway_api_key_source_authorizer": (
            not failed and name == "UpdateRestApi" and key_source
            and response.get("id") == api_id and response.get("apiKeySource") == "AUTHORIZER"
        ),
        "request.apigateway_credentialed_cors_explicit_origin": not failed and name == "UpdateApi" and cors,
    }
