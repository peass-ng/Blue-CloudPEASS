"""Correlate REST authorizer, Lambda integration and method-auth changes with deployment."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import timedelta
from typing import Any

from .aws_apigateway_rest_next import _target, _valid


_NAMES = {
    "UpdateAuthorizer": ("ApiGatewayRestAuthorizerRepointPublished",
                         "request.apigateway_rest_authorizer_repoint_published"),
    "PutIntegration": ("ApiGatewayRestLambdaIntegrationPublished",
                       "request.apigateway_rest_lambda_integration_published"),
    "UpdateMethod": ("ApiGatewayRestMethodAuthorizerRemovedPublished",
                     "request.apigateway_rest_method_authorizer_removed_published"),
}


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _lambda_uri(value: Any, region: str) -> bool:
    return (isinstance(value, str)
            and any(value.startswith(f"arn:{partition}:apigateway:{region}:lambda:path/2015-03-31/functions/arn:")
                    for partition in ("aws", "aws-us-gov", "aws-cn"))
            and value.endswith("/invocations") and len(value) < 2048)


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    writes = []
    deployments = []
    for record in records:
        parsed = _valid(record)
        if parsed is None:
            continue
        account, region, actor, principal, when, request, response = parsed
        name = record["eventName"]
        if name == "CreateDeployment":
            params = _map(request.get("createDeploymentInput"))
            api = request.get("restApiId")
            if (isinstance(api, str) and api and isinstance(params.get("stageName"), str)
                    and params["stageName"] and isinstance(response.get("id"), str)
                    and response["id"]):
                deployments.append((when, account, region, actor, principal, api, record))
            continue
        if name not in _NAMES:
            continue
        api = request.get("restApiId")
        if not isinstance(api, str) or not api:
            continue
        accepted = False
        if name == "UpdateAuthorizer":
            params = _map(request.get("updateAuthorizerInput"))
            changes = params.get("patchOperations")
            accepted = (isinstance(request.get("authorizerId"), str)
                        and response.get("id") == request.get("authorizerId")
                        and isinstance(changes, list)
                        and any(isinstance(change, Mapping) and change.get("op") == "replace"
                                and change.get("path") == "/authorizerUri"
                                and _lambda_uri(change.get("value"), region)
                                and response.get("authorizerUri") == change.get("value")
                                for change in changes))
        elif name == "PutIntegration":
            params = _map(request.get("putIntegrationInput"))
            accepted = (isinstance(request.get("resourceId"), str)
                        and request.get("httpMethod") in ("GET", "POST", "PUT", "PATCH", "DELETE")
                        and params.get("type") == "AWS_PROXY" and params.get("httpMethod") == "POST"
                        and _lambda_uri(params.get("uri"), region)
                        and response.get("type") == "AWS_PROXY" and response.get("uri") == params.get("uri"))
        elif name == "UpdateMethod":
            params = _map(request.get("updateMethodInput"))
            changes = params.get("patchOperations")
            accepted = (isinstance(request.get("resourceId"), str)
                        and request.get("httpMethod") in ("GET", "POST", "PUT", "PATCH", "DELETE")
                        and response.get("authorizationType") == "NONE"
                        and isinstance(changes, list)
                        and any(isinstance(change, Mapping) and change.get("op") == "replace"
                                and change.get("path") == "/authorizationType"
                                and change.get("value") == "NONE" for change in changes))
        if accepted:
            writes.append((when, account, region, principal, api, name, record["eventID"]))
    out = []
    used = set()
    for when, account, region, actor, principal, api, deployment in sorted(deployments, key=lambda x: x[0]):
        for change in writes:
            changed_at, changed_account, changed_region, changed_principal, changed_api, name, source_id = change
            if (source_id in used or (changed_account, changed_region, changed_principal, changed_api)
                    != (account, region, principal, api)
                    or not timedelta(0) <= when - changed_at <= timedelta(hours=1)):
                continue
            used.add(source_id)
            event_name, flag = _NAMES[name]
            out.append({
                "cloud.provider": "aws", "event.source": "apigateway.amazonaws.com",
                "event.name": event_name, "event.outcome": "success",
                "event.id": deployment["eventID"], "event.time": deployment["eventTime"],
                "account.id": account, "actor.id": actor,
                "target.id": _target(region, "restapis", api),
                flag: True, "correlation_evidence": {"source_event_id": source_id},
            })
    return out
