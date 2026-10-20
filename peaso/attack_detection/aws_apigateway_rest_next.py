"""Bounded API Gateway REST key, response and policy correlations.

CloudTrail may include a masked API-key value suffix, response templates and
full policy documents. None of those fields is copied to detector evidence.
"""

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import json
import re
from typing import Any


_NAMES = {"CreateApiKey", "CreateUsagePlanKey", "GetApiKey", "PutMethodResponse",
          "PutIntegrationResponse", "UpdateGatewayResponse", "UpdateRestApi",
          "CreateDeployment"}
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]\Z")
_ID = re.compile(r"[a-z0-9]{5,26}\Z")
_HEADER = re.compile(r"method\.response\.header\.[A-Za-z0-9-]{1,80}\Z")


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else None


def _identity(value: Any, account: str) -> tuple[str, str] | None:
    if not isinstance(value, Mapping) or value.get("accountId") not in (None, account):
        return None
    actor = value.get("arn")
    if not isinstance(actor, str) or not actor.startswith("arn:"):
        return None
    if value.get("type") == "AssumedRole":
        context = value.get("sessionContext")
        issuer = context.get("sessionIssuer") if isinstance(context, Mapping) else None
        principal = issuer.get("arn") if isinstance(issuer, Mapping) else None
        if not isinstance(principal, str) or not principal.startswith("arn:"):
            return None
    else:
        principal = actor
    return actor, principal


def _valid(record: Mapping[str, Any]) -> tuple | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "apigateway.amazonaws.com"
            or not isinstance(name, str)
            or name not in _NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name == "GetApiKey")
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request = record.get("requestParameters")
    event_id, when = record.get("eventID"), _when(record.get("eventTime"))
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping)
            or not isinstance(event_id, str) or not event_id or when is None):
        return None
    identity = _identity(record.get("userIdentity"), account)
    if identity is None:
        return None
    response = record.get("responseElements")
    return account, region, *identity, when, request, response if isinstance(response, Mapping) else {}


def _target(region: str, kind: str, value: str) -> str:
    part = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    return f"arn:{part}:apigateway:{region}::/{kind}/{value}"


def _policy_wildcard(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 16384:
        return False
    try:
        document = json.loads(value)
    except json.JSONDecodeError:
        return False
    statements = document.get("Statement") if isinstance(document, Mapping) else None
    if isinstance(statements, Mapping):
        statements = [statements]
    return (isinstance(statements, list)
            and any(isinstance(s, Mapping) and s.get("Effect") == "Allow"
                    and s.get("Principal") == "*"
                    and s.get("Action") in ("execute-api:Invoke", ["execute-api:Invoke"])
                    for s in statements))


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    keys = []
    attachments = []
    methods = []
    integrations = []
    gateway = []
    policies = []
    deployments = []
    out = []
    for record in records:
        valid = _valid(record)
        if valid is None:
            continue
        account, region, actor, principal, when, request, response = valid
        name = record["eventName"]
        if name == "CreateApiKey":
            params = request.get("createApiKeyInput")
            key_id = response.get("id")
            if (isinstance(params, Mapping) and params.get("enabled") is True
                    and isinstance(key_id, str) and _ID.fullmatch(key_id)):
                keys.append((when, account, region, principal, key_id, record["eventID"]))
        elif name == "CreateUsagePlanKey":
            params = request.get("createUsagePlanKeyInput")
            plan = request.get("usagePlanId")
            if not isinstance(params, Mapping):
                continue
            key_id = params.get("keyId")
            if (not isinstance(plan, str) or not _ID.fullmatch(plan)
                    or not isinstance(key_id, str) or not _ID.fullmatch(key_id)
                    or params.get("keyType") != "API_KEY" or response.get("id") != key_id):
                continue
            attachments.append((when, account, region, actor, principal, plan, key_id, record))
        elif name == "GetApiKey":
            key_id = request.get("apiKey")
            if request.get("includeValue") is True and isinstance(key_id, str) and _ID.fullmatch(key_id):
                out.append({"cloud.provider": "aws", "event.source": "apigateway.amazonaws.com",
                            "event.name": "ApiGatewayRestApiKeyValueRequested",
                            "event.outcome": "success", "event.id": record["eventID"],
                            "event.time": record["eventTime"], "account.id": account,
                            "actor.id": actor, "target.id": _target(region, "apikeys", key_id),
                            "request.apigateway_api_key_value_requested": True})
        elif name in {"PutMethodResponse", "PutIntegrationResponse"}:
            api_id, resource, verb, status = (request.get("restApiId"), request.get("resourceId"),
                                              request.get("httpMethod"), request.get("statusCode"))
            params = request.get("putMethodResponseInput" if name == "PutMethodResponse"
                                 else "putIntegrationResponseInput")
            mapping = params.get("responseParameters") if isinstance(params, Mapping) else None
            if (not isinstance(api_id, str) or not _ID.fullmatch(api_id)
                    or not isinstance(resource, str) or not _ID.fullmatch(resource)
                    or not isinstance(verb, str) or verb not in {"GET", "POST", "PUT", "PATCH", "DELETE"}
                    or not isinstance(status, str) or not re.fullmatch(r"[1-5][0-9]{2}", status)
                    or not isinstance(mapping, Mapping)):
                continue
            headers = frozenset(k for k in mapping if isinstance(k, str) and _HEADER.fullmatch(k))
            if not headers:
                continue
            entry = (when, account, region, principal, api_id, resource, verb, status, headers, record["eventID"])
            (methods if name == "PutMethodResponse" else integrations).append(entry)
        elif name == "UpdateGatewayResponse":
            api_id = request.get("restApiId")
            params = request.get("updateGatewayResponseInput")
            ops = params.get("patchOperations") if isinstance(params, Mapping) else None
            if (isinstance(api_id, str) and _ID.fullmatch(api_id)
                    and isinstance(request.get("responseType"), str)
                    and isinstance(ops, list)
                    and any(isinstance(op, Mapping) and op.get("op") in ("replace", "add")
                            and isinstance(op.get("path"), str)
                            and op["path"].startswith(("/responseTemplates/", "/responseParameters/"))
                            for op in ops)):
                gateway.append((when, account, region, principal, api_id, record["eventID"]))
        elif name == "UpdateRestApi":
            api_id = request.get("restApiId")
            params = request.get("updateRestApiInput")
            ops = params.get("patchOperations") if isinstance(params, Mapping) else None
            if (isinstance(api_id, str) and _ID.fullmatch(api_id)
                    and isinstance(ops, list)
                    and any(isinstance(op, Mapping) and op.get("op") == "replace"
                            and op.get("path") == "/policy" and _policy_wildcard(op.get("value"))
                            for op in ops)):
                policies.append((when, account, region, principal, api_id, record["eventID"]))
        elif name == "CreateDeployment":
            api_id = request.get("restApiId")
            params = request.get("createDeploymentInput")
            if (isinstance(api_id, str) and _ID.fullmatch(api_id)
                    and isinstance(params, Mapping)
                    and isinstance(params.get("stageName"), str)
                    and params["stageName"] and isinstance(response.get("id"), str)
                    and response["id"]):
                deployments.append((when, account, region, actor, principal, api_id, record))
    for when, account, region, actor, principal, plan, key_id, record in attachments:
        prior = [x for x in keys if x[1:4] == (account, region, principal)
                 and x[4] == key_id and timedelta(0) <= when-x[0] <= timedelta(hours=1)]
        if prior:
            source = max(prior, key=lambda item: item[0])
            out.append({"cloud.provider": "aws", "event.source": "apigateway.amazonaws.com",
                        "event.name": "ApiGatewayRestNewKeyAttachedToPlan",
                        "event.outcome": "success", "event.id": record["eventID"],
                        "event.time": record["eventTime"], "account.id": account,
                        "actor.id": actor, "target.id": _target(region, "usageplans", plan),
                        "request.apigateway_new_key_attached_to_plan": True,
                        "correlation_evidence": {"source_event_id": source[5]}})
    seen_sources: set[str] = set()
    for when, account, region, actor, principal, api_id, deployment in sorted(deployments, key=lambda item: item[0]):
        target = _target(region, "restapis", api_id)
        close = lambda source: [x for x in source if x[1:4] == (account, region, principal)
                                and x[4] == api_id and timedelta(0) <= when-x[0] <= timedelta(hours=1)]
        signals = []
        matched_method = []
        for method in close(methods):
            joined = [x for x in close(integrations)
                      if x[5:8] == method[5:8] and x[8] & method[8]
                      and method[0] <= x[0] <= when]
            if joined:
                matched_method.append(method)
        matched_method = [x for x in matched_method if x[9] not in seen_sources]
        if matched_method:
            signals.append(("ApiGatewayRestMethodResponsePublished",
                            "request.apigateway_method_response_published",
                            max(matched_method, key=lambda item: item[0])[9]))
        gw = [x for x in close(gateway) if x[5] not in seen_sources]
        if gw:
            signals.append(("ApiGatewayRestGatewayResponsePublished",
                            "request.apigateway_gateway_response_published",
                            max(gw, key=lambda item: item[0])[5]))
        policy = [x for x in close(policies) if x[5] not in seen_sources]
        if policy:
            signals.append(("ApiGatewayRestWildcardPolicyPublished",
                            "request.apigateway_wildcard_policy_published",
                            max(policy, key=lambda item: item[0])[5]))
        for event_name, flag, source_id in signals:
            seen_sources.add(source_id)
            out.append({"cloud.provider": "aws", "event.source": "apigateway.amazonaws.com",
                        "event.name": event_name, "event.outcome": "success",
                        "event.id": deployment["eventID"], "event.time": deployment["eventTime"],
                        "account.id": account, "actor.id": actor, "target.id": target,
                        flag: True, "correlation_evidence": {"source_event_id": source_id}})
    return out
