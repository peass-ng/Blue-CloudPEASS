"""Normalize Cognito M2M app-client creation and token issuance."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_CLIENT = re.compile(r"[A-Za-z0-9_+]{1,128}\Z")
_SCOPE = re.compile(r"[A-Za-z0-9_.:-]+/[A-Za-z0-9_.:-]+\Z")


def _custom_scopes(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(
        isinstance(scope, str) and bool(_SCOPE.fullmatch(scope)) for scope in value)


def normalize_aws_cognito_m2m(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "cognito-idp.amazonaws.com"
            or name not in {"CreateUserPoolClient", "GetClientToken"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)):
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or response.get("errorCode") or response.get("errorMessage"))
    client = response.get("userPoolClient")
    client = client if isinstance(client, Mapping) else {}
    authentication = response.get("clientAuthenticationResult")
    authentication = authentication if isinstance(authentication, Mapping) else {}
    pool = request.get("userPoolId")
    if name == "CreateUserPoolClient":
        valid_pool = (isinstance(pool, str) and pool.startswith(region + "_")
                      and bool(re.fullmatch(r"[A-Za-z0-9]+", pool[len(region)+1:])))
        target = client.get("clientId")
        valid_target = (isinstance(target, str) and bool(_CLIENT.fullmatch(target))
                        and client.get("userPoolId") == pool)
        created = bool(not failed and valid_pool and valid_target
                       and request.get("generateSecret") is True
                       and request.get("explicitAuthFlows") == ["ALLOW_CLIENT_TOKEN_AUTH"]
                       and _custom_scopes(request.get("allowedOAuthScopes")))
        issued = False
    else:
        target = request.get("clientId")
        valid_target = isinstance(target, str) and bool(_CLIENT.fullmatch(target))
        created = False
        issued = bool(not failed and valid_target and _custom_scopes(request.get("scopes"))
                      and authentication.get("tokenType") == "Bearer"
                      and type(authentication.get("expiresIn")) is int
                      and authentication["expiresIn"] > 0
                      and isinstance(authentication.get("accessToken"), str)
                      and bool(authentication["accessToken"]))
    if not valid_target:
        return None
    actor = record.get("userIdentity")
    actor = actor if isinstance(actor, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": record["eventSource"],
            "event.name": name, "event.outcome": "failure" if failed else "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": actor.get("arn"), "target.id": target,
            "request.cognito_m2m_client_created": created,
            "request.cognito_m2m_token_issued": issued}
