"""Normalize Cognito user-pool directory reads and destructive controls."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_NAMES = {"ListUsers", "AdminGetUser", "AdminUserGlobalSignOut",
          "SetLogDeliveryConfiguration", "DeleteUserPoolDomain", "DeleteUserPool"}
_READS = {"ListUsers", "AdminGetUser"}
_FLAGS = (
    "request.cognito_user_directory_listed",
    "request.cognito_user_profile_read",
    "request.cognito_user_global_sign_out",
    "request.cognito_log_delivery_cleared",
    "request.cognito_pool_domain_deleted",
    "request.cognito_pool_deleted",
)


def normalize_aws_cognito_directory(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "cognito-idp.amazonaws.com" or name not in _NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name in _READS)):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request = record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping)):
        return None
    pool = request.get("userPoolId")
    if (not isinstance(pool, str) or not pool.startswith(region + "_")
            or not re.fullmatch(r"[A-Za-z0-9]+", pool[len(region)+1:])):
        return None
    response = record.get("responseElements")
    response = response if isinstance(response, Mapping) else {}
    accepted = not (record.get("errorCode") or record.get("errorMessage")
                    or response.get("errorCode") or response.get("errorMessage"))
    has_user = isinstance(request.get("username"), str) and bool(request["username"])
    configurations = request.get("logConfigurations")
    returned_delivery = response.get("logDeliveryConfiguration")
    cleared = (isinstance(configurations, list) and not configurations
               and isinstance(returned_delivery, Mapping)
               and returned_delivery.get("userPoolId") == pool
               and returned_delivery.get("logConfigurations") == [])
    domain = request.get("domain")
    flags = dict.fromkeys(_FLAGS, False)
    flags["request.cognito_user_directory_listed"] = accepted and name == "ListUsers"
    flags["request.cognito_user_profile_read"] = accepted and name == "AdminGetUser" and has_user
    flags["request.cognito_user_global_sign_out"] = (
        accepted and name == "AdminUserGlobalSignOut" and has_user)
    flags["request.cognito_log_delivery_cleared"] = (
        accepted and name == "SetLogDeliveryConfiguration" and cleared)
    flags["request.cognito_pool_domain_deleted"] = (
        accepted and name == "DeleteUserPoolDomain" and isinstance(domain, str)
        and bool(domain))
    flags["request.cognito_pool_deleted"] = accepted and name == "DeleteUserPool"
    actor = record.get("userIdentity")
    actor = actor if isinstance(actor, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": record["eventSource"],
            "event.name": name, "event.outcome": "success" if accepted else "failure",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": actor.get("arn"), "target.id": pool,
            **flags}
