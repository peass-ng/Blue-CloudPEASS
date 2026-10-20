"""AppSync management mutations proven on an isolated synthetic GraphQL API.

CloudTrail masks API keys, resolver code/templates and environment variable
maps. Emit only route booleans and the API ARN; never copy those fields.
"""

from collections.abc import Mapping
import re
from typing import Any

_OPERATIONS = {"UpdateGraphqlApi", "CreateApiKey", "UpdateApiKey",
               "PutGraphqlApiEnvironmentVariables", "UpdateResolver"}
_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]\Z")
_API_ID = re.compile(r"[a-z0-9]{26}\Z")
_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]{0,127}\Z")


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "appsync.amazonaws.com"
            or record.get("eventName") not in _OPERATIONS
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request, response = (record.get("userIdentity"),
                                   record.get("requestParameters"),
                                   record.get("responseElements"))
    if (not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or not isinstance(request, Mapping)
            or not isinstance(response, Mapping)
            or identity.get("accountId") not in (None, account)
            or not isinstance(identity.get("arn"), str)
            or not identity["arn"].startswith("arn:")
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    api_id = request.get("apiId")
    if not isinstance(api_id, str) or not _API_ID.fullmatch(api_id):
        return None
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    api_arn = f"arn:{partition}:appsync:{region}:{account}:apis/{api_id}"
    name = record["eventName"]
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or response.get("errorCode") or response.get("errorMessage"))
    flags = {
        "request.appsync_api_key_auth_enabled": False,
        "request.appsync_api_key_created": False,
        "request.appsync_api_key_updated": False,
        "request.appsync_environment_replaced": False,
        "request.appsync_resolver_definition_updated": False,
    }
    if name == "UpdateGraphqlApi":
        returned = response.get("graphqlApi")
        flags["request.appsync_api_key_auth_enabled"] = (
            request.get("authenticationType") == "API_KEY"
            and isinstance(returned, Mapping)
            and returned.get("apiId") == api_id
            and returned.get("arn") == api_arn
            and returned.get("authenticationType") == "API_KEY")
    elif name == "CreateApiKey":
        key = response.get("apiKey")
        flags["request.appsync_api_key_created"] = (
            isinstance(key, Mapping) and isinstance(key.get("id"), str)
            and bool(key["id"]) and isinstance(key.get("expires"), int)
            and key["expires"] > 0)
    elif name == "UpdateApiKey":
        key = response.get("apiKey")
        flags["request.appsync_api_key_updated"] = (
            isinstance(request.get("id"), str) and bool(request["id"])
            and isinstance(key, Mapping) and isinstance(key.get("id"), str)
            and bool(key["id"]) and isinstance(key.get("expires"), int)
            and key["expires"] > 0 and isinstance(request.get("expires"), int))
    elif name == "PutGraphqlApiEnvironmentVariables":
        flags["request.appsync_environment_replaced"] = (
            "environmentVariables" in request and "environmentVariables" in response)
    elif name == "UpdateResolver":
        resolver = response.get("resolver")
        type_name, field_name = request.get("typeName"), request.get("fieldName")
        if (isinstance(type_name, str) and _NAME.fullmatch(type_name)
                and isinstance(field_name, str) and _NAME.fullmatch(field_name)
                and isinstance(resolver, Mapping)):
            resolver_arn = f"{api_arn}/types/{type_name}/resolvers/{field_name}"
            flags["request.appsync_resolver_definition_updated"] = (
                any(key in request for key in ("requestMappingTemplate", "responseMappingTemplate", "code"))
                and resolver.get("resolverArn") == resolver_arn
                and resolver.get("typeName") == type_name
                and resolver.get("fieldName") == field_name)
    if not any(flags.values()):
        return None
    return {"cloud.provider": "aws", "event.source": "appsync.amazonaws.com",
            "event.name": name, "event.outcome": "failure" if failed else "success",
            "event.id": record["eventID"], "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity["arn"], "target.id": api_arn,
            **flags}
