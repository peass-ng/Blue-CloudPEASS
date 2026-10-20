"""AppSync read, introspection, and function-update management signals.

Read API responses are absent from CloudTrail. The signals represent accepted
access requests, while content and function bodies stay outside evidence.
"""

from collections.abc import Mapping
import re
from typing import Any

_READS = {"GetGraphqlApiEnvironmentVariables", "ListApiKeys", "GetIntrospectionSchema"}
_WRITES = {"UpdateFunction", "UpdateGraphqlApi"}
_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]\Z")
_API_ID = re.compile(r"[a-z0-9]{26}\Z")


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "appsync.amazonaws.com"
            or name not in _READS | _WRITES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name in _READS)):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response, identity = (record.get("requestParameters"),
                                   record.get("responseElements"),
                                   record.get("userIdentity"))
    if (not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping) or not isinstance(identity, Mapping)
            or identity.get("accountId") not in (None, account)
            or not isinstance(identity.get("arn"), str)
            or not identity["arn"].startswith("arn:")
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    api_id = request.get("apiId")
    if not isinstance(api_id, str) or not _API_ID.fullmatch(api_id):
        return None
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    api_arn = f"arn:{partition}:appsync:{region}:{account}:apis/{api_id}"
    flags = {
        "request.appsync_environment_read": name == "GetGraphqlApiEnvironmentVariables",
        "request.appsync_api_keys_listed": name == "ListApiKeys",
        "request.appsync_schema_export_requested": name == "GetIntrospectionSchema"
            and request.get("format") in {"SDL", "JSON"},
        "request.appsync_function_definition_updated": False,
        "request.appsync_introspection_enabled": False,
    }
    if name == "UpdateFunction":
        config = response.get("functionConfiguration") if isinstance(response, Mapping) else None
        function_id = request.get("functionId")
        if (isinstance(config, Mapping) and isinstance(function_id, str)
                and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", function_id)):
            flags["request.appsync_function_definition_updated"] = (
                any(key in request for key in ("requestMappingTemplate", "responseMappingTemplate", "code"))
                and config.get("functionId") == function_id
                and config.get("functionArn") == f"{api_arn}/functions/{function_id}"
                and config.get("name") == request.get("name"))
    elif name == "UpdateGraphqlApi":
        api = response.get("graphqlApi") if isinstance(response, Mapping) else None
        flags["request.appsync_introspection_enabled"] = (
            request.get("introspectionConfig") == "ENABLED"
            and isinstance(api, Mapping) and api.get("apiId") == api_id
            and api.get("arn") == api_arn
            and api.get("introspectionConfig") == "ENABLED")
    if not any(flags.values()):
        return None
    return {"cloud.provider": "aws", "event.source": "appsync.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity["arn"], "target.id": api_arn,
            **flags}
