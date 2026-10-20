"""Project signed HTTP data-source role grants in AppSync.

HTTP resolver mapping templates and API keys may be secret-bearing. Only a
validated resource ARN and route boolean are emitted.
"""

from collections.abc import Mapping
import re
from typing import Any
from urllib.parse import urlsplit


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]\Z")
_API_ID = re.compile(r"[a-z0-9]{26}\Z")
_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]{0,127}\Z")
_SERVICE = re.compile(r"[a-z0-9-]{2,64}\Z")


def _partition(region: str) -> str:
    return "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"


def _aws_endpoint(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = urlsplit(value)
        host, port = parsed.hostname or "", parsed.port
    except ValueError:
        return False
    return (parsed.scheme == "https" and port in (None, 443)
            and not parsed.username and not parsed.password
            and not parsed.path.strip("/") and not parsed.query and not parsed.fragment
            and (host.endswith(".amazonaws.com") or host.endswith(".amazonaws.com.cn")))


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name, source = record.get("eventName"), record.get("eventSource")
    if (source != "appsync.amazonaws.com"
            or name not in ("CreateDataSource", "UpdateDataSource")
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, identity = record.get("requestParameters"), record.get("userIdentity")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping) or not isinstance(identity, Mapping)
            or identity.get("accountId") not in (None, account)
            or not isinstance(identity.get("arn"), str)
            or not identity["arn"].startswith("arn:")
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    api_id, data_name = request.get("apiId"), request.get("name")
    role, http = request.get("serviceRoleArn"), request.get("httpConfig")
    if (not isinstance(api_id, str) or not _API_ID.fullmatch(api_id)
            or not isinstance(data_name, str) or not _NAME.fullmatch(data_name)
            or request.get("type") != "HTTP"
            or not isinstance(role, str)
            or not re.fullmatch(
                rf"arn:{_partition(region)}:iam::{account}:role/[A-Za-z0-9+=,.@_/-]+", role)
            or not isinstance(http, Mapping) or not _aws_endpoint(http.get("endpoint"))):
        return None
    auth = http.get("authorizationConfig")
    config = auth.get("awsIamConfig") if isinstance(auth, Mapping) else None
    if (not isinstance(auth, Mapping) or auth.get("authorizationType") != "AWS_IAM"
            or not isinstance(config, Mapping)
            or config.get("signingRegion") != region
            or not isinstance(config.get("signingServiceName"), str)
            or not _SERVICE.fullmatch(config["signingServiceName"])):
        return None
    response = record.get("responseElements")
    returned = response.get("dataSource") if isinstance(response, Mapping) else None
    api_arn = f"arn:{_partition(region)}:appsync:{region}:{account}:apis/{api_id}"
    target = f"{api_arn}/datasources/{data_name}"
    if (not isinstance(returned, Mapping) or returned.get("dataSourceArn") != target
            or returned.get("name") != data_name or returned.get("type") != "HTTP"
            or returned.get("serviceRoleArn") != role):
        return None
    flag = ("request.appsync_signed_http_role_data_source_created" if name == "CreateDataSource"
            else "request.appsync_signed_http_role_data_source_updated")
    return {"cloud.provider": "aws", "event.source": source,
            "event.name": name, "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity["arn"], "target.id": target,
            flag: True}
