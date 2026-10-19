"""DynamoDB TTL and table deletion changes."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def normalize_aws_dynamodb_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "dynamodb.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"UpdateTimeToLive", "DeleteTable"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    table = request.get("tableName")
    if not isinstance(table, str) or not table:
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or response.get("errorCode") or response.get("errorMessage"))
    requested_ttl = request.get("timeToLiveSpecification")
    returned_ttl = response.get("timeToLiveSpecification")
    ttl = (isinstance(requested_ttl, Mapping) and isinstance(returned_ttl, Mapping)
           and requested_ttl.get("enabled") is True and returned_ttl.get("enabled") is True
           and isinstance(requested_ttl.get("attributeName"), str)
           and bool(requested_ttl["attributeName"])
           and returned_ttl.get("attributeName") == requested_ttl["attributeName"])
    deleted = response.get("tableDescription")
    deleted = (isinstance(deleted, Mapping) and deleted.get("tableName") == table
               and deleted.get("tableStatus") == "DELETING")
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "dynamodb.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId"), "actor.id": identity.get("arn"),
        "target.id": table,
        "request.dynamodb_ttl_enable_accepted": not failed and name == "UpdateTimeToLive" and ttl,
        "request.dynamodb_table_delete_accepted": not failed and name == "DeleteTable" and deleted,
    }
