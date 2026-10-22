"""Accepted enabled Logs Insights scheduled query with an S3 destination."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_S3_URI = re.compile(r"s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9](?:/[^\s]*)?\Z")


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "logs.amazonaws.com"
            or name not in {"CreateScheduledQuery", "UpdateScheduledQuery"}
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or request.get("state") != "ENABLED" or response.get("state") != "ENABLED"
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    destination = request.get("destinationConfiguration")
    s3 = destination.get("s3Configuration") if isinstance(destination, Mapping) else None
    if not isinstance(s3, Mapping):
        return None
    query, groups = request.get("queryString"), request.get("logGroupIdentifiers")
    if (not isinstance(query, str) or not query
            or not isinstance(groups, list) or not groups
            or any(not isinstance(group, str) or not group for group in groups)
            or not isinstance(s3.get("destinationIdentifier"), str)
            or not _S3_URI.fullmatch(s3["destinationIdentifier"])
            or not isinstance(s3.get("ownerAccountId"), str)
            or not _ACCOUNT.fullmatch(s3["ownerAccountId"])):
        return None
    role_prefix = f"arn:aws:iam::{account}:role/"
    if (not isinstance(request.get("executionRoleArn"), str)
            or not request["executionRoleArn"].startswith(role_prefix)
            or not isinstance(s3.get("roleArn"), str)
            or not s3["roleArn"].startswith(role_prefix)):
        return None
    arn = response.get("scheduledQueryArn")
    resources = record.get("resources")
    if (not isinstance(arn, str)
            or not arn.startswith(f"arn:aws:logs:{region}:{account}:scheduled-query:")
            or (name == "UpdateScheduledQuery" and request.get("identifier") != arn)
            or not isinstance(resources, list) or len(resources) != 1
            or not isinstance(resources[0], Mapping)
            or resources[0].get("type") != "AWS::Logs::ScheduledQuery"
            or resources[0].get("ARN") != arn):
        return None
    identity = record.get("userIdentity")
    if (not isinstance(identity, Mapping) or identity.get("type") == "AWSService"
            or identity.get("invokedBy") or identity.get("accountId") != account):
        return None
    return {
        "cloud.provider": "aws", "event.source": "logs.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": "sha256:" + hashlib.sha256(arn.encode()).hexdigest()[:24],
        "request.logs_enabled_scheduled_query": True,
    }
