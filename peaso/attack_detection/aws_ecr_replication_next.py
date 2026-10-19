"""Detect ECR replication configured to another AWS registry."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_ecr_replication(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "ecr.amazonaws.com" or record.get("eventName") != "PutReplicationConfiguration":
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    account = record.get("recipientAccountId")
    if not isinstance(account, str) or re.fullmatch(r"\d{12}", account) is None:
        return None
    configuration = request.get("replicationConfiguration")
    actual = response.get("replicationConfiguration")
    if not isinstance(configuration, Mapping) or actual != configuration:
        return None
    rules = configuration.get("rules")
    if not isinstance(rules, list):
        return None
    external = False
    for rule in rules:
        destinations = rule.get("destinations") if isinstance(rule, Mapping) else None
        if not isinstance(destinations, list):
            continue
        for destination in destinations:
            if not isinstance(destination, Mapping):
                continue
            registry = destination.get("registryId")
            region = destination.get("region")
            if (isinstance(registry, str) and re.fullmatch(r"\d{12}", registry)
                    and registry != account and isinstance(region, str) and region):
                external = True
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "ecr.amazonaws.com",
        "event.name": "PutReplicationConfiguration", "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": account,
        "request.ecr_external_replication": not failed and external,
    }
