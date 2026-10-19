"""Accepted replication of a customer managed multi-Region KMS key."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_MRK = re.compile(r"mrk-[0-9a-f]{32}\Z")


def normalize_aws_kms_replication(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "kms.amazonaws.com"
            or record.get("eventName") != "ReplicateKey"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account) or not isinstance(region, str):
        return None
    requested = request.get("keyId")
    replica_region = request.get("replicaRegion")
    if not isinstance(requested, str) or not isinstance(replica_region, str) or replica_region == region:
        return None
    prefix = f"arn:aws:kms:{region}:{account}:key/"
    primary_arn = requested if requested.startswith(prefix) else prefix + requested
    key_id = primary_arn[len(prefix):]
    if not _MRK.fullmatch(key_id):
        return None
    replica_arn = f"arn:aws:kms:{replica_region}:{account}:key/{key_id}"
    metadata = response.get("replicaKeyMetadata")
    if not isinstance(metadata, Mapping):
        return None
    config = metadata.get("multiRegionConfiguration")
    primary = config.get("primaryKey") if isinstance(config, Mapping) else None
    if (metadata.get("aWSAccountId") != account or metadata.get("keyId") != key_id
            or metadata.get("arn") != replica_arn or metadata.get("multiRegion") is not True
            or metadata.get("keyManager") != "CUSTOMER"
            or metadata.get("keyState") not in {"Creating", "Enabled"}
            or not isinstance(config, Mapping) or config.get("multiRegionKeyType") != "REPLICA"
            or not isinstance(primary, Mapping) or primary.get("arn") != primary_arn
            or primary.get("region") != region):
        return None
    resources = record.get("resources")
    if not isinstance(resources, list) or not any(isinstance(item, Mapping)
            and item.get("accountId") == account and item.get("ARN") == primary_arn
            for item in resources):
        return None
    accepted = not record.get("errorCode") and not record.get("errorMessage")
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": "kms.amazonaws.com",
            "event.name": "ReplicateKey",
            "event.outcome": "success" if accepted else "failure",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity.get("arn"), "target.id": replica_arn,
            "request.kms_multiregion_replica_created": accepted}
