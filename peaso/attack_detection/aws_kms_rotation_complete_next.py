"""KMS service event confirming an on-demand material rotation completed."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_KEY_ID = re.compile(r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})\Z")
_MATERIAL_ID = re.compile(r"[0-9a-f]{64}\Z")


def normalize_aws_kms_on_demand_rotation(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "kms.amazonaws.com"
            or record.get("eventName") != "RotateKey"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsServiceEvent"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("requestParameters") is not None):
        return None
    details = record.get("serviceEventDetails")
    if not isinstance(details, Mapping):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    key = details.get("keyId")
    if (not isinstance(account, str) or not re.fullmatch(r"\d{12}", account)
            or not isinstance(region, str) or not isinstance(key, str)
            or not _KEY_ID.fullmatch(key)):
        return None
    arn = f"arn:aws:kms:{region}:{account}:key/{key}"
    resources = record.get("resources")
    if not isinstance(resources, list) or not any(isinstance(item, Mapping)
            and item.get("accountId") == account and item.get("ARN") == arn
            for item in resources):
        return None
    before, after = details.get("previousKeyMaterialId"), details.get("currentKeyMaterialId")
    accepted = (not record.get("errorCode") and not record.get("errorMessage")
                and details.get("rotationType") == "ON_DEMAND"
                and details.get("keyOrigin") in {"AWS_KMS", "EXTERNAL"}
                and isinstance(before, str) and bool(_MATERIAL_ID.fullmatch(before))
                and isinstance(after, str) and bool(_MATERIAL_ID.fullmatch(after))
                and before != after)
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": "kms.amazonaws.com",
            "event.name": "RotateKey",
            "event.outcome": "success" if accepted else "failure",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity.get("arn") or identity.get("invokedBy"),
            "target.id": arn, "request.kms_on_demand_rotation_completed": accepted}
