"""Accepted removal of imported KMS key material."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_KEY_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


def normalize_aws_kms_imported_material(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "kms.amazonaws.com"
            or record.get("eventName") != "DeleteImportedKeyMaterial"
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
    key = request.get("keyId")
    prefix = f"arn:aws:kms:{region}:{account}:key/"
    if not isinstance(key, str):
        return None
    key_arn = key if key.startswith(prefix) else prefix + key
    if not _KEY_ID.fullmatch(key_arn[len(prefix):]):
        return None
    resources = record.get("resources")
    if not isinstance(resources, list) or not any(isinstance(r, Mapping)
            and r.get("accountId") == account and r.get("ARN") == key_arn for r in resources):
        return None
    material = request.get("keyMaterialId")
    if material is not None and (not isinstance(material, str)
                                 or not re.fullmatch(r"[0-9a-f]{64}", material)
                                 or response.get("keyMaterialId") != material):
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    accepted = not failed and response.get("keyId") == key_arn
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": "kms.amazonaws.com",
            "event.name": "DeleteImportedKeyMaterial",
            "event.outcome": "success" if accepted else "failure",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity.get("arn"), "target.id": key_arn,
            "request.kms_imported_material_deleted": accepted}
