"""Lightsail database read, exposure, opaque update and snapshot signals.

CloudTrail omits returned passwords and can omit password-update parameters.
Only checked event metadata and boolean signals enter canonical evidence.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{1,254}\Z")
_FLAGS = {
    "GetRelationalDatabaseSnapshots": "request.lightsail_db_snapshots_listed",
    "CreateRelationalDatabaseFromSnapshot": "request.lightsail_db_snapshot_restore_started",
}


def _operation(response: Mapping[str, Any], resource: str, kind: str) -> bool:
    operations = response.get("operations")
    return (isinstance(operations, list) and bool(operations)
            and all(isinstance(x, Mapping) and x.get("status") in {"Started", "Succeeded"}
                    for x in operations)
            and any(x.get("resourceName") == resource and x.get("operationType") == kind
                    for x in operations))


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "lightsail.amazonaws.com"
            or name not in {"GetRelationalDatabaseMasterUserPassword", "UpdateRelationalDatabase",
                            "GetRelationalDatabaseSnapshots", "CreateRelationalDatabaseFromSnapshot"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall" or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name.startswith("Get"))
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account = record.get("recipientAccountId")
    identity = record.get("userIdentity")
    region = record.get("awsRegion")
    if (not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account)
            or not isinstance(identity, Mapping) or not isinstance(identity.get("arn"), str)
            or identity.get("accountId") not in (None, account)
            or not isinstance(region, str) or not region
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str) or not record["eventTime"]):
        return None
    request = record.get("requestParameters")
    response = record.get("responseElements")
    request = request if isinstance(request, Mapping) else {}
    response = response if isinstance(response, Mapping) else {}
    target = None
    flag = None
    if name == "GetRelationalDatabaseMasterUserPassword":
        target = request.get("relationalDatabaseName")
        version = request.get("passwordVersion", "CURRENT")
        if isinstance(target, str) and _NAME.fullmatch(target) and version in {"CURRENT", "PREVIOUS"}:
            flag = ("request.lightsail_db_previous_password_read" if version == "PREVIOUS"
                    else "request.lightsail_db_current_password_read")
    elif name == "GetRelationalDatabaseSnapshots":
        if not request or (set(request) == {"pageToken"} and isinstance(request.get("pageToken"), str)):
            flag = _FLAGS[name]
    elif name == "UpdateRelationalDatabase":
        target = request.get("relationalDatabaseName")
        if isinstance(target, str) and _NAME.fullmatch(target) and _operation(response, target, name):
            if request.get("publiclyAccessible") is True:
                flag = "request.lightsail_db_public_access_enabled"
            elif set(request) <= {"relationalDatabaseName", "applyImmediately"}:
                flag = "request.lightsail_db_opaque_update"
    else:
        target = request.get("relationalDatabaseName")
        snapshot = request.get("relationalDatabaseSnapshotName")
        if (isinstance(target, str) and _NAME.fullmatch(target)
                and isinstance(snapshot, str) and _NAME.fullmatch(snapshot)
                and _operation(response, target, name)):
            flag = _FLAGS[name]
    if flag is None:
        return None
    return {"cloud.provider": "aws", "event.source": "lightsail.amazonaws.com",
            "event.name": name, "event.outcome": "success", "event.id": record["eventID"],
            "event.time": record["eventTime"], "account.id": account,
            "actor.id": identity["arn"], "target.id": target, flag: True}
