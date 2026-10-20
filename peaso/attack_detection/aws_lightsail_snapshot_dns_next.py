"""Bounded Lightsail default-key, snapshot, export and DNS request signals.

CloudTrail omits the private key and snapshot-list responses. Only validated
request metadata and success flags enter canonical evidence.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_INSTANCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{1,254}\Z")
_DOMAIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{1,251}[A-Za-z0-9])?\Z")
_FLAGS = {
    "DownloadDefaultKeyPair": "request.lightsail_default_key_pair_downloaded",
    "GetInstanceSnapshots": "request.lightsail_instance_snapshots_listed",
    "CreateInstancesFromSnapshot": "request.lightsail_instance_snapshot_restore_started",
    "ExportSnapshot": "request.lightsail_snapshot_export_started",
    "CreateDomainEntry": "request.lightsail_domain_entry_created",
    "UpdateDomainEntry": "request.lightsail_domain_entry_updated",
}


def _operations(value: Any, resource: str, operation_type: str | None = None) -> bool:
    return (isinstance(value, list) and bool(value)
            and all(isinstance(op, Mapping) and op.get("status") in {"Started", "Succeeded"}
                    for op in value)
            and any(isinstance(op, Mapping) and op.get("resourceName") == resource
                    and (operation_type is None or op.get("operationType") == operation_type)
                    for op in value))


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "lightsail.amazonaws.com" or name not in _FLAGS
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall" or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name in {"DownloadDefaultKeyPair", "GetInstanceSnapshots"})
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
    accepted = False
    if name == "DownloadDefaultKeyPair":
        accepted = not request
    elif name == "GetInstanceSnapshots":
        accepted = not request or (set(request) == {"pageToken"}
                                   and isinstance(request.get("pageToken"), str))
    elif name == "CreateInstancesFromSnapshot":
        snapshot = request.get("instanceSnapshotName")
        instances = request.get("instanceNames")
        operations = response.get("operations")
        accepted = (isinstance(snapshot, str) and bool(_INSTANCE.fullmatch(snapshot))
                    and isinstance(instances, list) and 1 <= len(instances) <= 20
                    and all(isinstance(x, str) and bool(_INSTANCE.fullmatch(x)) for x in instances)
                    and any(_operations(operations, x, "CreateInstancesFromSnapshot") for x in instances))
        target = instances[0] if accepted else None
    elif name == "ExportSnapshot":
        snapshot = request.get("sourceSnapshotName")
        accepted = (isinstance(snapshot, str) and bool(_INSTANCE.fullmatch(snapshot))
                    and _operations(response.get("operations"), snapshot, "ExportSnapshot"))
        target = snapshot if accepted else None
    else:
        domain = request.get("domainName")
        entry = request.get("domainEntry")
        operation = response.get("operation") if name == "CreateDomainEntry" else None
        operations = [operation] if operation is not None else response.get("operations")
        accepted = (isinstance(domain, str) and bool(_DOMAIN.fullmatch(domain))
                    and isinstance(entry, Mapping) and isinstance(entry.get("name"), str)
                    and (entry["name"] == domain or entry["name"].endswith("." + domain))
                    and entry.get("type") in {"A", "AAAA", "CNAME", "MX", "TXT"}
                    and isinstance(entry.get("target"), str) and bool(entry["target"])
                    and (name != "UpdateDomainEntry" or isinstance(entry.get("id"), str))
                    and _operations(operations, domain))
        target = domain if accepted else None
    if not accepted:
        return None
    return {"cloud.provider": "aws", "event.source": "lightsail.amazonaws.com",
            "event.name": name, "event.outcome": "success", "event.id": record["eventID"],
            "event.time": record["eventTime"], "account.id": account,
            "actor.id": identity["arn"], "target.id": target, _FLAGS[name]: True}
