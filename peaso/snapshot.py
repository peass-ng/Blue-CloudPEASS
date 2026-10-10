"""JSON snapshots are copied at boundaries and addressed by a verified content digest."""
from __future__ import annotations
import copy
import hashlib
import json
from datetime import datetime, timezone

SCHEMA_VERSION = "1.0"
PROVIDERS = ("aws", "gcp", "azure", "k8s")
STATUSES = ("collected", "empty", "partial", "denied", "unknown", "malformed", "timeout", "not_collected")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value).encode()).hexdigest()


def seal(snapshot):
    result = copy.deepcopy(snapshot)
    result.pop("snapshot_id", None)
    result["snapshot_id"] = digest(result)
    return result


def validate(snapshot):
    if not isinstance(snapshot, dict):
        raise ValueError("snapshot must be an object")
    result = copy.deepcopy(snapshot)
    if result.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported snapshot schema_version")
    if result.get("provider") not in PROVIDERS:
        raise ValueError("snapshot provider must be aws, gcp, azure, or k8s")
    if not isinstance(result.get("scopes"), list) or not all(isinstance(x, str) for x in result["scopes"]):
        raise ValueError("snapshot scopes must be a string list")
    if not isinstance(result.get("created_at"), str):
        raise ValueError("snapshot created_at must be a string")
    if not isinstance(result.get("collections"), list):
        raise ValueError("snapshot collections must be a list")
    seen = set()
    for collection in result["collections"]:
        if not isinstance(collection, dict) or not all(isinstance(collection.get(k), str) for k in ("type", "scope", "status")):
            raise ValueError("collection requires type, scope, and status strings")
        if collection["status"] not in STATUSES or not isinstance(collection.get("items"), list):
            raise ValueError("collection requires a known status and items list")
        if any(not isinstance(item, dict) for item in collection["items"]):
            raise ValueError("collection items must be native objects")
        key = (collection["type"], collection["scope"])
        if key in seen:
            raise ValueError("duplicate collection type/scope")
        seen.add(key)
        if collection["status"] in ("empty", "denied", "unknown", "malformed", "timeout", "not_collected") and collection["items"]:
            raise ValueError("unavailable/empty collection cannot contain items")
    original = result.pop("snapshot_id", None)
    calculated = digest(result)
    if original is not None and original != calculated:
        raise ValueError("snapshot content digest mismatch")
    result["snapshot_id"] = calculated
    return result


def make_snapshot(provider, scopes, collections, *, created_at=None, metadata=None):
    return validate(seal({"schema_version": SCHEMA_VERSION, "provider": provider,
        "scopes": list(scopes), "created_at": created_at or datetime.now(timezone.utc).isoformat(),
        "collections": collections, "metadata": metadata or {}}))


def resource_id(provider, kind, scope, item):
    identifiers = {"security_group": "GroupId", "vpc": "VpcId", "subnet": "SubnetId", "instance": "InstanceId",
                   "route_table": "RouteTableId", "ebs_volume": "VolumeId", "network_interface": "NetworkInterfaceId"}
    for explicit in ("_resource_id", "native_id"):
        if isinstance(item.get(explicit), str):
            return item[explicit]
    # Prefer authoritative self identity, never a referenced parent such as VpcId.
    for key in ("Arn", "arn", "id", "selfLink", identifiers.get(kind, "_unused"), "UserName", "GroupName", "RoleName", "PolicyName", "Name", "name"):
        if isinstance(item.get(key), (str, int)):
            return str(item[key])
    meta = item.get("metadata", {})
    if isinstance(meta, dict) and meta.get("name"):
        return f"{meta.get('namespace', '_cluster')}/{meta['name']}"
    return digest(item)


def resources(snapshot):
    output = {}
    for collection in snapshot["collections"]:
        for item in collection["items"]:
            if not isinstance(item, dict):
                continue
            rid = resource_id(snapshot["provider"], collection["type"], collection["scope"], item)
            key = (collection["scope"], collection["type"], rid)
            output[key] = {"id": digest([snapshot["provider"], collection["scope"], collection["type"], rid]), "native_id": rid, "type": collection["type"], "service": collection.get("service", collection["type"].split('_')[0]),
                "scope": collection["scope"], "provider": snapshot["provider"], "data": copy.deepcopy(item)}
    return [output[key] for key in sorted(output)]
