"""Retain the Mongo cluster state needed for access analysis without credentials."""
from __future__ import annotations


def project(row):
    if not isinstance(row, dict) or not isinstance(row.get("properties"), dict):
        raise ValueError("Mongo cluster detail has no properties")
    props = row["properties"]
    safe = {key: props[key] for key in (
        "provisioningState", "createMode", "publicNetworkAccess") if key in props}
    replica = props.get("replicaParameters")
    if isinstance(replica, dict) and "sourceResourceId" in replica:
        safe["replicaParameters"] = {"sourceResourceId": replica["sourceResourceId"]}
    auth = props.get("authConfig")
    if isinstance(auth, dict) and "allowedModes" in auth:
        safe["authConfig"] = {"allowedModes": auth["allowedModes"]}
    return {key: row[key] for key in ("id", "type", "name", "location", "_provenance") if key in row} | {
        "properties": safe}
