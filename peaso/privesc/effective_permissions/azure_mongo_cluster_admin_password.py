"""Bind Mongo administrator-password control to one usable primary cluster."""
from __future__ import annotations

import re

from . import inventory_status, items


CLUSTER = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.documentdb/mongoclusters/[^/]+")
WRITE = {"action": "Microsoft.DocumentDB/mongoClusters/write"}


def _subscription(resource):
    match = re.match(r"/subscriptions/[^/]+", resource)
    return match.group(0) if match else ""


def select(model, candidates, source):
    if source is None:
        return {}
    rows = {str(row.get("id") or "").casefold(): row
            for _, row in items(model.snapshot, "mongo_cluster")
            if CLUSTER.fullmatch(str(row.get("id") or "").casefold())
            and str(row.get("type") or "").casefold() == "microsoft.documentdb/mongoclusters"}
    status = inventory_status(model.snapshot, "mongo_cluster")
    out = {}
    for tid, target in candidates.items():
        cluster_id = str(target.scope).casefold()
        if not CLUSTER.fullmatch(cluster_id):
            continue
        row = rows.get(cluster_id)
        if row is None:
            if status.get(_subscription(cluster_id)) not in ("collected", "empty"):
                out[tid] = ("unknown", "mongo_cluster_inventory_incomplete")
            continue
        props = row.get("properties")
        if not isinstance(props, dict):
            out[tid] = ("unknown", "mongo_cluster_state_unverified")
            continue
        state = str(props.get("provisioningState") or "").casefold()
        if state in ("failed", "canceled", "deleting"):
            continue
        if state != "succeeded":
            out[tid] = ("unknown", "mongo_cluster_state_unverified")
            continue
        mode = str(props.get("createMode") or "").casefold()
        replica = props.get("replicaParameters") or {}
        if mode in ("georeplica", "replica") or (isinstance(replica, dict) and replica.get("sourceResourceId")):
            continue
        grant = model.cached_check(source, WRITE, cluster_id)
        if grant is None:
            continue
        if grant.confidence == "unknown":
            out[tid] = ("unknown", "mongo_cluster_write_unverified")
            continue
        out[tid] = ("conditional", "mongo_admin_password_reset_network_conditional")
    return out
