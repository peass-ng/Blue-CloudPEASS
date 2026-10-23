"""Bind a Mongo root self-grant to the source's exact user child resource."""
from __future__ import annotations

import re

from . import inventory_status, items
from .azure_mongo_cluster_admin_password import CLUSTER, _subscription


USER_WRITE = {"action": "Microsoft.DocumentDB/mongoClusters/users/write"}
CLUSTER_WRITE = {"action": "Microsoft.DocumentDB/mongoClusters/write"}
GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
SOURCE_KINDS = frozenset({"azure_user", "azure_service_principal", "azure_managed_identity"})


def select(model, candidates, source):
    if source is None or source.kind not in SOURCE_KINDS or not GUID.fullmatch(source.id.casefold()):
        return {}
    if source.attrs.get("account_enabled") is False:
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
        replica = props.get("replicaParameters") or {}
        if (str(props.get("createMode") or "").casefold() in ("georeplica", "replica")
                or isinstance(replica, dict) and replica.get("sourceResourceId")):
            continue
        user_id = cluster_id + "/users/" + source.id.casefold()
        grant = model.cached_check(source, USER_WRITE, user_id)
        if grant is None:
            prefix = cluster_id + "/users/"
            for principal_id in (source.id, *source.attrs.get("groups", ())):
                for assignment in model.assignments.get(principal_id, ()):
                    child = str(assignment.get("scope") or "").casefold()
                    if (child.startswith(prefix) and GUID.fullmatch(child[len(prefix):])
                            and child != user_id):
                        other = model.cached_check(source, USER_WRITE, child)
                        if other is not None:
                            out[tid] = ("unknown", "mongo_other_user_control_unverified")
                            break
            continue
        if grant.confidence == "unknown":
            out[tid] = ("unknown", "mongo_user_write_unverified")
            continue
        auth = props.get("authConfig")
        modes = auth.get("allowedModes") if isinstance(auth, dict) else None
        if not isinstance(modes, list):
            # A missing mode can be the pre-Entra default or an incomplete read.
            enable = model.cached_check(source, CLUSTER_WRITE, cluster_id)
            out[tid] = (("conditional", "mongo_entra_auth_enableable") if enable is not None
                        and enable.confidence != "unknown" else ("unknown", "mongo_entra_auth_unverified"))
            continue
        if not any(str(mode).casefold() == "microsoftentraid" for mode in modes):
            enable = model.cached_check(source, CLUSTER_WRITE, cluster_id)
            if enable is None:
                continue
            if enable.confidence == "unknown":
                out[tid] = ("unknown", "mongo_entra_auth_enable_unverified")
                continue
        out[tid] = ("conditional", "mongo_self_root_grant_network_conditional")
    return out
