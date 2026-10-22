"""Bind SQL Entra administrator writes to an exact server and controlled identity."""
from __future__ import annotations

import re

from . import inventory_status, items
from .azure_postgresql_flexible_entra_admin_write import _controlled_subjects


SERVER = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.sql/servers/[^/]+")
ADMIN_WRITE = {"action": "Microsoft.Sql/servers/administrators/write"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _subscription(resource):
    match = re.match(r"/subscriptions/[^/]+", resource)
    return match.group(0) if match else ""


def select(model, candidates, source):
    if source is None:
        return {}
    subjects = {_low(subject) for subject in _controlled_subjects(model, source)}
    if not subjects:
        return {}
    rows = {rid: row for _, row in items(model.snapshot, "sql_server")
            if (rid := _low(row.get("id"))) and SERVER.fullmatch(rid)
            and _low(row.get("type")) == "microsoft.sql/servers"}
    status = inventory_status(model.snapshot, "sql_server")
    directory_objects = {_low(oid): obj for oid, obj in model.dir_objects.items()}
    membership_status = {_low(oid): state for oid, state in model.membership_status.items()}
    out = {}
    for tid, target in candidates.items():
        server_id = _low(target.scope)
        if not SERVER.fullmatch(server_id):
            continue
        row = rows.get(server_id)
        if row is None:
            if status.get(_subscription(server_id)) not in ("collected", "empty"):
                out[tid] = ("unknown", "sql_server_inventory_incomplete")
            continue
        state = _low((row.get("properties") or {}).get("state"))
        if state in ("disabled", "dropping"):
            continue
        if state != "ready":
            out[tid] = ("unknown", "sql_server_state_unverified")
            continue
        coverage = ((row.get("_coverage") or {}).get("serverAdministrators") or {}).get("status")
        if coverage not in ("collected", "empty"):
            out[tid] = ("unknown", "sql_entra_administrator_inventory_incomplete")
            continue
        admins = row.get("serverAdministrators") or []
        if len(admins) > 1:
            out[tid] = ("unknown", "sql_entra_administrator_inventory_malformed")
            continue
        if admins:
            admin = admins[0]
            if (_low(admin.get("id")) != server_id + "/administrators/activedirectory"
                    or _low(admin.get("type")) != "microsoft.sql/servers/administrators"):
                out[tid] = ("unknown", "sql_entra_administrator_inventory_malformed")
                continue
            sid = _low((admin.get("properties") or {}).get("sid"))
            if not sid:
                out[tid] = ("unknown", "sql_entra_administrator_identity_unverified")
                continue
            if sid in subjects:
                continue
            directory_obj = directory_objects.get(sid) or {}
            if directory_obj.get("securityEnabled") is not None and membership_status.get(sid) not in ("collected", "empty"):
                out[tid] = ("unknown", "sql_existing_admin_group_membership_incomplete")
                continue
        child_id = server_id + "/administrators/activedirectory"
        grant = model.cached_check(source, ADMIN_WRITE, child_id)
        if grant is None:
            continue
        if grant.confidence == "unknown":
            out[tid] = ("unknown", "sql_entra_admin_write_unverified")
            continue
        out[tid] = ("conditional", "sql_entra_admin_network_conditional")
    return out
