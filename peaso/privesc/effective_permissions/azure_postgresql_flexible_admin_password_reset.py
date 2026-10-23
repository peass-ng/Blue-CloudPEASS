"""Bind PostgreSQL password reset to a usable exact Flexible Server."""
from __future__ import annotations

import re

from . import inventory_status, items


SERVER = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.dbforpostgresql/flexibleservers/[^/]+")
WRITE = {"action": "Microsoft.DBforPostgreSQL/flexibleServers/write"}
START = {"action": "Microsoft.DBforPostgreSQL/flexibleServers/start/action"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _subscription(resource):
    match = re.match(r"/subscriptions/[^/]+", resource)
    return match.group(0) if match else ""


def _grant(model, source, action, scope):
    grant = model.cached_check(source, action, scope)
    return "unknown" if grant is not None and grant.confidence == "unknown" else bool(grant)


def select(model, candidates, source):
    if source is None:
        return {}
    rows = {rid: row for _, row in items(model.snapshot, "postgresql_flexible_server")
            if (rid := _low(row.get("id"))) and SERVER.fullmatch(rid)
            and _low(row.get("type")) == "microsoft.dbforpostgresql/flexibleservers"}
    status = inventory_status(model.snapshot, "postgresql_flexible_server")
    out = {}
    for tid, target in candidates.items():
        server_id = _low(target.scope)
        if not SERVER.fullmatch(server_id):
            continue
        row = rows.get(server_id)
        if row is None:
            if status.get(_subscription(server_id)) not in ("collected", "empty"):
                out[tid] = ("unknown", "postgresql_server_inventory_incomplete")
            continue
        props = row.get("properties") or {}
        state = _low(props.get("state"))
        if state in ("dropping", "disabled"):
            continue
        if state == "stopped":
            start = _grant(model, source, START, server_id)
            if start is not True:
                if start == "unknown":
                    out[tid] = ("unknown", "postgresql_server_start_unverified")
                continue
        elif state != "ready":
            out[tid] = ("unknown", "postgresql_server_state_unverified")
            continue
        write = _grant(model, source, WRITE, server_id)
        if write is not True:
            if write == "unknown":
                out[tid] = ("unknown", "postgresql_server_write_unverified")
            continue
        auth = props.get("authConfig") or {}
        password_auth = _low(auth.get("passwordAuth"))
        if password_auth not in ("enabled", "disabled"):
            out[tid] = ("unknown", "postgresql_password_auth_unverified")
            continue
        if password_auth == "enabled" and not props.get("administratorLogin"):
            out[tid] = ("unknown", "postgresql_administrator_login_unverified")
            continue
        role = _low(props.get("replicationRole"))
        replica = bool(props.get("sourceServerResourceId")) or role == "replica"
        if role not in ("none", "primary", "replica") and not replica:
            out[tid] = ("unknown", "postgresql_replication_role_unverified")
            continue
        out[tid] = ("conditional", "postgresql_replica_promote_then_reset_network_conditional"
                    if replica else "postgresql_admin_password_reset_network_conditional")
    return out
