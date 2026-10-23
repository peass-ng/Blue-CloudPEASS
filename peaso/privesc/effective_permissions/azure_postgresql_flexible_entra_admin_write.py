"""Bind PostgreSQL Entra administrator writes to a controlled directory principal."""
from __future__ import annotations

import re

from . import inventory_status, items


SERVER = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.dbforpostgresql/flexibleservers/[^/]+")
ADMIN_WRITE = {"action": "Microsoft.DBforPostgreSQL/flexibleServers/administrators/write"}
SERVER_WRITE = {"action": "Microsoft.DBforPostgreSQL/flexibleServers/write"}
START = {"action": "Microsoft.DBforPostgreSQL/flexibleServers/start/action"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _subscription(resource):
    match = re.match(r"/subscriptions/[^/]+", resource)
    return match.group(0) if match else ""


def _grant(model, source, action, scope):
    grant = model.cached_check(source, action, scope)
    return "unknown" if grant is not None and grant.confidence == "unknown" else bool(grant)


def _controlled_subjects(model, source):
    if source.kind not in ("azure_user", "azure_service_principal", "azure_managed_identity"):
        return ()
    if source.attrs.get("account_enabled") is False:
        return ()
    if not source.attrs.get("directory") and not (source.kind == "azure_managed_identity"
                                                  and (source.attrs.get("uai_resource_verified")
                                                       or source.attrs.get("hosts"))):
        return ()
    groups = [group for group in source.attrs.get("groups") or ()
              if (model.dir_objects.get(group) or {}).get("id") == group]
    return (source.id, *groups)


def select(model, candidates, source):
    if source is None:
        return {}
    subjects = _controlled_subjects(model, source)
    if not subjects:
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
        auth = _low((props.get("authConfig") or {}).get("activeDirectoryAuth"))
        if auth not in ("enabled", "disabled"):
            out[tid] = ("unknown", "postgresql_entra_auth_unverified")
            continue
        role = _low(props.get("replicationRole"))
        replica = bool(props.get("sourceServerResourceId")) or role == "replica"
        if role not in ("none", "primary", "replica") and not replica:
            out[tid] = ("unknown", "postgresql_replication_role_unverified")
            continue
        if auth == "disabled" or replica:
            server_write = _grant(model, source, SERVER_WRITE, server_id)
            if server_write is not True:
                if server_write == "unknown":
                    out[tid] = ("unknown", "postgresql_server_write_unverified")
                continue
        coverage = ((row.get("_coverage") or {}).get("administrators") or {}).get("status")
        if coverage not in ("collected", "empty"):
            out[tid] = ("unknown", "postgresql_administrators_inventory_incomplete")
            continue
        existing = {_low((admin.get("properties") or {}).get("objectId") or admin.get("name"))
                    for admin in row.get("administrators") or [] if isinstance(admin, dict)}
        if any(_low(subject) in existing for subject in subjects):
            continue
        unresolved = False
        for subject in subjects:
            grant = _grant(model, source, ADMIN_WRITE, server_id + "/administrators/" + subject)
            if grant is True:
                out[tid] = ("conditional", "postgresql_entra_admin_network_conditional")
                break
            if grant == "unknown":
                unresolved = True
        else:
            if unresolved:
                out[tid] = ("unknown", "postgresql_admin_write_unverified")
    return out
