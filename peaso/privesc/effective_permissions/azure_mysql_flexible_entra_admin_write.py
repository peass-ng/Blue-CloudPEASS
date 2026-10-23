"""Bind MySQL Entra administrator assignment to the exact server and identity."""
from __future__ import annotations

import re

from . import inventory_status, items


SERVER = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.dbformysql/flexibleservers/[^/]+")
UAMI = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.managedidentity/userassignedidentities/[^/]+")
ADMIN_WRITE = {"action": "Microsoft.DBforMySQL/flexibleServers/administrators/write"}
SERVER_WRITE = {"action": "Microsoft.DBforMySQL/flexibleServers/write"}
ASSIGN = {"action": "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"}
START = {"action": "Microsoft.DBforMySQL/flexibleServers/start/action"}
GRAPH_READ = {"user.read.all", "groupmember.read.all", "application.read.all"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _subscription(resource):
    match = re.match(r"/subscriptions/[^/]+", resource)
    return match.group(0) if match else ""


def _grant(model, source, action, scope):
    grant = model.cached_check(source, action, scope)
    return "unknown" if grant is not None and grant.confidence == "unknown" else bool(grant)


def _directory_read(model, pid):
    for role_id, scope, _ in model.dir_assignments.get(pid, ()):
        role = model.dir_roles.get(role_id)
        if (role and _low(role.get("name")) == "directory readers" and role.get("enabled") is not False
                and scope in ("/", "/tenants/" + model.tenant)):
            return True
    graph = {(_low(row.get("appRoleValue") or row.get("permission")))
             for _, row in items(model.snapshot, "directory_app_role_assignment")
             if row.get("principalId") == pid and model._valid_graph_app_grant(row)}
    if GRAPH_READ <= graph or "directory.read.all" in graph:
        return True
    statuses = inventory_status(model.snapshot, "directory_app_role_assignment")
    role_status = inventory_status(model.snapshot, "directory_role_assignment")
    graph_status = statuses.get("/tenants/" + model.tenant + "/servicePrincipals/" + pid)
    if graph_status not in ("collected", "empty") or not role_status or any(
            status not in ("collected", "empty") for status in role_status.values()):
        return "unknown"
    return False


def _identities(model):
    rows = {}
    for _, row in items(model.snapshot, "managed_identity"):
        rid = _low(row.get("id"))
        if UAMI.fullmatch(rid) and _low(row.get("type")) == "microsoft.managedidentity/userassignedidentities":
            pid = (row.get("properties") or {}).get("principalId")
            if isinstance(pid, str) and pid:
                rows[rid] = pid
    return rows


def select(model, candidates, source):
    if source is None or source.kind != "azure_user" or source.attrs.get("account_enabled") is False:
        return {}
    rows = {rid: row for _, row in items(model.snapshot, "mysql_flexible_server")
            if (rid := _low(row.get("id"))) and SERVER.fullmatch(rid)
            and _low(row.get("type")) == "microsoft.dbformysql/flexibleservers"}
    status = inventory_status(model.snapshot, "mysql_flexible_server")
    identities = _identities(model)
    identity_status = inventory_status(model.snapshot, "managed_identity")
    out = {}
    for tid, target in candidates.items():
        server_id = _low(target.scope)
        if not SERVER.fullmatch(server_id):
            continue
        row = rows.get(server_id)
        if row is None:
            if status.get(_subscription(server_id)) not in ("collected", "empty"):
                out[tid] = ("unknown", "mysql_server_inventory_incomplete")
            continue
        state = _low((row.get("properties") or {}).get("state"))
        if state in ("dropping", "disabled"):
            continue
        if state == "stopped":
            start = _grant(model, source, START, server_id)
            if start is not True:
                if start == "unknown":
                    out[tid] = ("unknown", "mysql_server_start_unverified")
                continue
        elif state != "ready":
            out[tid] = ("unknown", "mysql_server_state_unverified")
            continue
        admin = _grant(model, source, ADMIN_WRITE, server_id + "/administrators/ActiveDirectory")
        if admin is not True:
            if admin == "unknown":
                out[tid] = ("unknown", "mysql_admin_write_unverified")
            continue
        if not source.attrs.get("directory") or not source.attrs.get("upn"):
            out[tid] = ("unknown", "mysql_admin_source_user_unverified")
            continue
        attached = (row.get("identity") or {}).get("userAssignedIdentities") or {}
        possibilities = []
        unresolved = False
        if isinstance(attached, dict):
            for identity_id, detail in attached.items():
                uid = _low(identity_id)
                if not UAMI.fullmatch(uid):
                    continue
                pid = identities.get(uid)
                if not pid or ((detail or {}).get("principalId") and _low((detail or {}).get("principalId")) != _low(pid)):
                    unresolved = True
                else:
                    possibilities.append((uid, pid, False))
        else:
            unresolved = True
        # If no suitable identity is attached, the caller may attach one first.
        server_write = _grant(model, source, SERVER_WRITE, server_id)
        if server_write is True:
            for uid, pid in identities.items():
                if uid in attached:
                    continue
                assign = _grant(model, source, ASSIGN, uid)
                if assign is True:
                    possibilities.append((uid, pid, True))
                elif assign == "unknown":
                    unresolved = True
        elif server_write == "unknown":
            unresolved = True
        for _, pid, _ in possibilities:
            directory_read = _directory_read(model, pid)
            if directory_read is True:
                out[tid] = ("conditional", "mysql_entra_admin_network_conditional")
                break
            if directory_read == "unknown":
                unresolved = True
        else:
            if unresolved or identity_status.get(_subscription(server_id)) not in ("collected", "empty"):
                out[tid] = ("unknown", "mysql_entra_identity_or_directory_access_unverified")
    return out
