"""Bind a SQL administrator password reset to an exact usable logical server."""
from __future__ import annotations

import re

from . import inventory_status, items


SERVER = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.sql/servers/[^/]+")
WRITE = {"action": "Microsoft.Sql/servers/write"}
AUTH_WRITE = {"action": "Microsoft.Sql/servers/azureADOnlyAuthentications/write"}


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
    rows = {rid: row for _, row in items(model.snapshot, "sql_server")
            if (rid := _low(row.get("id"))) and SERVER.fullmatch(rid)
            and _low(row.get("type")) == "microsoft.sql/servers"}
    status = inventory_status(model.snapshot, "sql_server")
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
        props = row.get("properties") or {}
        state = _low(props.get("state"))
        if state in ("disabled", "dropping"):
            continue
        if state != "ready":
            out[tid] = ("unknown", "sql_server_state_unverified")
            continue
        if not isinstance(props.get("administratorLogin"), str) or not props["administratorLogin"]:
            out[tid] = ("unknown", "sql_administrator_login_unverified")
            continue
        write = _grant(model, source, WRITE, server_id)
        if write is not True:
            if write == "unknown":
                out[tid] = ("unknown", "sql_server_write_unverified")
            continue
        children = [child for child in row.get("azureADOnlyAuthentications") or []
                    if _low(child.get("id")) == server_id + "/azureadonlyauthentications/default"]
        mode = ((children[0].get("properties") or {}).get("azureADOnlyAuthentication")
                if len(children) == 1 else None)
        expanded = (props.get("administrators") or {}).get("azureADOnlyAuthentication")
        if type(mode) is bool and type(expanded) is bool and mode != expanded:
            out[tid] = ("unknown", "sql_authentication_mode_conflict")
            continue
        if type(mode) is not bool and type(expanded) is bool:
            mode = expanded
        if type(mode) is not bool:
            out[tid] = ("unknown", "sql_authentication_mode_unverified")
            continue
        if mode:
            auth_id = server_id + "/azureadonlyauthentications/default"
            auth_write = _grant(model, source, AUTH_WRITE, auth_id)
            if auth_write is not True:
                if auth_write == "unknown":
                    out[tid] = ("unknown", "sql_authentication_change_permission_unverified")
                continue
        out[tid] = ("conditional", "sql_administrator_password_reset_network_conditional")
    return out
