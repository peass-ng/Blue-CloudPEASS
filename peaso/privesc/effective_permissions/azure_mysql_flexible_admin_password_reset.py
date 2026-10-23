"""Bind a MySQL administrator password reset to one usable Flexible Server."""
from __future__ import annotations

import re

from . import inventory_status, items


SERVER = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.dbformysql/flexibleservers/[^/]+")
WRITE = {"action": "Microsoft.DBforMySQL/flexibleServers/write"}
CONFIG_WRITE = {"action": "Microsoft.DBforMySQL/flexibleServers/configurations/write"}
START = {"action": "Microsoft.DBforMySQL/flexibleServers/start/action"}
RESTART = {"action": "Microsoft.DBforMySQL/flexibleServers/restart/action"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _subscription(resource):
    match = re.match(r"/subscriptions/[^/]+", resource)
    return match.group(0) if match else ""


def _held(model, source, action, scope):
    grant = model.cached_check(source, action, scope)
    if grant is None:
        return False, False
    return grant.confidence != "unknown", grant.confidence == "unknown"


def select(model, candidates, source):
    if source is None:
        return {}
    rows = {rid: row for _, row in items(model.snapshot, "mysql_flexible_server")
            if (rid := _low(row.get("id"))) and SERVER.fullmatch(rid)
            and _low(row.get("type")) == "microsoft.dbformysql/flexibleservers"}
    status = inventory_status(model.snapshot, "mysql_flexible_server")
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
        props = row.get("properties") or {}
        state = _low(props.get("state"))
        if state in ("dropping", "disabled"):
            continue
        if state == "stopped":
            start, uncertain = _held(model, source, START, server_id)
            if not start:
                if uncertain:
                    out[tid] = ("unknown", "mysql_server_start_permission_unverified")
                continue
        elif state != "ready":
            out[tid] = ("unknown", "mysql_server_state_unverified")
            continue
        write, uncertain = _held(model, source, WRITE, server_id)
        if not write:
            if uncertain:
                out[tid] = ("unknown", "mysql_server_write_unverified")
            continue
        config_id = server_id + "/configurations/aad_auth_only"
        configs = [c for c in row.get("configurations") or []
                   if _low(c.get("id")) == config_id and _low(c.get("name")) == "aad_auth_only"]
        configuration = (configs[0].get("properties") or {}) if len(configs) == 1 else {}
        mode = _low(configuration.get("value"))
        if mode == "on":
            if configuration.get("isReadOnly") is True:
                continue
            if configuration.get("isReadOnly") is not False:
                out[tid] = ("unknown", "mysql_auth_setting_writability_unverified")
                continue
            config_write, uncertain = _held(model, source, CONFIG_WRITE, config_id)
            if not config_write:
                if uncertain:
                    out[tid] = ("unknown", "mysql_auth_change_permission_unverified")
                continue
            if configuration.get("isDynamicConfig") is False:
                restart, uncertain = _held(model, source, RESTART, server_id)
                if not restart:
                    if uncertain:
                        out[tid] = ("unknown", "mysql_auth_restart_permission_unverified")
                    continue
            elif configuration.get("isDynamicConfig") is not True:
                out[tid] = ("unknown", "mysql_auth_restart_need_unverified")
                continue
        elif mode != "off":
            out[tid] = ("unknown", "mysql_password_auth_mode_unverified")
            continue
        out[tid] = ("conditional", "mysql_password_reset_network_conditional")
    return out
