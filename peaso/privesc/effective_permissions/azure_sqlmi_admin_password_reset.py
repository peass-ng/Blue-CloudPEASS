"""Bind Managed Instance password reset to an exact usable native instance."""
from __future__ import annotations

import re

from . import inventory_status, items


INSTANCE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.sql/managedinstances/[^/]+")
WRITE = {"action": "Microsoft.Sql/managedInstances/write"}
AUTH_WRITE = {"action": "Microsoft.Sql/managedInstances/azureADOnlyAuthentications/write"}
START = {"action": "Microsoft.Sql/managedInstances/start/action"}


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
    rows = {rid: row for _, row in items(model.snapshot, "mssql_managed_instance")
            if (rid := _low(row.get("id"))) and INSTANCE.fullmatch(rid)
            and _low(row.get("type")) == "microsoft.sql/managedinstances"}
    status = inventory_status(model.snapshot, "mssql_managed_instance")
    out = {}
    for tid, target in candidates.items():
        instance_id = _low(target.scope)
        if not INSTANCE.fullmatch(instance_id):
            continue
        row = rows.get(instance_id)
        if row is None:
            if status.get(_subscription(instance_id)) not in ("collected", "empty"):
                out[tid] = ("unknown", "sqlmi_inventory_incomplete")
            continue
        props = row.get("properties") or {}
        state = _low(props.get("state"))
        provisioning = _low(props.get("provisioningState"))
        if state in ("disabled", "dropping"):
            continue
        if provisioning != "succeeded":
            out[tid] = ("unknown", "sqlmi_provisioning_state_unverified")
            continue
        if state == "stopped":
            start = _grant(model, source, START, instance_id)
            if start is not True:
                if start == "unknown":
                    out[tid] = ("unknown", "sqlmi_start_permission_unverified")
                continue
        elif state != "ready":
            out[tid] = ("unknown", "sqlmi_state_unverified")
            continue
        if not isinstance(props.get("administratorLogin"), str) or not props["administratorLogin"]:
            out[tid] = ("unknown", "sqlmi_administrator_login_unverified")
            continue
        write = _grant(model, source, WRITE, instance_id)
        if write is not True:
            if write == "unknown":
                out[tid] = ("unknown", "sqlmi_write_unverified")
            continue
        children = [child for child in row.get("azureADOnlyAuthentications") or []
                    if _low(child.get("id")) == instance_id + "/azureadonlyauthentications/default"]
        mode = ((children[0].get("properties") or {}).get("azureADOnlyAuthentication")
                if len(children) == 1 else None)
        expanded = (props.get("administrators") or {}).get("azureADOnlyAuthentication")
        if type(mode) is bool and type(expanded) is bool and mode != expanded:
            out[tid] = ("unknown", "sqlmi_authentication_mode_conflict")
            continue
        if type(mode) is not bool and type(expanded) is bool:
            mode = expanded
        if type(mode) is not bool:
            out[tid] = ("unknown", "sqlmi_authentication_mode_unverified")
            continue
        if mode:
            auth_id = instance_id + "/azureadonlyauthentications/default"
            auth_write = _grant(model, source, AUTH_WRITE, auth_id)
            if auth_write is not True:
                if auth_write == "unknown":
                    out[tid] = ("unknown", "sqlmi_authentication_change_permission_unverified")
                continue
        out[tid] = ("conditional", "sqlmi_administrator_password_reset_network_conditional")
    return out
