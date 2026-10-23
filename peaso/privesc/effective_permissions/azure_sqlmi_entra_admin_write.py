"""Bind Managed Instance Entra admin write to a controlled principal and usable MI."""
from __future__ import annotations

import re

from . import inventory_status, items
from .azure_mysql_flexible_entra_admin_write import _directory_read
from .azure_postgresql_flexible_entra_admin_write import _controlled_subjects


INSTANCE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.sql/managedinstances/[^/]+")
UAMI = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.managedidentity/userassignedidentities/[^/]+")
ADMIN_WRITE = {"action": "Microsoft.Sql/managedInstances/administrators/write"}
START = {"action": "Microsoft.Sql/managedInstances/start/action"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _subscription(resource):
    match = re.match(r"/subscriptions/[^/]+", resource)
    return match.group(0) if match else ""


def _grant(model, source, action, scope):
    grant = model.cached_check(source, action, scope)
    return "unknown" if grant is not None and grant.confidence == "unknown" else bool(grant)


def _instance_identity(model, row):
    identity = row.get("identity") or {}
    props = row.get("properties") or {}
    if not isinstance(identity, dict) or not isinstance(props, dict):
        return "unknown"
    primary = _low(props.get("primaryUserAssignedIdentityId"))
    if primary:
        if not UAMI.fullmatch(primary):
            return "unknown"
        assignments = identity.get("userAssignedIdentities") or {}
        if not isinstance(assignments, dict):
            return "unknown"
        attached = {_low(uid): detail for uid, detail in assignments.items() if isinstance(uid, str)}
        detail = attached.get(primary) or {}
        if not isinstance(detail, dict):
            return "unknown"
        pid = detail.get("principalId")
        native = next((item for _, item in items(model.snapshot, "managed_identity")
                       if _low(item.get("id")) == primary
                       and _low(item.get("type")) == "microsoft.managedidentity/userassignedidentities"), None)
        native_pid = (native.get("properties") or {}).get("principalId") if native else None
        if native_pid and (not pid or _low(pid) == _low(native_pid)):
            return native_pid
        return "unknown"
    pid = identity.get("principalId")
    if isinstance(pid, str) and pid:
        return pid
    service_principal = props.get("servicePrincipal") or {}
    if (isinstance(service_principal, dict)
            and _low(service_principal.get("type")) == "systemassigned"
            and isinstance(service_principal.get("principalId"), str)
            and service_principal["principalId"]):
        return service_principal["principalId"]
    return "unknown"


def select(model, candidates, source):
    if source is None:
        return {}
    subjects = {_low(subject) for subject in _controlled_subjects(model, source)}
    if not subjects:
        return {}
    rows = {rid: row for _, row in items(model.snapshot, "mssql_managed_instance")
            if (rid := _low(row.get("id"))) and INSTANCE.fullmatch(rid)
            and _low(row.get("type")) == "microsoft.sql/managedinstances"}
    status = inventory_status(model.snapshot, "mssql_managed_instance")
    directory_objects = {_low(oid): obj for oid, obj in model.dir_objects.items()}
    membership_status = {_low(oid): state for oid, state in model.membership_status.items()}
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
        if state in ("disabled", "dropping"):
            continue
        if _low(props.get("provisioningState")) != "succeeded":
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
        coverage = ((row.get("_coverage") or {}).get("instanceAdministrators") or {}).get("status")
        if coverage not in ("collected", "empty"):
            out[tid] = ("unknown", "sqlmi_administrator_inventory_incomplete")
            continue
        admins = row.get("instanceAdministrators") or []
        if len(admins) > 1:
            out[tid] = ("unknown", "sqlmi_administrator_inventory_malformed")
            continue
        if admins:
            admin = admins[0]
            if (_low(admin.get("id")) != instance_id + "/administrators/activedirectory"
                    or _low(admin.get("type")) != "microsoft.sql/managedinstances/administrators"):
                out[tid] = ("unknown", "sqlmi_administrator_inventory_malformed")
                continue
            sid = _low((admin.get("properties") or {}).get("sid"))
            if not sid:
                out[tid] = ("unknown", "sqlmi_administrator_identity_unverified")
                continue
            if sid in subjects:
                continue
            directory_obj = directory_objects.get(sid) or {}
            if directory_obj.get("securityEnabled") is not None and membership_status.get(sid) not in ("collected", "empty"):
                out[tid] = ("unknown", "sqlmi_existing_admin_group_membership_incomplete")
                continue
        child_id = instance_id + "/administrators/activedirectory"
        write = _grant(model, source, ADMIN_WRITE, child_id)
        if write is not True:
            if write == "unknown":
                out[tid] = ("unknown", "sqlmi_administrator_write_unverified")
            continue
        identity_pid = _instance_identity(model, row)
        if identity_pid == "unknown":
            out[tid] = ("unknown", "sqlmi_directory_identity_unverified")
            continue
        directory_read = _directory_read(model, identity_pid)
        if directory_read is not True:
            if directory_read == "unknown":
                out[tid] = ("unknown", "sqlmi_directory_read_unverified")
            continue
        out[tid] = ("conditional", "sqlmi_entra_admin_network_conditional")
    return out
