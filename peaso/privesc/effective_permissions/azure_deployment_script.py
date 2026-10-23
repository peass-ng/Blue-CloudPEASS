"""Bind deployment-script execution to a writable script and assignable UAMI."""
from __future__ import annotations

import re

from . import items


_RG = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+")
_SCRIPT = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.resources/deploymentscripts/[^/]+")
_UAMI = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.managedidentity/userassignedidentities/[^/]+")
_WRITE = {"action": "microsoft.resources/deploymentscripts/write"}
_ASSIGN = {"action": "microsoft.managedidentity/userassignedidentities/assign/action"}
_SUPPORT = (
    ("microsoft.containerinstance/containergroups/read", "aci"),
    ("microsoft.containerinstance/containergroups/write", "aci"),
    ("microsoft.storage/storageaccounts/read", "storage"),
    ("microsoft.storage/storageaccounts/write", "storage"),
    ("microsoft.storage/storageaccounts/listkeys/action", "storage"),
)
_DELETE = {"action": "microsoft.containerinstance/containergroups/delete"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _held(model, source, action, resource):
    grant = model.cached_check(source, {"action": action} if isinstance(action, str) else action, resource)
    return grant is not None and grant.confidence != "unknown"


def _rg(value):
    match = _RG.match(value)
    return match.group() if match else ""


def _script_refs(model, source, scripts):
    refs = {}
    for scope in model.scopes:
        if _RG.fullmatch(scope):
            ref = scope + "/providers/microsoft.resources/deploymentscripts/peaso-privesc-probe"
            if _held(model, source, _WRITE, ref):
                refs[ref] = None
    for rid, row in scripts.items():
        if _SCRIPT.fullmatch(rid) and _held(model, source, _WRITE, rid):
            refs[rid] = row
    return refs


def _support_refs(rg, script):
    props = (script or {}).get("properties") or {}
    aci = _low(props.get("containerInstanceId"))
    storage = _low(props.get("storageAccountId"))
    aci = aci if aci.startswith(rg + "/providers/microsoft.containerinstance/containergroups/") else (
        rg + "/providers/microsoft.containerinstance/containergroups/peaso-privesc-probe")
    storage = storage if storage.startswith(rg + "/providers/microsoft.storage/storageaccounts/") else (
        rg + "/providers/microsoft.storage/storageaccounts/peaso-privesc-probe")
    return aci, storage


def select(model, candidates, source):
    if source is None:
        return {}
    scripts = {_low(row.get("id")): row for _, row in items(model.snapshot, "resource_graph")
               if isinstance(row, dict) and _low(row.get("type")) == "microsoft.resources/deploymentscripts"
               and isinstance(row.get("id"), str)}
    refs = _script_refs(model, source, scripts)
    uncollected_script = any(
        _SCRIPT.fullmatch(assignment.get("scope") or "")
        and (assignment.get("scope") or "") not in scripts
        and _held(model, source, _WRITE, assignment["scope"])
        for pid in (source.id, *source.attrs.get("groups", ()))
        for assignment in model.assignments.get(pid, ()))
    out = {}
    for tid, target in candidates.items():
        identity = _low(target.attrs.get("uai_resource"))
        if not target.attrs.get("uai_resource_verified") or not _UAMI.fullmatch(identity):
            continue
        if not _held(model, source, _ASSIGN, identity):
            continue
        unknown = "writable_deployment_script_not_collected" if uncollected_script and not refs else None
        for script_id, script in refs.items():
            rg = _rg(script_id)
            aci, storage = _support_refs(rg, script)
            if not all(_held(model, source, action, aci if kind == "aci" else storage)
                       for action, kind in _SUPPORT):
                if script and (script.get("properties") or {}).get("storageAccountSettings"):
                    unknown = "deployment_script_custom_storage_path_not_verified"
                continue
            if script:
                props = script.get("properties") or {}
                retained = _low(props.get("containerInstanceId"))
                if retained and retained in model.resources and not _held(model, source, _DELETE, retained):
                    continue
                if retained and retained not in model.resources and _low(props.get("cleanupPreference")) == "onexpiration":
                    unknown = "deployment_script_support_container_not_verified"
                    continue
            out[tid] = ("conditional", "deployment_script_user_assigned_identity_execution")
            break
        if tid not in out and unknown:
            out[tid] = ("unknown", unknown)
    return out
