"""Join writable gallery application versions with one VM identity host."""
from __future__ import annotations

import re

from . import items
from .azure_vm_assign_existing import VM, _allowed, _low, _power


APP = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.compute/galleries/[^/]+/applications/[^/]+")
GALLERY = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.compute/galleries/[^/]+")
GROUP = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+")
VERSION_WRITE = "microsoft.compute/galleries/applications/versions/write"
APP_WRITE = "microsoft.compute/galleries/applications/write"
GALLERY_WRITE = "microsoft.compute/galleries/write"
VM_WRITE = "microsoft.compute/virtualmachines/write"


def _version_writable(model, source, app, assigned_scopes, resources):
    prefix = app + "/versions/"
    versions = {prefix + "99.0.0"}
    versions.update(scope for scope in assigned_scopes
                    if re.fullmatch(re.escape(prefix) + r"[^/]+", scope))
    versions.update(rid for rid in resources
                    if re.fullmatch(re.escape(prefix) + r"[^/]+", rid))
    return any(_allowed(model, source, VERSION_WRITE, version) for version in versions)


def select(model, candidates, source):
    if source is None:
        return {}
    graph = {_low(row.get("id")): row for _, row in items(model.snapshot, "resource_graph")
             if row.get("id") and row.get("type")}
    vms = {rid: row for rid, row in graph.items()
           if VM.fullmatch(rid) and _low(row.get("type")) == "microsoft.compute/virtualmachines"}
    vms.update({_low(row.get("id")): row for _, row in items(model.snapshot, "vm")
                if VM.fullmatch(_low(row.get("id")))
                and _low(row.get("type")) == "microsoft.compute/virtualmachines"})
    apps = {rid: row for rid, row in graph.items()
            if APP.fullmatch(rid) and _low(row.get("type")) == "microsoft.compute/galleries/applications"}
    galleries = {rid for rid, row in graph.items()
                 if GALLERY.fullmatch(rid) and _low(row.get("type")) == "microsoft.compute/galleries"}
    groups = {_low(row.get("id")) for _, row in items(model.snapshot, "resource_group")
              if GROUP.fullmatch(_low(row.get("id")))}
    groups.update(match.group(0) for rid in graph if (match := GROUP.match(rid)))
    assigned_scopes = {assignment["scope"] for assignments in model.assignments.values()
                       for assignment in assignments}
    writable_apps = {app: row for app, row in apps.items()
                     if _version_writable(model, source, app, assigned_scopes, graph)}
    for gallery in galleries:
        app = gallery + "/applications/peaso-probe"
        if (_allowed(model, source, APP_WRITE, app)
                and _version_writable(model, source, app, assigned_scopes, graph)):
            writable_apps[app] = None
    for group in groups:
        gallery = group + "/providers/microsoft.compute/galleries/peaso-probe"
        app = gallery + "/applications/peaso-probe"
        if (_allowed(model, source, GALLERY_WRITE, gallery)
                and _allowed(model, source, APP_WRITE, app)
                and _version_writable(model, source, app, assigned_scopes, graph)):
            writable_apps[app] = None
    if not writable_apps:
        return {}
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity":
            continue
        for vm in target.attrs.get("hosts") or ():
            row = vms.get(vm)
            if row is None or not _allowed(model, source, VM_WRITE, vm):
                continue
            if _power(row) == "stopped" and not _allowed(
                    model, source, "microsoft.compute/virtualmachines/start/action", vm):
                continue
            props = row.get("properties") or {}
            vm_os = _low(((props.get("storageProfile") or {}).get("osDisk") or {}).get("osType"))
            for app_row in writable_apps.values():
                if app_row is not None:
                    app_os = _low((app_row.get("properties") or {}).get("supportedOSType"))
                    if vm_os and app_os and vm_os != app_os:
                        continue
                out[tid] = ("conditional", "vm_gallery_app_guest_execution_prerequisites")
                break
            if tid in out:
                break
    return out
