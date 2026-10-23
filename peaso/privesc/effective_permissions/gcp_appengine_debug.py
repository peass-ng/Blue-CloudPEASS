"""Exact flexible App Engine VM and runtime identity for the SSH escalation path."""
from __future__ import annotations

import re

from . import inventory_status, items


_INSTANCE = re.compile(r"apps/([^/]+)/services/[^/]+/versions/[^/]+/instances/[^/]+\Z")
_VERSION = re.compile(r"apps/([^/]+)/services/[^/]+/versions/[^/]+\Z")


def _setting(metadata, name):
    entries = metadata.get("items") if isinstance(metadata, dict) else None
    if not isinstance(entries, list):
        return None
    values = [str(item.get("value", "")).lower() for item in entries
              if isinstance(item, dict) and item.get("key") == name]
    if len(values) != 1:
        return None
    if values[0] in ("true", "1"):
        return True
    if values[0] in ("false", "0"):
        return False
    return None


def load(model):
    """Only join an instance to a version and a known runtime service account."""
    snap = model.snapshot
    status = {model._norm_scope(scope): value for scope, value in inventory_status(snap, "app_engine_instance").items()}
    for scope, value in status.items():
        model.host_status[(scope, "app_engine_instance")] = value
    versions = {}
    for scope, item in items(snap, "app_engine_version"):
        project = model._norm_scope(scope)
        name = item.get("name")
        match = _VERSION.fullmatch(name) if isinstance(name, str) else None
        if not match or project != f"projects/{match[1]}":
            model.host_status[(project, "app_engine_instance")] = "partial"
            continue
        versions[name] = item
    vstatus = {model._norm_scope(scope): value for scope, value in inventory_status(snap, "app_engine_version").items()}
    for project, value in vstatus.items():
        if value not in ("collected", "empty"):
            model.host_status[(project, "app_engine_instance")] = value
    compute = {}
    for scope, item in items(snap, "instance"):
        from .gcp import _instance_resource
        resource = _instance_resource(item, scope)
        if resource:
            compute[resource] = item
    project_metadata = {model._norm_scope(scope): item.get("commonInstanceMetadata")
                        for scope, item in items(snap, "project")}
    app_identity = {model._norm_scope(scope): item.get("serviceAccount")
                    for scope, item in items(snap, "app_engine_application_identity")
                    if item.get("name") == "apps/" + model._norm_scope(scope).split("/", 1)[-1]}
    result = {}
    for scope, item in items(snap, "app_engine_instance"):
        project = model._norm_scope(scope)
        name = item.get("name")
        match = _INSTANCE.fullmatch(name) if isinstance(name, str) else None
        if not match or project != f"projects/{match[1]}":
            model.host_status[(project, "app_engine_instance")] = "partial"
            continue
        version = versions.get(name.rsplit("/instances/", 1)[0])
        if not version or version.get("env") != "flex" or version.get("servingStatus") != "SERVING":
            model.host_status[(project, "app_engine_instance")] = "partial"
            continue
        email = version.get("serviceAccount") or app_identity.get(project)
        if not isinstance(email, str) or not re.fullmatch(r"[^@\s]+@[^@\s]+", email):
            model.host_status[(project, "app_engine_instance")] = "partial"
            continue
        vm_name, zone = item.get("vmName"), item.get("vmZoneName")
        vm_resource = (f"{project}/zones/{zone}/instances/{vm_name}"
                       if isinstance(vm_name, str) and vm_name and isinstance(zone, str) and zone else None)
        vm = compute.get(vm_resource) if vm_resource else None
        model.parents.setdefault(name, project)
        model.hosts.setdefault(email, {}).setdefault("app_engine_instance", []).append(name)
        model.host_projects.setdefault((email, "app_engine_instance"), set()).add(project)
        result.setdefault(email, []).append((project, name, vm_resource, item, version, vm,
                                              project_metadata.get(project)))
    return result


def selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    out = {}
    for tid, target in candidates.items():
        email = target.attrs.get("email")
        unresolved = False
        for project, app_instance, vm_resource, app, version, vm, metadata in model.appengine_debug_instances.get(email, ()):
            if project != target.scope:
                continue
            if app.get("vmStatus") not in (None, "RUNNING"):
                continue
            if app.get("vmStatus") is None or not vm_resource:
                unresolved = True
                continue
            debug = model.check(source, {"action": "appengine.instances.enableDebug"}, app_instance)
            login = [model.check(source, {"action": permission}, vm_resource) for permission in
                     ("compute.instances.osLogin", "compute.instances.osAdminLogin")]
            actas = model.check(source, {"action": "iam.serviceAccounts.actAs"},
                                target.attrs.get("resource") or f"{project}/serviceAccounts/{email}")
            if not debug and not (any(login) and actas):
                continue
            if version.get("runtime", "").lower().startswith("aspnet") or version.get("runtime", "").lower() == "dotnet":
                unresolved = True
                continue
            # Project metadata can be overridden on the backing VM. The enforced
            # organization policy takes precedence over either metadata setting.
            org_login = model._effective_boolean_policy(project, "compute.requireOsLogin")
            vm_login = _setting(vm.get("metadata"), "enable-oslogin") if vm else None
            project_login = _setting(metadata, "enable-oslogin")
            if org_login is True:
                os_login = True
            elif vm_login is not None:
                os_login = vm_login if org_login is False else None
            elif project_login is not None:
                os_login = project_login if org_login is False else None
            else:
                os_login = False if org_login is False and project in {
                    model._norm_scope(s) for s, st in inventory_status(model.snapshot, "project").items()
                    if st in ("collected", "empty")} and vm is not None else None
            debug_ready = app.get("vmDebugEnabled") is True or debug is not None
            usable = ((debug is not None and os_login is False) or
                      (debug_ready and os_login is True and any(login) and actas))
            if not usable:
                if os_login is None or (app.get("vmDebugEnabled") is None and not debug):
                    unresolved = True
                continue
            if vm is None:
                unresolved = True
                continue
            public_ip = any(access.get("natIP") for iface in vm.get("networkInterfaces", ())
                            if isinstance(iface, dict) for access in iface.get("accessConfigs", ())
                            if isinstance(access, dict))
            iap = model.check(source, {"action": "iap.tunnelInstances.accessViaIAP"}, vm_resource)
            if not public_ip and not iap:
                # A private route through VPN, peering, or an existing foothold
                # cannot be ruled out from this cloud inventory.
                unresolved = True
                continue
            grants = ([debug] if debug is not None and os_login is False else [g for g in (*login, actas) if g])
            if any(grant.confidence == "unknown" for grant in grants) or (iap and iap.confidence == "unknown" and not public_ip):
                unresolved = True
                continue
            # The inventory cannot establish the caller's source IP, firewall
            # passage, or SSH key acceptance. Never emit a derived edge here.
            out[tid] = ("conditional", "exact_flexible_vm_ssh_route_and_login_require_confirmation")
            break
        if tid not in out and unresolved:
            out[tid] = ("unknown", "appengine_vm_login_or_route_unresolved")
    return out
