"""Join project metadata control to an exact VM that can inherit and run it."""

from __future__ import annotations

from collections import Counter

from . import inventory_status, items
from .gcp_metadata_vm import _oslogin_enforced, _scope_grant
from .gcp_oslogin import _UNRESOLVED, _firewall_permits_ssh, _flag, _vm_resource


def _keys(metadata):
    if metadata is None:
        return set()
    if not isinstance(metadata, dict):
        return None
    rows = metadata.get("items", [])
    if isinstance(rows, dict):
        return set(rows) if all(isinstance(key, str) for key in rows) else None
    if not isinstance(rows, list) or any(not isinstance(row, dict) or
                                         not isinstance(row.get("key"), str) for row in rows):
        return None
    return {row["key"] for row in rows}


def _startup(model, source, project, vm, resource, zone, settings):
    rows = settings.get((project, zone), [])
    if len(rows) != 1:
        return False
    vm_keys = _keys(vm.get("metadata"))
    zone_keys = _keys(rows[0].get("metadata"))
    if vm_keys is None or zone_keys is None:
        return False
    # An instance-level startup script takes precedence over a project script.
    # Zonal startup-script also masks that same project key.
    script_keys = {"startup-script", "startup-script-url", "windows-startup-script-cmd",
                   "windows-startup-script-ps1", "windows-startup-script-bat",
                   "windows-startup-script-url"}
    if vm_keys.intersection(script_keys):
        return False
    if zone_keys.intersection(script_keys):
        return False
    state = vm.get("status")
    if state == "RUNNING":
        if _scope_grant(model, source, "compute.instances.reset", resource) == "derived":
            return True
        return all(_scope_grant(model, source, action, resource) == "derived" for action in
                   ("compute.instances.stop", "compute.instances.start"))
    if state in ("TERMINATED", "STOPPED"):
        return _scope_grant(model, source, "compute.instances.start", resource) == "derived"
    return False


def _ssh(model, project, vm):
    if vm.get("status") != "RUNNING":
        return False
    blocked = _flag(vm.get("metadata"), "block-project-ssh-keys")
    oslogin = _flag(vm.get("metadata"), "enable-oslogin")
    if blocked is not False and blocked is not None:
        return False
    if oslogin is True or oslogin is _UNRESOLVED:
        return False
    # The writer can disable project OS Login, unless an organization policy
    # enforces it or the instance explicitly enables it.
    if _oslogin_enforced(model, project) is not False:
        return False
    return _firewall_permits_ssh(model, project, vm)


def selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    rows = []
    for scope, vm in items(model.snapshot, "instance"):
        project = model._norm_scope(scope)
        resource = _vm_resource(model, vm, project)
        zone = str(vm.get("zone") or "").rsplit("/", 1)[-1]
        if resource and resource.split("/zones/", 1)[1].split("/", 1)[0] == zone:
            rows.append((project, resource, zone, vm))
    counts = Counter(resource for _, resource, _, _ in rows)
    settings = {}
    for scope, row in items(model.snapshot, "instance_settings"):
        settings.setdefault((model._norm_scope(scope), row.get("_zone")), []).append(row)
    result = {}
    for tid, target in candidates.items():
        if target.attrs.get("disabled") is True:
            continue
        for project, resource, zone, vm in rows:
            accounts = [account for account in vm.get("serviceAccounts") or []
                        if isinstance(account, dict) and account.get("email") == target.attrs.get("email")]
            if not accounts:
                continue
            model.parents.setdefault(resource, project)
            write = _scope_grant(model, source, "compute.projects.setCommonInstanceMetadata", project)
            if write is None:
                continue
            if counts[resource] != 1:
                verdict = ("unknown", "project_metadata_vm_identity_conflict")
            elif project != target.scope:
                verdict = ("unknown", "project_metadata_cross_project_sa_usage_unresolved")
            elif inventory_status(model.snapshot, "instance").get(project) != "collected":
                verdict = ("unknown", "project_metadata_vm_inventory_unresolved")
            elif write != "derived" or _scope_grant(model, source, "compute.projects.get", project) != "derived":
                verdict = ("unknown", "project_metadata_write_or_fingerprint_unresolved")
            elif _scope_grant(model, source, "iam.serviceAccounts.actAs", project) != "derived":
                verdict = ("unknown", "project_metadata_project_actas_unresolved")
            elif any("https://www.googleapis.com/auth/cloud-platform" not in (account.get("scopes") or [])
                     for account in accounts):
                verdict = ("unknown", "project_metadata_sa_access_scopes_unresolved")
            elif _ssh(model, project, vm) or _startup(model, source, project, vm, resource, zone, settings):
                verdict = None
            else:
                verdict = ("unknown", "project_metadata_execution_or_ssh_route_unresolved")
            if verdict is None or tid not in result:
                result[tid] = verdict
    return result
