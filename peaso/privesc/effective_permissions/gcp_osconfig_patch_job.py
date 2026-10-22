"""Join patch job or deployment writes to a supported active VM."""

from __future__ import annotations

import re
from collections import Counter

from . import ANY, inventory_status, items
from .gcp_osconfig_guest_policy import _agent_inventory, _vm_verdict
from .gcp_osconfig_os_policy_assignment import _attached_vms


def deployment_resources(model, project):
    status = inventory_status(model.snapshot, "os_patch_deployment").get(project)
    if status not in ("collected", "empty"):
        return None
    names = []
    for scope, row in items(model.snapshot, "os_patch_deployment"):
        if model._norm_scope(scope) != project:
            continue
        name = model._norm_scope(row.get("name"))
        if not re.fullmatch(re.escape(project) + r"/patchDeployments/[A-Za-z0-9_-]+", name):
            return None
        names.append(name)
    if status == "empty" and names or len(names) != len(set(names)):
        return None
    return sorted(names)


def _patch_os(model, project, vm, resource):
    report = _agent_inventory(model, project, vm, resource)
    if report is None:
        return ("unknown", "osconfig_patch_os_inventory_unresolved")
    info = report.get("osInfo") or {}
    name = str(info.get("shortName") or "").lower()
    version = str(info.get("version") or "")
    major = re.match(r"^(\d+)", version)
    supported = {"debian": 9, "ubuntu": 18, "rhel": 7, "redhat": 7,
                 "centos": 7, "rocky": 8, "sles": 12, "opensuse": 15,
                 "windows": 0}
    if name in {"cos", "container-optimized-os", "fedora-coreos"}:
        return ("unknown", "osconfig_patch_os_support_unresolved")
    if name == "windows":
        year = re.search(r"\b(20(?:12|16|19|22|25))\b", str(info.get("longName") or ""))
        return None if year else ("unknown", "osconfig_patch_windows_version_unresolved")
    if name not in supported or major is None or int(major[1]) < supported[name]:
        return ("unknown", "osconfig_patch_os_support_unresolved")
    return None


def selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    out = {}
    for tid, target in candidates.items():
        project = target.scope
        vms = list(_attached_vms(model, target))
        counts = Counter(resource for _, resource, _ in vms if resource)
        direct = model.check(source, {"action": "osconfig.patchJobs.exec"}, project)
        create = model.check(source, {"action": "osconfig.patchDeployments.create"}, project)
        names = deployment_resources(model, project)
        by_name = {model._norm_scope(row.get("name")): row for scope, row in
                   items(model.snapshot, "os_patch_deployment") if model._norm_scope(scope) == project}
        updates = []
        if names is not None:
            updates = [(name, grant) for name in names
                       if (grant := model.check(source,
                           {"action": "osconfig.patchDeployments.update"}, name)) is not None]
        possible_update = model.check(source, {"action": "osconfig.patchDeployments.update"}, ANY)
        if direct is None and create is None and not updates and possible_update is None:
            continue
        unresolved = None
        for vm, resource, _ in vms:
            if resource is None or counts[resource] != 1:
                unresolved = ("unknown", "osconfig_patch_vm_identity_ambiguous")
                continue
            state = _vm_verdict(model, project, vm, resource, source, feature="tasks")
            if state == "disabled":
                continue
            os_state = _patch_os(model, project, vm, resource)
            if os_state == "disabled":
                continue
            if state is None and os_state is None:
                if any(grant is not None and grant.confidence == "derived" for grant in (direct, create)):
                    out[tid] = None
                    break
                if any(grant.confidence == "derived" and
                       by_name[name].get("state") == "ACTIVE" and
                       isinstance(by_name[name].get("recurringSchedule"), dict)
                       for name, grant in updates):
                    out[tid] = None
                    break
            unresolved = (state if isinstance(state, tuple) else os_state
                          if isinstance(os_state, tuple) else
                          ("unknown", "osconfig_patch_deployment_or_permission_unresolved"))
        else:
            if unresolved is not None:
                out[tid] = unresolved
    return out
