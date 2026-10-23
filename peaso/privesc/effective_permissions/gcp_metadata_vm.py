"""Bind instance metadata control to a concrete execution or SSH path."""

from __future__ import annotations

from collections import Counter

from . import inventory_status, items
from .gcp_oslogin import _firewall_permits_ssh, _vm_resource


def _scope_grant(model, source, action, resource):
    grant = model.check(source, {"action": action}, resource)
    return grant.confidence if grant is not None else None


def _oslogin_enforced(model, project):
    if inventory_status(model.snapshot, "org_policy_effective").get(project) not in ("collected", "empty"):
        return None
    rows = [item for scope, item in items(model.snapshot, "org_policy_effective")
            if model._norm_scope(scope) == project and
            str(item.get("constraint", "")).removeprefix("constraints/") == "compute.requireOsLogin"]
    if not rows:
        return False
    if len(rows) != 1 or not isinstance(rows[0].get("spec"), dict):
        return None
    spec = rows[0]["spec"]
    rules = spec.get("rules")
    if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
        return None
    return rules[0].get("enforce") if isinstance(rules[0].get("enforce"), bool) else None


def _route(model, source, project, vm, resource):
    state = vm.get("status")
    if state == "RUNNING":
        reset = _scope_grant(model, source, "compute.instances.reset", resource)
        if reset == "derived":
            return "startup"
        stop = _scope_grant(model, source, "compute.instances.stop", resource)
        start = _scope_grant(model, source, "compute.instances.start", resource)
        if stop == start == "derived":
            return "startup"
        enforced = _oslogin_enforced(model, project)
        if enforced is False and _firewall_permits_ssh(model, project, vm):
            return "ssh"
        if reset is not None or stop is not None or start is not None or enforced is None:
            return "unknown"
        return "unknown"
    if state in ("TERMINATED", "STOPPED"):
        if _scope_grant(model, source, "compute.instances.start", resource) == "derived":
            return "startup"
    return "unknown"


def selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    rows = []
    for scope, vm in items(model.snapshot, "instance"):
        project = model._norm_scope(scope)
        resource = _vm_resource(model, vm, project)
        if resource:
            rows.append((project, resource, vm))
    counts = Counter(resource for _, resource, _ in rows)
    by_email = {}
    for project, resource, vm in rows:
        for account in vm.get("serviceAccounts") or []:
            if isinstance(account, dict) and isinstance(account.get("email"), str):
                by_email.setdefault(account["email"], []).append((project, resource, vm, account))
    out = {}
    for tid, target in candidates.items():
        for project, resource, vm, account in by_email.get(target.attrs.get("email"), []):
            model.parents.setdefault(resource, project)
            write = _scope_grant(model, source, "compute.instances.setMetadata", resource)
            if write is None:
                continue
            if counts[resource] != 1:
                verdict = ("unknown", "metadata_vm_identity_conflict")
            elif project != target.scope:
                verdict = ("unknown", "metadata_cross_project_sa_usage_unresolved")
            elif inventory_status(model.snapshot, "instance").get(project) != "collected":
                verdict = ("unknown", "metadata_vm_inventory_unresolved")
            elif write != "derived":
                verdict = ("unknown", "metadata_write_condition_unresolved")
            elif _scope_grant(model, source, "compute.instances.get", resource) != "derived":
                verdict = ("unknown", "metadata_fingerprint_unresolved")
            elif "https://www.googleapis.com/auth/cloud-platform" not in (account.get("scopes") or []):
                verdict = ("unknown", "metadata_sa_access_scopes_unresolved")
            else:
                route = _route(model, source, project, vm, resource)
                verdict = (None if route in ("startup", "ssh") else
                           ("unknown", "metadata_execution_or_ssh_route_unresolved"))
            if verdict is None or tid not in out:
                out[tid] = verdict
    return out
