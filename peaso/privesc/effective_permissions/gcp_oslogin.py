"""Join an OS Login permission to an exact running VM and its attached SA."""

from __future__ import annotations

import re

from . import inventory_status, items

_UNRESOLVED = object()


def _flag(metadata, key):
    if metadata is not None and not isinstance(metadata, dict):
        return _UNRESOLVED
    rows = metadata.get("items") if isinstance(metadata, dict) else None
    if rows is None:
        return None
    if not isinstance(rows, list):
        return _UNRESOLVED
    values = [str(row.get("value", "")).lower() for row in rows
              if isinstance(row, dict) and row.get("key") == key]
    if not values:
        return None
    return values[0] == "true" if len(values) == 1 and values[0] in ("true", "false") else _UNRESOLVED


def _allows_ssh(allow):
    if not isinstance(allow, dict) or allow.get("IPProtocol") not in ("all", "tcp"):
        return False
    if allow["IPProtocol"] == "all" or not allow.get("ports"):
        return True
    for port in allow["ports"]:
        if not isinstance(port, str):
            continue
        if port == "22":
            return True
        match = re.fullmatch(r"(\d+)-(\d+)", port)
        if match and int(match[1]) <= 22 <= int(match[2]):
            return True
    return False


def _vm_resource(model, vm, project):
    link = vm.get("selfLink")
    match = re.fullmatch(
        r"https://(?:www|compute)\.googleapis\.com/compute/v1/(projects/[^/]+/zones/[^/]+/instances/[^/]+)",
        link) if isinstance(link, str) else None
    resource = model._norm_scope(match.group(1)) if match else None
    return resource if resource and resource.startswith(project + "/") else None


def _project_metadata(model, project):
    rows = [item for scope, item in items(model.snapshot, "project") if model._norm_scope(scope) == project]
    return rows[0].get("commonInstanceMetadata") if len(rows) == 1 else None


def _firewall_permits_ssh(model, project, vm):
    interfaces = vm.get("networkInterfaces")
    if not isinstance(interfaces, list):
        return False
    networks = set()
    for nic in interfaces:
        if not isinstance(nic, dict) or not any(
                isinstance(config, dict) and config.get("natIP") for config in nic.get("accessConfigs") or []):
            continue
        network = nic.get("network")
        if isinstance(network, str):
            networks.add(network.rsplit("/compute/v1/", 1)[-1])
    if not networks:
        return False
    if inventory_status(model.snapshot, "firewall").get(project) != "collected":
        return False
    if inventory_status(model.snapshot, "effective_firewall").get(project) != "collected":
        return False
    if any((row.get("firewallPolicys") or []) for scope, row in items(model.snapshot, "effective_firewall")
           if model._norm_scope(scope) == project):
        return False
    tags = set((vm.get("tags") or {}).get("items") or [])
    service_accounts = {row.get("email") for row in vm.get("serviceAccounts") or [] if isinstance(row, dict)}
    for scope, rule in items(model.snapshot, "firewall"):
        if model._norm_scope(scope) != project or rule.get("disabled") is True:
            continue
        network = str(rule.get("network") or "").rsplit("/compute/v1/", 1)[-1]
        if network not in networks or rule.get("direction") != "INGRESS":
            continue
        if rule.get("denied"):
            return False
        if rule.get("targetTags") and not tags.intersection(rule["targetTags"]):
            continue
        if rule.get("targetServiceAccounts") and not service_accounts.intersection(rule["targetServiceAccounts"]):
            continue
        if rule.get("sourceTags") or rule.get("sourceServiceAccounts"):
            continue
        if not any(range_ in ("0.0.0.0/0", "::/0") for range_ in rule.get("sourceRanges") or []):
            continue
        if any(_allows_ssh(allow) for allow in rule.get("allowed") or []):
            return True
    return False


def selector(model, value, candidates, source, *, require_admin=True):
    if value is not True or source is None:
        return {}
    by_project = {}
    for scope, item in items(model.snapshot, "instance"):
        by_project.setdefault(model._norm_scope(scope), []).append(item)
    result = {}
    for tid, target in candidates.items():
        email = target.attrs.get("email")
        for project, vms in by_project.items():
            for vm in vms:
                if not any(row.get("email") == email for row in vm.get("serviceAccounts") or [] if isinstance(row, dict)):
                    continue
                resource = _vm_resource(model, vm, project)
                if resource is None:
                    continue
                model.parents.setdefault(resource, project)
                login = model.check(source, {"action": "compute.instances.osLogin"}, resource)
                admin = model.check(source, {"action": "compute.instances.osAdminLogin"}, resource) if require_admin else None
                if login is None or (require_admin and admin is None):
                    continue
                instance_flag = _flag(vm.get("metadata"), "enable-oslogin")
                project_meta = _project_metadata(model, project)
                project_flag = _flag(project_meta, "enable-oslogin")
                enabled = instance_flag if instance_flag is not None else project_flag
                if enabled is _UNRESOLVED:
                    result[tid] = ("unknown", "oslogin_metadata_unresolved")
                    continue
                if enabled is False:
                    continue
                actas = model.check(source, {"action": "iam.serviceAccounts.actAs"}, target.attrs.get("resource"))
                if actas is None:
                    continue
                instance_2fa = _flag(vm.get("metadata"), "enable-oslogin-2fa")
                project_2fa = _flag(project_meta, "enable-oslogin-2fa")
                twofa = instance_2fa if instance_2fa is not None else project_2fa
                orgs = [scope for scope in model.ancestors(project) if scope.startswith("organizations/")]
                external = (source.kind == "gcp_user" and orgs and not any(
                    (grant := model.check(source, {"action": "compute.oslogin.updateExternalUser"}, org)) is not None
                    and grant.confidence == "derived" for org in orgs))
                if vm.get("status") == "TERMINATED":
                    verdict = ("unknown", "oslogin_vm_must_start")
                elif project != target.scope:
                    verdict = ("unknown", "oslogin_cross_project_sa_usage_unresolved")
                elif inventory_status(model.snapshot, "instance").get(project) != "collected":
                    verdict = ("unknown", "oslogin_vm_inventory_unresolved")
                elif enabled is None or vm.get("status") != "RUNNING":
                    verdict = ("unknown", "oslogin_enablement_or_vm_state_unresolved")
                elif external:
                    verdict = ("unknown", "oslogin_external_user_eligibility_unresolved")
                elif actas.confidence != "derived":
                    verdict = ("unknown", "oslogin_service_account_attachment_unresolved")
                elif twofa in (True, _UNRESOLVED) and source.kind == "gcp_user":
                    verdict = ("unknown", "oslogin_second_factor_unresolved")
                elif login.confidence != "derived" or (require_admin and admin.confidence != "derived"):
                    verdict = ("unknown", "oslogin_iam_condition_unresolved")
                elif not _firewall_permits_ssh(model, project, vm):
                    verdict = ("unknown", "oslogin_ssh_reachability_unresolved")
                else:
                    verdict = None
                if verdict is None or tid not in result:
                    result[tid] = verdict
    return result
