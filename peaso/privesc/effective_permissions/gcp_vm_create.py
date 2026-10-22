"""Check a concrete VM configuration for a prospective service-account pivot."""

from __future__ import annotations

import re

from . import inventory_status, items


def _subnet_resource(model, item):
    link = item.get("selfLink")
    match = re.fullmatch(
        r"https://(?:www|compute)\.googleapis\.com/compute/v1/(projects/[^/]+/regions/[^/]+/subnetworks/[^/]+)",
        link) if isinstance(link, str) else None
    return model._norm_scope(match.group(1)) if match else None


def selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    by_project = {}
    for tid, target in candidates.items():
        by_project.setdefault(target.scope, []).append(tid)
    statuses = {model._norm_scope(scope): status for scope, status in
                inventory_status(model.snapshot, "subnetwork").items()}
    image_status = {model._norm_scope(scope): status for scope, status in
                    inventory_status(model.snapshot, "image").items()}
    result = {}
    for project, tids in by_project.items():
        core = [model.check(source, {"action": permission}, project) for permission in (
            "compute.instances.create", "compute.instances.setMetadata", "compute.instances.setServiceAccount")]
        if any(grant is None for grant in core):
            continue
        disk = model.check(source, {"action": "compute.disks.create"}, project)
        subnet_ready = False
        for scope, item in items(model.snapshot, "subnetwork"):
            if model._norm_scope(scope) != project:
                continue
            resource = _subnet_resource(model, item)
            if not resource or not resource.startswith(project + "/"):
                continue
            model.parents.setdefault(resource, project)
            use = model.check(source, {"action": "compute.subnetworks.use"}, resource)
            external = model.check(source, {"action": "compute.subnetworks.useExternalIp"}, resource)
            if (use is not None and use.confidence == "derived"
                    and external is not None and external.confidence == "derived"
                    and item.get("purpose") == "PRIVATE"
                    and item.get("state") == "READY"):
                subnet_ready = True
                break
        image_ready = any(resource.startswith(project + "/global/images/")
                          and item.get("status") == "READY"
                          and (grant := model.check(source, {"action": "compute.images.useReadOnly"}, resource)) is not None
                          and grant.confidence == "derived" for resource, item in model.images.items())
        known = (all(grant.confidence == "derived" for grant in core)
                 and disk is not None and disk.confidence == "derived" and subnet_ready and image_ready
                 and statuses.get(project) == "collected" and image_status.get(project) == "collected")
        verdict = None if known else ("unknown", "vm_boot_image_subnet_or_egress_unresolved")
        for tid in tids:
            target = candidates[tid]
            actas = model.check(source, {"action": "iam.serviceAccounts.actAs"}, target.attrs.get("resource"))
            if actas is None:
                continue
            result[tid] = verdict if actas.confidence == "derived" else (
                "unknown", "vm_service_account_attachment_unresolved")
    return result
