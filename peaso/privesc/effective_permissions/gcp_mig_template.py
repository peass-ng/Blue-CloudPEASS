"""Bind a managed instance group template pivot to one existing group and SA."""

from __future__ import annotations

import re

from . import inventory_status, items


def _resource(model, value, pattern):
    if not isinstance(value, str):
        return None
    if re.fullmatch(pattern, value):
        return model._norm_scope(value)
    match = re.fullmatch(r"https://(?:www|compute)\.googleapis\.com/compute/v1/(" + pattern + r")", value)
    return model._norm_scope(match.group(1)) if match else None


def selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    outcomes = {}
    for project in sorted({target.scope for target in candidates.values()}):
        outcomes.update(_project_path(model, source, project, candidates))
    return outcomes


def _template_verdict(model, source, project, template, mig, update):
    if template is None:
        return ("unknown", "mig_template_unresolved")
    props = template.get("properties") or {}
    disks = props.get("disks") if isinstance(props, dict) else None
    nics = props.get("networkInterfaces") if isinstance(props, dict) else None
    # Rebuilding the observed template with controlled startup metadata
    # needs the same referenced image and subnet access. A missing grant
    # keeps the path visible as unresolved.
    required = [
        ("compute.instanceTemplates.useReadOnly", project),
        ("compute.instances.create", project),
        ("compute.instances.setMetadata", project),
        ("compute.disks.create", project),
    ]
    complete = isinstance(disks, list) and bool(disks) and isinstance(nics, list) and bool(nics)
    for disk in disks if isinstance(disks, list) else []:
        image = ((disk or {}).get("initializeParams") or {}).get("sourceImage")
        if image:
            image_ref = _resource(model, image, r"projects/[^/]+/global/images/[^/]+")
            if image_ref is None:
                required.append(("compute.images.useReadOnly", ""))
            else:
                model.parents.setdefault(image_ref, image_ref.split("/global/", 1)[0])
                required.append(("compute.images.useReadOnly", image_ref))
        else:
            complete = False
    for nic in nics if isinstance(nics, list) else []:
        subnet = (nic or {}).get("subnetwork")
        if subnet:
            subnet_ref = _resource(model, subnet, r"projects/[^/]+/regions/[^/]+/subnetworks/[^/]+")
            if subnet_ref:
                model.parents.setdefault(subnet_ref, subnet_ref.split("/regions/", 1)[0])
            required.append(("compute.subnetworks.use", subnet_ref or ""))
        else:
            complete = False
    supporting = all(ref and model.check(source, {"action": permission}, ref) is not None
                     for permission, ref in required)
    rollout = (mig.get("updatePolicy") or {}).get("type") == "PROACTIVE"
    target_size = mig.get("targetSize")
    return (None if complete and supporting and rollout and isinstance(target_size, int) and target_size > 0
            and update.confidence == "derived" else
            ("unknown", "mig_supporting_permission_or_rollout_unresolved"))


def _project_path(model, source, project, candidates):
    project = model._norm_scope(project)
    if not project.startswith("projects/") or project.count("/") != 1:
        return {}
    targets = {tid: target for tid, target in candidates.items() if target.scope == project}
    if not targets:
        return {}
    inventory = {model._norm_scope(scope): status for scope, status in
                 inventory_status(model.snapshot, "instance_group_manager").items()}
    templates = {model._norm_scope(scope): status for scope, status in
                 inventory_status(model.snapshot, "instance_template").items()}
    if inventory.get(project) not in ("collected", "empty") or templates.get(project) not in ("collected", "empty"):
        return {tid: ("unknown", "mig_or_template_inventory_unresolved") for tid in targets}
    number = next((num for num, pid in model.project_alias.items() if pid == project.split("/", 1)[1]), None)
    agent = next((node for node in model.principals.values()
                  if node.attrs.get("email", "").lower() == f"{number}@cloudservices.gserviceaccount.com"), None)
    if not number or agent is None:
        return {tid: ("unknown", "mig_service_agent_unresolved") for tid in targets}
    if model.check(source, {"action": "compute.instanceTemplates.create"}, project) is None:
        return {}
    template_rows = {}
    for scope, item in items(model.snapshot, "instance_template"):
        if model._norm_scope(scope) != project:
            continue
        resource = _resource(model, item.get("selfLink"),
                             r"projects/[^/]+/(?:global|regions/[^/]+)/instanceTemplates/[^/]+")
        if resource and resource.startswith(project + "/"):
            model.parents.setdefault(resource, project)
            template_rows[resource] = item
    outcomes = {}
    for scope, mig in items(model.snapshot, "instance_group_manager"):
        if model._norm_scope(scope) != project:
            continue
        resource = _resource(model, mig.get("selfLink"),
                             r"projects/[^/]+/(?:zones|regions)/[^/]+/instanceGroupManagers/[^/]+")
        if not resource or not resource.startswith(project + "/"):
            continue
        model.parents.setdefault(resource, project)
        update = model.check(source, {"action": "compute.instanceGroupManagers.update"}, resource)
        if update is None:
            continue
        versions = [version.get("instanceTemplate") for version in mig.get("versions") or []
                    if isinstance(version, dict) and version.get("instanceTemplate")]
        template_urls = versions or [mig.get("instanceTemplate")]
        refs = [_resource(model, url, r"projects/[^/]+/(?:global|regions/[^/]+)/instanceTemplates/[^/]+")
                for url in template_urls if url]
        verdicts = [_template_verdict(model, source, project, template_rows.get(ref), mig, update)
                    for ref in refs]
        verdict = None if None in verdicts else (verdicts[0] if verdicts else ("unknown", "mig_template_unresolved"))
        for tid, target in targets.items():
            actas = model.check(agent, {"action": "iam.serviceAccounts.actAs"}, target.attrs.get("resource"))
            if actas is None:
                continue
            candidate = verdict
            if actas.confidence != "derived":
                candidate = ("unknown", "mig_service_agent_actas_unresolved")
            if candidate is None or tid not in outcomes:
                outcomes[tid] = candidate
    return outcomes
