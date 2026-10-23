"""Find one viable new template and managed-instance-group SA pivot."""

from __future__ import annotations

from . import inventory_status, items
from .gcp_vm_create import _subnet_resource


def _grant(model, principal, action, resource):
    grant = model.check(principal, {"action": action}, resource)
    return grant.confidence if grant is not None else None


def _agent(model, project):
    number = next((num for num, pid in model.project_alias.items()
                   if pid == project.split("/", 1)[1]), None)
    if not number:
        return None
    email = f"{number}@cloudservices.gserviceaccount.com"
    return next((node for node in model.principals.values()
                 if node.attrs.get("email", "").lower() == email), None)


def _support(model, source, agent, project):
    # A template and one zonal MIG with a startup script, a new boot disk,
    # and an external IP provide a concrete configuration. Other images,
    # existing disks, Shared VPC and private egress remain unresolved.
    source_actions = ("compute.instances.create", "compute.instances.setMetadata", "compute.disks.create")
    agent_actions = ("compute.instances.create",
                     "compute.instances.setMetadata", "compute.instances.setServiceAccount",
                     "compute.disks.create")
    if any(not any(_grant(model, principal, action, project) == "derived" for action in
                   ("compute.instanceTemplates.get", "compute.instanceTemplates.useReadOnly"))
           for principal in (source, agent)):
        return False
    if any(_grant(model, source, action, project) != "derived" for action in source_actions):
        return False
    if any(_grant(model, agent, action, project) != "derived" for action in agent_actions):
        return False
    if inventory_status(model.snapshot, "image").get(project) != "collected":
        return False
    if inventory_status(model.snapshot, "subnetwork").get(project) != "collected":
        return False
    images = [resource for resource, image in model.images.items()
              if resource.startswith(project + "/global/images/") and image.get("status") == "READY"
              and _grant(model, source, "compute.images.useReadOnly", resource) == "derived"
              and _grant(model, agent, "compute.images.useReadOnly", resource) == "derived"]
    if not images:
        return False
    for scope, subnet in items(model.snapshot, "subnetwork"):
        if model._norm_scope(scope) != project:
            continue
        resource = _subnet_resource(model, subnet)
        if not resource or not resource.startswith(project + "/"):
            continue
        model.parents.setdefault(resource, project)
        if subnet.get("purpose") != "PRIVATE" or subnet.get("state") != "READY":
            continue
        if all(_grant(model, principal, action, resource) == "derived"
               for principal in (source, agent)
               for action in ("compute.subnetworks.use", "compute.subnetworks.useExternalIp")):
            return True
    return False


def selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    result = {}
    projects = {scope for scope in model.scopes if scope.startswith("projects/") and scope.count("/") == 1}
    for project in projects:
        project = model._norm_scope(project)
        core = [_grant(model, source, action, project) for action in
                ("compute.instanceTemplates.create", "compute.instanceGroupManagers.create")]
        if any(grant is None for grant in core):
            continue
        agent = _agent(model, project)
        supported = (agent is not None and all(grant == "derived" for grant in core)
                     and _support(model, source, agent, project))
        for tid, target in candidates.items():
            if agent is None:
                if target.scope == project:
                    result.setdefault(tid, ("unknown", "mig_create_service_agent_unresolved"))
                continue
            actas = _grant(model, agent, "iam.serviceAccounts.actAs", target.attrs.get("resource"))
            if actas is None:
                continue
            verdict = (None if supported and actas == "derived" and target.scope == project else
                       ("unknown", "mig_create_configuration_or_cross_project_sa_unresolved"))
            if verdict is None or tid not in result:
                result[tid] = verdict
    return result
