"""Verify a usable legacy deployment and a concrete service-agent VM path."""

from __future__ import annotations

from . import inventory_status, items
from .gcp_datafusion_artifact import _rights
from .gcp_dataproc_create import _api
from .gcp_vm_create import _subnet_resource


def _existing(model, project):
    states = {model._norm_scope(scope): status for scope, status in
              inventory_status(model.snapshot, 'deployment_manager_deployment').items()}
    if states.get(project) not in ('collected', 'empty'):
        return 'uncertain'
    return ('derived' if any(model._norm_scope(scope) == project for scope, _ in
                             items(model.snapshot, 'deployment_manager_deployment'))
            else 'uncertain')  # Historical customer eligibility is not disproved by an empty list.


def _vm_path(model, source, agent, project):
    if _api(model, project, 'compute') == 'denied':
        return 'denied'
    if _api(model, project, 'compute') != 'derived':
        return 'uncertain'
    core = ('compute.instances.create', 'compute.instances.setServiceAccount',
            'compute.instances.setMetadata', 'compute.disks.create')
    for permission in core:
        if _rights(model, agent, project, (permission,)) != 'derived':
            return 'uncertain'
    image_ready = any(resource.startswith(project + '/global/images/')
                      and image.get('status') == 'READY'
                      and _rights(model, agent, resource,
                                  ('compute.images.useReadOnly',)) == 'derived'
                      for resource, image in model.images.items())
    if not image_ready:
        return 'uncertain'
    subnet_ready = False
    for scope, subnet in items(model.snapshot, 'subnetwork'):
        if model._norm_scope(scope) != project:
            continue
        resource = _subnet_resource(model, subnet)
        if resource and subnet.get('purpose') == 'PRIVATE' and subnet.get('state') == 'READY':
            model.parents.setdefault(resource, project)
            if _rights(model, agent, resource, ('compute.subnetworks.use',
                                                'compute.subnetworks.useExternalIp')) == 'derived':
                subnet_ready = True
                break
    if not subnet_ready:
        return 'uncertain'
    accounts = [node for node in model.sas.values()
                if node.scope == project and not node.attrs.get('service_agent')
                and not node.attrs.get('disabled') and node.id != agent.id]
    if not accounts:
        return 'uncertain'
    for account in accounts:
        resource = account.attrs.get('resource')
        if not isinstance(resource, str):
            continue
        if _rights(model, agent, resource, ('iam.serviceAccounts.actAs',)) != 'derived':
            continue
        if (any(_rights(model, source, project, (permission,)) != 'derived'
                for permission in core) or
                _rights(model, source, resource, ('iam.serviceAccounts.actAs',)) != 'derived'):
            return 'derived'
    return 'uncertain'


def select(model, candidates, source):
    if source is None:
        return {}
    out = {}
    for target_id, agent in candidates.items():
        if (target_id == source.id or agent.kind != 'gcp_service_account'
                or agent.attrs.get('service_agent') != 'cloudservices_agent'):
            continue
        project = agent.attrs.get('project')
        if not isinstance(project, str):
            continue
        number = agent.attrs.get('email', '').split('@', 1)[0]
        if not number.isdecimal() or model.project_alias.get(number) != project.split('/', 1)[-1]:
            continue
        create = _rights(model, source, project, ('deploymentmanager.deployments.create',))
        if create == 'denied':
            continue
        if _api(model, project, 'deploymentmanager') == 'denied':
            continue
        if create != 'derived' or _api(model, project, 'deploymentmanager') != 'derived':
            out[target_id] = ('unknown', 'deployment_manager_permission_or_api_unresolved')
            continue
        eligible = _existing(model, project)
        vm = _vm_path(model, source, agent, project)
        if eligible == 'derived' and vm == 'derived':
            out[target_id] = ('conditional', 'existing_customer_with_service_agent_vm_path')
        else:
            out[target_id] = ('unknown', 'deployment_manager_customer_or_deputy_path_unresolved')
    return out
