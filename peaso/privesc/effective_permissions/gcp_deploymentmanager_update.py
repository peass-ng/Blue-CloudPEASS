"""Resolve direct updates of one exact Deployment Manager deployment."""

from __future__ import annotations

from . import inventory_status
from .gcp_datafusion_artifact import _rights
from .gcp_dataproc_create import _api
from .gcp_deploymentmanager_create import _vm_path


def select(model, candidates, source):
    if source is None:
        return {}
    out = {}
    for target_id, agent in candidates.items():
        if (target_id == source.id or agent.kind != 'gcp_service_account' or
                agent.attrs.get('service_agent') != 'cloudservices_agent'):
            continue
        project = agent.attrs.get('project')
        number = agent.attrs.get('email', '').split('@', 1)[0]
        if (not isinstance(project, str) or not number.isdecimal() or
                model.project_alias.get(number) != project.split('/', 1)[-1]):
            continue
        api = _api(model, project, 'deploymentmanager')
        if api == 'denied':
            continue
        unresolved = api != 'derived'
        states = {model._norm_scope(scope): state for scope, state in
                  inventory_status(model.snapshot, 'deployment_manager_deployment').items()}
        if (states.get(project) not in ('collected', 'empty') and
                _rights(model, source, project,
                        ('deploymentmanager.deployments.update',)) != 'denied'):
            unresolved = True
        for resource, row in model.deployment_manager_deployments.items():
            if not resource.startswith(project + '/global/deployments/'):
                continue
            update = _rights(model, source, resource,
                             ('deploymentmanager.deployments.update',))
            if update == 'denied':
                continue
            if update != 'derived':
                unresolved = True
                continue
            get = _rights(model, source, resource,
                          ('deploymentmanager.deployments.get',))
            fingerprint = row.get('fingerprint')
            if (get != 'derived' or not isinstance(fingerprint, str) or
                    not fingerprint or _vm_path(model, source, agent, project) != 'derived'):
                unresolved = True
                continue
            if api == 'derived':
                out[target_id] = ('conditional', 'exact_deployment_update_with_agent_vm_path')
                break
        if target_id not in out and unresolved:
            out[target_id] = ('unknown', 'deployment_update_or_deputy_path_unresolved')
    return out
