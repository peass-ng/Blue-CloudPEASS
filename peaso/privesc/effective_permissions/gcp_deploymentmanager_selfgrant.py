"""Check a deployment policy self-grant followed by deputy execution."""

from __future__ import annotations

from . import Grant
from .gcp_datafusion_artifact import _rights
from .gcp_dataproc_create import _api
from .gcp_deploymentmanager_create import _vm_path


def select(model, candidates, source):
    if source is None:
        return {}
    out = {}
    admin = model.roles.get('roles/deploymentmanager.admin')
    role_ready = (admin is not None and admin.confidence == 'derived' and
                  admin.has('deploymentmanager.deployments.update') and
                  admin.has('deploymentmanager.deployments.get'))
    for target_id, agent in candidates.items():
        if (target_id == source.id or agent.kind != 'gcp_service_account' or
                agent.attrs.get('service_agent') != 'cloudservices_agent'):
            continue
        project = agent.attrs.get('project')
        number = agent.attrs.get('email', '').split('@', 1)[0]
        if (not isinstance(project, str) or not number.isdecimal() or
                model.project_alias.get(number) != project.split('/', 1)[-1]):
            continue
        if _api(model, project, 'deploymentmanager') == 'denied':
            continue
        api_ready = _api(model, project, 'deploymentmanager') == 'derived'
        unresolved = not api_ready
        for resource, row in model.deployment_manager_deployments.items():
            if not resource.startswith(project + '/global/deployments/'):
                continue
            policy_write = _rights(model, source, resource,
                                   ('deploymentmanager.deployments.setIamPolicy',))
            if policy_write == 'denied':
                continue
            if policy_write != 'derived':
                unresolved = True
                continue
            # An existing direct update path belongs to the update technique.
            if _rights(model, source, resource,
                       ('deploymentmanager.deployments.update',)) == 'derived':
                continue
            policy_read = _rights(model, source, resource,
                                  ('deploymentmanager.deployments.getIamPolicy',))
            policy = row.get('iamPolicy')
            coverage = ((row.get('_coverage') or {}).get('iamPolicy') or {}).get('status')
            if (policy_read != 'derived' or coverage != 'collected' or
                    not isinstance(policy, dict) or
                    not isinstance(policy.get('etag'), str) or not policy['etag'] or
                    not role_ready or not source.id.startswith(('user:', 'serviceAccount:'))):
                unresolved = True
                continue
            updated = model._deny(source, 'deploymentmanager.deployments.update',
                                  resource, Grant())
            if updated is None:
                continue
            if updated.confidence != 'derived':
                unresolved = True
                continue
            if _vm_path(model, source, agent, project) != 'derived':
                unresolved = True
                continue
            if not api_ready:
                continue
            out[target_id] = ('conditional', 'exact_deployment_policy_self_grant_and_update')
            break
        if target_id not in out and unresolved:
            out[target_id] = ('unknown', 'deployment_policy_or_deputy_path_unresolved')
    return out
