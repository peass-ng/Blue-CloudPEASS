"""Join Dataproc session creation to a usable interactive runtime identity."""

from __future__ import annotations

from . import items
from .gcp_datafusion_artifact import _rights
from .gcp_dataproc_create import _WORKER, _agent, _api, _role_on_project, _subnet


def select(model, candidates, source):
    if source is None:
        return {}
    projects = sorted({model._norm_scope(scope) for scope, _ in items(model.snapshot, 'project')})
    out = {}
    for target_id, target in candidates.items():
        if target_id == source.id or target.kind != 'gcp_service_account' or target.attrs.get('disabled'):
            continue
        resource = target.attrs.get('resource')
        target_project = target.attrs.get('project') or target.scope
        if not isinstance(resource, str) or not isinstance(target_project, str):
            continue
        actas = _rights(model, source, resource, ('iam.serviceAccounts.actAs',))
        if actas == 'denied':
            continue
        uncertain = actas == 'uncertain'
        for project in projects:
            create = _rights(model, source, project, ('dataproc.sessions.create',))
            if create == 'denied':
                continue
            if project != target_project:
                uncertain = True  # Cross-project attachment has additional IAM and policy gates.
                continue
            if create != 'derived':
                uncertain = True
                continue
            if _api(model, project) == 'denied':
                continue
            if _api(model, project) != 'derived' or _subnet(model, project) != 'derived':
                uncertain = True
                continue
            # The interactive client reads its session details before connecting.
            session_get = _rights(model, source, project, ('dataproc.sessions.get',))
            if session_get != 'derived':
                uncertain = True
                continue
            old_runtime = (_agent(model, project) == 'derived'
                           and _rights(model, target, project, _WORKER) == 'derived')
            new_runtime = (_api(model, project, 'dataprocrm') == 'derived'
                           and _agent(model, project, 'node3') == 'derived'
                           and _role_on_project(model, target.id, project,
                                                'roles/dataproc.serverlessNode')
                           and _role_on_project(model, target.id, project,
                                                'roles/dataprocrm.nodeServiceAgent'))
            if (old_runtime or new_runtime) and actas == 'derived':
                out[target_id] = ('conditional', 'interactive_session_with_runnable_service_account')
                break
            uncertain = True
        if target_id not in out and uncertain:
            out[target_id] = ('unknown', 'interactive_session_access_or_runtime_unresolved')
    return out
