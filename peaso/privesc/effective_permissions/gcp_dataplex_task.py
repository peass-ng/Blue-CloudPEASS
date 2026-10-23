"""Join Dataplex task creation to an existing lake and a runnable identity."""

from __future__ import annotations

from . import inventory_status, items
from .gcp_datafusion_artifact import _rights


def _service_states(model):
    status = {model._norm_scope(scope): state for scope, state in
              inventory_status(model.snapshot, 'service_usage').items()}
    services = {}
    for scope, row in items(model.snapshot, 'service_usage'):
        project = model._norm_scope(scope)
        name = model._norm_scope(row.get('name')) if isinstance(row.get('name'), str) else ''
        for service in ('dataplex', 'dataproc'):
            if name == project + '/services/' + service + '.googleapis.com':
                services[(project, service)] = row.get('state')
    return status, services


def _payload(model, source, target):
    """Find an existing bucket where a new Python file can be written and read."""
    uncertain = False
    bucket_status = {model._norm_scope(scope): state for scope, state in
                     inventory_status(model.snapshot, 'bucket').items()}
    for name, project in model.bucket_projects.items():
        bucket = '//storage.googleapis.com/projects/_/buckets/' + name
        object_resource = bucket + '/objects/__peaso_dataplex_task.py'
        model.parents.setdefault(object_resource, bucket)
        create = _rights(model, source, bucket, ('storage.objects.create',))
        read = _rights(model, target, object_resource, ('storage.objects.get',))
        if create == read == 'derived':
            return 'derived'
        if create != 'denied' and read != 'denied':
            uncertain = True
    if any(state not in ('collected', 'empty') for state in bucket_status.values()):
        uncertain = True
    # External buckets and existing editable payload objects are not an
    # exhaustive inventory; their absence cannot prove the path impossible.
    return 'uncertain' if uncertain else 'unresolved'


def _agent_role(model, project, project_numbers):
    number = project_numbers.get(project.removeprefix('projects/'))
    if not number:
        return 'uncertain'
    agent = 'serviceAccount:service-' + number + '@gcp-sa-dataplex.iam.gserviceaccount.com'
    bindings = model.grants.get(agent, ())
    if any(scope == project and role == 'roles/dataplex.serviceAgent' and not condition
           for scope, role, condition, _ in bindings):
        return 'derived'
    return 'uncertain'


def select(model, candidates, source):
    if source is None:
        return {}
    lake_status = {model._norm_scope(scope): state for scope, state in
                   inventory_status(model.snapshot, 'dataplex_privesc_lake').items()}
    usage_status, services = _service_states(model)
    project_numbers = {pid: number for number, pid in model.project_alias.items()
                       if number.isdecimal()}
    out = {}
    for target_id, target in candidates.items():
        if (target_id == source.id or target.kind != 'gcp_service_account'
                or target.attrs.get('disabled')):
            continue
        sa_resource = target.attrs.get('resource')
        target_project = target.attrs.get('project') or target.scope
        if not isinstance(sa_resource, str) or not isinstance(target_project, str):
            continue
        actas = _rights(model, source, sa_resource, ('iam.serviceAccounts.actAs',))
        if actas == 'denied':
            continue
        uncertain = actas == 'uncertain'
        for name, lake in model.dataplex_lakes.items():
            lake_project = name.split('/locations/', 1)[0]
            if lake_status.get(lake_project) not in ('collected', 'empty'):
                uncertain = True
                continue
            create = _rights(model, source, name, ('dataplex.tasks.create',))
            if create == 'denied':
                continue
            if lake.get('state') in ('DELETING', 'CREATING'):
                continue
            if create == 'uncertain' or lake.get('state') != 'ACTIVE':
                uncertain = True
                continue
            if lake_project != target_project:
                uncertain = True
                continue
            if usage_status.get(lake_project) not in ('collected', 'empty'):
                uncertain = True
                continue
            if any(services.get((lake_project, service)) != 'ENABLED'
                   for service in ('dataplex', 'dataproc')):
                if any(services.get((lake_project, service)) not in
                       (None, 'ENABLED', 'DISABLED') for service in ('dataplex', 'dataproc')):
                    uncertain = True
                continue
            if _agent_role(model, lake_project, project_numbers) != 'derived':
                uncertain = True
                continue
            worker = _rights(model, target, lake_project,
                             ('dataproc.agents.create', 'dataproc.agents.get',
                              'dataproc.agents.update', 'dataproc.agents.delete',
                              'dataproc.tasks.lease', 'dataproc.tasks.reportStatus',
                              'storage.objects.create', 'storage.objects.get',
                              'storage.objects.delete', 'storage.objects.list'))
            if worker == 'denied':
                uncertain = True
                continue
            if worker == 'uncertain':
                uncertain = True
                continue
            payload = _payload(model, source, target)
            if payload != 'derived' or actas != 'derived':
                uncertain = True
                continue
            out[target_id] = ('conditional', 'active_lake_and_controlled_readable_spark_payload')
            break
        if target_id not in out and uncertain:
            out[target_id] = ('unknown', 'dataplex_task_execution_path_unresolved')
    return out
