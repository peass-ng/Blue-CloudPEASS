"""Bind Data Fusion IAM policy control to one runnable pipeline account."""

from __future__ import annotations

from . import inventory_status
from .gcp_datafusion_artifact import _namespace_possible_runner, _rights
from .gcp_datafusion_pipeline import _code_capable, _profiles


def select(model, candidates, source):
    if source is None:
        return {}
    statuses = {model._norm_scope(scope): state for scope, state in
                inventory_status(model.snapshot, 'datafusion_privesc_instance').items()}
    project_numbers = {pid: number for number, pid in model.project_alias.items()
                       if number.isdecimal()}
    out = {}
    for target_id, target in candidates.items():
        if (target_id == source.id or target.kind != 'gcp_service_account'
                or target.attrs.get('disabled')):
            continue
        email = target.attrs.get('email')
        sa_resource = target.attrs.get('resource')
        if not isinstance(email, str):
            continue
        uncertain = False
        for instance_name, instance in model.datafusion_instances.items():
            project = instance_name.split('/locations/', 1)[0]
            if statuses.get(project) not in ('collected', 'empty') or instance.get('state') != 'RUNNING':
                continue
            instance_write = _rights(model, source, instance_name,
                                     ('datafusion.instances.setIamPolicy',))
            namespaces = instance.get('namespaces')
            if not isinstance(namespaces, list):
                uncertain |= instance_write != 'denied'
                continue
            for namespace in namespaces:
                if not isinstance(namespace, dict) or not isinstance(namespace.get('name'), str):
                    uncertain |= instance_write != 'denied'
                    continue
                namespace_resource = instance_name + '/namespaces/' + namespace['name']
                namespace_write = ('denied' if instance.get('enableRbac') is not True else
                                   _rights(model, source, namespace_resource,
                                           ('datafusion.namespaces.setIamPolicy',)))
                if instance_write == namespace_write == 'denied':
                    continue
                profiles, profile_reason = _profiles(instance, namespace, project_numbers)
                matching = [(runner, cluster_project) for runner, cluster_project in profiles
                            if runner.lower() == email.lower()]
                if not matching:
                    uncertain |= bool(profile_reason and _namespace_possible_runner(
                        instance, namespace, project_numbers, email))
                    continue
                plugins = namespace.get('pipelinePlugins')
                artifacts = namespace.get('artifacts')
                if not isinstance(plugins, list) or not isinstance(artifacts, list):
                    uncertain = True
                    continue
                parents = {(artifact.get('version'), artifact.get('scope'))
                           for artifact in artifacts if isinstance(artifact, dict)
                           and artifact.get('name') == 'cdap-data-pipeline'}
                if not any(_code_capable(plugin) and
                           (plugin['parentVersion'], plugin['parentScope']) in parents
                           for plugin in plugins):
                    continue
                namespace_gate = _rights(model, source, instance_name,
                                         ('datafusion.instances.get',))
                # A new instance admin grant supplies the instance gate and
                # pipeline permissions. A namespace binding needs current
                # instance access; the documentation disagrees on whether a
                # namespace role implicitly supplies it.
                route = ('derived' if instance_write == 'derived' else
                         ('derived' if namespace_write == namespace_gate == 'derived'
                          else 'uncertain' if instance_write == 'uncertain'
                          or namespace_write != 'denied' else 'denied'))
                if route == 'denied':
                    continue
                if route == 'uncertain':
                    uncertain = True
                    continue
                agent_number = project_numbers.get(project.removeprefix('projects/'))
                agent = (model.principals.get('serviceAccount:service-' + agent_number
                         + '@gcp-sa-datafusion.iam.gserviceaccount.com') if agent_number else None)
                if agent is None or not isinstance(sa_resource, str):
                    uncertain = True
                    continue
                for _, cluster_project in matching:
                    runtime = (_rights(model, agent, sa_resource,
                                       ('iam.serviceAccounts.actAs',)),
                               _rights(model, target, instance_name,
                                       ('datafusion.instances.runtime',)),
                               _rights(model, target, 'projects/' + cluster_project,
                                       ('dataproc.agents.create',)))
                    if 'denied' in runtime:
                        continue
                    if 'uncertain' in runtime:
                        uncertain = True
                        continue
                    out[target_id] = ('conditional', 'exact_policy_self_grant_to_code_pipeline_runner')
                    break
                if target_id in out:
                    break
            if target_id in out:
                break
        if target_id not in out and uncertain:
            out[target_id] = ('unknown', 'datafusion_selfgrant_pipeline_path_unresolved')
    return out
