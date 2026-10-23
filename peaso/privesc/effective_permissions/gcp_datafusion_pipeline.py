"""Match a creatable code-capable pipeline to an exact runnable Data Fusion identity."""

from __future__ import annotations

from . import inventory_status
from .gcp_datafusion_artifact import _namespace_possible_runner, _rights, resolve_runner_context


_CODE_PLUGINS = {
    ('PySparkProgram', 'action'): ('spark', 'python'),
    ('ScalaSparkProgram', 'action'): ('spark', 'scala'),
    ('ScalaSparkCompute', 'sparkcompute'): ('spark', 'scala'),
    ('PythonEvaluator', 'transform'): ('python',),
    ('JavaScript', 'transform'): ('javascript',),
    ('Spark', 'sparkcompute'): ('spark',),
}


def _code_capable(plugin):
    if not isinstance(plugin, dict):
        return False
    markers = _CODE_PLUGINS.get((plugin.get('name'), plugin.get('type')))
    class_name = plugin.get('className')
    return (markers is not None and isinstance(class_name, str)
            and any(marker in class_name.lower() for marker in markers)
            and plugin.get('parentScope') == 'SYSTEM'
            and isinstance(plugin.get('parentVersion'), str))


def _profiles(instance, namespace, project_numbers):
    """Include the built-in profile and every enabled selectable Dataproc profile."""
    default = namespace.get('defaultProfile')
    uncertain = not isinstance(default, dict)
    options = [None] if isinstance(default, dict) and default.get('profileName') is None else []
    profiles = namespace.get('profiles')
    if not isinstance(profiles, list):
        profiles = []
        uncertain = True
    options += [profile['scope'].lower() + ':' + profile['name']
                for profile in profiles if isinstance(profile, dict)
                and profile.get('scope') in ('USER', 'SYSTEM')
                and isinstance(profile.get('name'), str)
                and profile.get('status') == 'ENABLED'
                and profile.get('provisioner') in ('gcp-dataproc', 'dataproc')]
    resolved = []
    for chosen in options:
        email, project, reason = resolve_runner_context(
            instance, namespace, {'workflowProfile': {'profileName': chosen}},
            {'profileName': None}, project_numbers)
        if reason:
            uncertain = True
        elif email and project:
            resolved.append((email, project))
    return resolved, 'datafusion_profile_runner_unresolved' if uncertain else None


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
            namespaces = instance.get('namespaces')
            if not isinstance(namespaces, list):
                uncertain = True
                continue
            for namespace in namespaces:
                if not isinstance(namespace, dict) or not isinstance(namespace.get('name'), str):
                    uncertain = True
                    continue
                profiles, profile_reason = _profiles(instance, namespace, project_numbers)
                possible = any(runner.lower() == email.lower() for runner, _ in profiles)
                if not possible:
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
                namespace_resource = instance_name + '/namespaces/' + namespace['name']
                rights = (_rights(model, source, instance_name,
                                  ('datafusion.instances.get',)),
                          _rights(model, source, namespace_resource,
                                  ('datafusion.namespaces.get', 'datafusion.pipelines.create',
                                   'datafusion.pipelines.execute')))
                if 'denied' in rights:
                    continue
                if 'uncertain' in rights:
                    uncertain = True
                    continue
                agent_number = project_numbers.get(project.removeprefix('projects/'))
                agent = (model.principals.get('serviceAccount:service-' + agent_number
                         + '@gcp-sa-datafusion.iam.gserviceaccount.com') if agent_number else None)
                if agent is None or not isinstance(sa_resource, str):
                    uncertain = True
                    continue
                for runner, cluster_project in profiles:
                    if runner.lower() != email.lower():
                        continue
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
                    out[target_id] = ('conditional', 'installed_code_plugin_and_exact_runner')
                    break
                if target_id in out:
                    break
            if target_id in out:
                break
        if target_id not in out and uncertain:
            out[target_id] = ('unknown', 'datafusion_pipeline_path_unresolved')
    return out
