"""Resolve the identity of an existing scheduled Data Fusion pipeline."""

from __future__ import annotations

import re

from . import inventory_status


_SA = re.compile(r'[^@\s]+@[^@\s]+\.iam\.gserviceaccount\.com')
_DEFAULT = re.compile(r'[0-9]+-compute@developer\.gserviceaccount\.com')


def _email(value):
    return isinstance(value, str) and bool(_SA.fullmatch(value) or _DEFAULT.fullmatch(value))


def resolve_runner_context(instance, namespace, app, schedule, project_numbers):
    """Return (runner email, cluster project, unresolved reason)."""
    instance_project = instance['name'].split('/')[1]
    preference = app.get('workflowProfile')
    if not isinstance(preference, dict):
        return None, None, 'datafusion_workflow_preference_unresolved'
    chosen = schedule.get('profileName') or preference.get('profileName')
    override = (schedule.get('runnerServiceAccountOverride')
                or preference.get('runnerServiceAccountOverride'))
    if chosen is None:
        if override:
            return None, None, 'datafusion_builtin_profile_override_unresolved'
        default = instance.get('dataprocServiceAccount')
        if default:
            return ((default, instance_project, None) if _email(default)
                    else (None, None, 'datafusion_instance_runner_invalid'))
        number = project_numbers.get(instance_project)
        return ((f'{number}-compute@developer.gserviceaccount.com', instance_project, None)
                if isinstance(number, str) and number.isdecimal()
                else (None, None, 'datafusion_default_runner_project_number_missing'))
    if not isinstance(chosen, str) or not re.fullmatch(r'(?:user|system):[A-Za-z0-9_.-]+', chosen):
        return None, None, 'datafusion_profile_reference_invalid'
    scope, name = chosen.split(':', 1)
    profiles = namespace.get('profiles')
    if not isinstance(profiles, list):
        return None, None, 'datafusion_profile_inventory_unresolved'
    matches = [profile for profile in profiles
               if isinstance(profile, dict) and profile.get('name') == name
               and profile.get('scope') == scope.upper()]
    if len(matches) != 1:
        return None, None, 'datafusion_profile_not_unique_or_missing'
    profile = matches[0]
    if profile.get('status') != 'ENABLED' or profile.get('provisioner') not in ('gcp-dataproc', 'dataproc'):
        return None, None, 'datafusion_profile_not_runnable'
    project_property = profile.get('projectId')
    if project_property is not None and not isinstance(project_property, dict):
        return None, None, 'datafusion_profile_project_invalid'
    project = project_property.get('value') if project_property else None
    project = project or instance_project
    if not isinstance(project, str) or not re.fullmatch(r'[a-z][a-z0-9-]*[a-z0-9]', project):
        return None, None, 'datafusion_profile_project_invalid'
    configured = profile.get('runnerServiceAccount')
    if configured is not None and not isinstance(configured, dict):
        return None, None, 'datafusion_profile_runner_invalid'
    base = configured.get('value') if configured else None
    if override:
        if not _email(override):
            return None, None, 'datafusion_runner_override_invalid'
        if override != base and (not configured or configured.get('isEditable') is not True):
            return None, None, 'datafusion_runner_override_lock_unresolved'
        return override, project, None
    if base:
        return ((base, project, None) if _email(base)
                else (None, None, 'datafusion_profile_runner_invalid'))
    number = project_numbers.get(project)
    if not isinstance(number, str) or not number.isdecimal():
        return None, None, 'datafusion_profile_project_number_missing'
    return f'{number}-compute@developer.gserviceaccount.com', project, None


def resolve_runner(instance, namespace, app, schedule, project_numbers):
    email, _, reason = resolve_runner_context(instance, namespace, app, schedule, project_numbers)
    return email, reason


def _snapshot_version(version):
    return isinstance(version, str) and bool(re.search(r'[-.]SNAPSHOT(?:[-.].*)?$', version))


def _rights(model, principal, resource, actions):
    grants = [model.check(principal, {'action': action}, resource) for action in actions]
    if any(grant is None for grant in grants):
        return 'denied'
    return ('derived' if all(grant.confidence == 'derived' for grant in grants)
            else 'uncertain')


def _possible_runner(instance, namespace, app, schedule, project_numbers, email):
    """Limit unresolved paths to identities named by the selected profile."""
    preference = app.get('workflowProfile')
    if not isinstance(preference, dict):
        return False
    chosen = schedule.get('profileName') or preference.get('profileName')
    mentioned = [schedule.get('runnerServiceAccountOverride'),
                 preference.get('runnerServiceAccountOverride')]
    instance_project = instance['name'].split('/')[1]
    if chosen is None:
        mentioned.append(instance.get('dataprocServiceAccount'))
        number = project_numbers.get(instance_project)
        if number:
            mentioned.append(f'{number}-compute@developer.gserviceaccount.com')
    elif isinstance(chosen, str) and ':' in chosen:
        scope, name = chosen.split(':', 1)
        profiles = namespace.get('profiles')
        for profile in profiles if isinstance(profiles, list) else ():
            if (not isinstance(profile, dict) or profile.get('name') != name
                    or profile.get('scope') != scope.upper()):
                continue
            runner = profile.get('runnerServiceAccount')
            if isinstance(runner, dict):
                mentioned.append(runner.get('value'))
            project = profile.get('projectId')
            project = project.get('value') if isinstance(project, dict) else None
            number = project_numbers.get(project or instance_project)
            if number:
                mentioned.append(f'{number}-compute@developer.gserviceaccount.com')
    return email.lower() in {value.lower() for value in mentioned if isinstance(value, str)}


def _namespace_possible_runner(instance, namespace, project_numbers, email):
    mentioned = [instance.get('dataprocServiceAccount')]
    profiles = namespace.get('profiles')
    for profile in profiles if isinstance(profiles, list) else ():
        if not isinstance(profile, dict):
            continue
        runner = profile.get('runnerServiceAccount')
        if isinstance(runner, dict):
            mentioned.append(runner.get('value'))
        project = profile.get('projectId')
        project = project.get('value') if isinstance(project, dict) else None
        number = project_numbers.get(project or instance['name'].split('/')[1])
        if number:
            mentioned.append(f'{number}-compute@developer.gserviceaccount.com')
    return email.lower() in {value.lower() for value in mentioned if isinstance(value, str)}


def select(model, candidates, source):
    """Link one replaceable plugin and enabled schedule to one named runner."""
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
        if not isinstance(email, str):
            continue
        uncertain = False
        for instance_name, instance in model.datafusion_instances.items():
            project = instance_name.split('/locations/', 1)[0]
            if statuses.get(project) not in ('collected', 'empty'):
                continue
            if instance.get('state') != 'RUNNING':
                continue
            namespaces = instance.get('namespaces')
            if not isinstance(namespaces, list):
                uncertain = True
                continue
            for namespace in namespaces:
                if not isinstance(namespace, dict) or not isinstance(namespace.get('name'), str):
                    uncertain = True
                    continue
                namespace_resource = instance_name + '/namespaces/' + namespace['name']
                artifacts = namespace.get('artifacts')
                applications = namespace.get('applications')
                if not isinstance(applications, list):
                    uncertain |= _namespace_possible_runner(
                        instance, namespace, project_numbers, email)
                    continue
                for app in applications:
                    if not isinstance(app, dict) or app.get('hasDataPipelineWorkflow') is not True:
                        continue
                    schedules = app.get('schedules')
                    if not isinstance(schedules, list):
                        uncertain = True
                        continue
                    for schedule in schedules:
                        if (not isinstance(schedule, dict) or schedule.get('enabled') is not True
                                or schedule.get('programType') != 'WORKFLOW'
                                or schedule.get('programName') != 'DataPipelineWorkflow'):
                            continue
                        runner, cluster_project, reason = resolve_runner_context(
                            instance, namespace, app, schedule, project_numbers)
                        if reason or not runner or not cluster_project:
                            uncertain |= _possible_runner(
                                instance, namespace, app, schedule, project_numbers, email)
                            continue
                        if runner.lower() != email.lower():
                            continue
                        if not isinstance(artifacts, list):
                            uncertain = True
                            continue
                        if app.get('pluginReferencesComplete') is not True:
                            uncertain = True
                            continue
                        refs = app.get('pluginArtifacts')
                        if not isinstance(refs, list):
                            uncertain = True
                            continue
                        for ref in refs:
                            if not isinstance(ref, dict) or ref.get('scope') != 'USER':
                                continue
                            name, version = ref.get('name'), ref.get('version')
                            if not isinstance(name, str) or not isinstance(version, str):
                                uncertain = True
                                continue
                            installed = [artifact for artifact in artifacts
                                         if isinstance(artifact, dict) and artifact.get('name') == name
                                         and artifact.get('version') == version
                                         and artifact.get('scope') == 'USER']
                            if len(installed) > 1:
                                uncertain = True
                                continue
                            actions = ['datafusion.instances.get', 'datafusion.namespaces.get',
                                       'datafusion.artifacts.create', 'datafusion.artifacts.update']
                            rights = [_rights(model, source, instance_name, actions[:1]),
                                      _rights(model, source, namespace_resource, actions[1:])]
                            if installed and not _snapshot_version(version):
                                rights.append(_rights(model, source, namespace_resource,
                                                      ('datafusion.artifacts.delete',)))
                            if 'denied' in rights:
                                continue
                            if 'uncertain' in rights:
                                uncertain = True
                                continue
                            agent_number = project_numbers.get(project.removeprefix('projects/'))
                            agent = (model.principals.get('serviceAccount:service-' + agent_number
                                     + '@gcp-sa-datafusion.iam.gserviceaccount.com')
                                     if agent_number else None)
                            sa_resource = target.attrs.get('resource')
                            if agent is None or not isinstance(sa_resource, str):
                                uncertain = True
                                continue
                            runtime = [_rights(model, agent, sa_resource,
                                               ('iam.serviceAccounts.actAs',)),
                                       _rights(model, target, instance_name,
                                               ('datafusion.instances.runtime',)),
                                       _rights(model, target, 'projects/' + cluster_project,
                                               ('dataproc.agents.create',))]
                            if 'denied' in runtime:
                                continue
                            if 'uncertain' in runtime:
                                uncertain = True
                                continue
                            out[target_id] = ('conditional', 'enabled_pipeline_uses_exact_replaceable_plugin')
                            break
                        if target_id in out:
                            break
                    if target_id in out:
                        break
                if target_id in out:
                    break
            if target_id in out:
                break
        if target_id not in out and uncertain:
            out[target_id] = ('unknown', 'datafusion_plugin_or_runner_path_unresolved')
    return out
