"""Project CDAP pipeline metadata without retaining configuration contents."""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from .gcp import ReadError, _validate_iam_policy


_NAMESPACE = re.compile(r'/api/v3/namespaces')
_APPS = re.compile(r'/api/v3/namespaces/[A-Za-z0-9_-]+/apps')
_APP = re.compile(r'/api/v3/namespaces/[A-Za-z0-9_-]+/apps/[A-Za-z0-9_.-]+')
_ARTIFACTS = re.compile(r'/api/v3/namespaces/[A-Za-z0-9_-]+/artifacts')
_EXTENSIONS = re.compile(r'/api/v3/namespaces/[A-Za-z0-9_-]+/artifacts/[A-Za-z0-9_.-]+/versions/[A-Za-z0-9_.-]+/extensions')
_EXTENSION_PLUGINS = re.compile(r'/api/v3/namespaces/[A-Za-z0-9_-]+/artifacts/[A-Za-z0-9_.-]+/versions/[A-Za-z0-9_.-]+/extensions/[a-z]+')
_PROFILES = re.compile(r'/api/v3/namespaces/[A-Za-z0-9_-]+/profiles')
_NS_PREFERENCES = re.compile(r'/api/v3/namespaces/[A-Za-z0-9_-]+/preferences')
_PREFERENCES = re.compile(r'/api/v3/namespaces/[A-Za-z0-9_-]+/apps/[A-Za-z0-9_.-]+/workflows/DataPipelineWorkflow/preferences')
_SCHEDULES = re.compile(r'/api/v3/namespaces/[A-Za-z0-9_-]+/apps/[A-Za-z0-9_.-]+/schedules')
_INSTANCE = re.compile(r'projects/([^/]+)/locations/([a-z0-9-]+)/instances/([A-Za-z0-9_-]+)')
_CDAP_HOST = re.compile(r'[a-z0-9-]+-dot-[a-z0-9-]+\.datafusion\.googleusercontent\.com')


def _records(data, fields):
    rows = data.get('items')
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ReadError('malformed', 'datafusion_cdap_list_invalid')
    result = []
    for row in rows:
        projected = {field: row.get(field) for field in fields}
        if any(not isinstance(value, str) or not value for value in projected.values()):
            raise ReadError('malformed', 'datafusion_cdap_identity_invalid')
        result.append(projected)
    return {'items': result}


def _plugins(configuration):
    if isinstance(configuration, str):
        try:
            configuration = json.loads(configuration)
        except (ValueError, TypeError):
            return [], False
    if not isinstance(configuration, dict):
        return [], False
    stages = configuration.get('stages')
    post_actions = configuration.get('postActions', [])
    if not isinstance(stages, list) or not isinstance(post_actions, list):
        return [], False
    refs = []
    complete = True
    for stage in stages + post_actions:
        if not isinstance(stage, dict) or not isinstance(stage.get('plugin'), dict):
            complete = False
            continue
        plugin = stage['plugin']
        artifact = plugin.get('artifact')
        if (not isinstance(artifact, dict)
                or any(not isinstance(artifact.get(key), str) or not artifact[key]
                       for key in ('name', 'version', 'scope'))
                or artifact['scope'].upper() not in ('USER', 'SYSTEM')):
            complete = False
            continue
        refs.append({'name': artifact['name'], 'version': artifact['version'],
                     'scope': artifact['scope'].upper(),
                     'pluginName': plugin.get('name') if isinstance(plugin.get('name'), str) else None,
                     'pluginType': plugin.get('type') if isinstance(plugin.get('type'), str) else None})
    return refs, complete


def _profiles(data):
    rows = data.get('items')
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ReadError('malformed', 'datafusion_profile_list_invalid')
    result = []
    for row in rows:
        if any(not isinstance(row.get(key), str) or not row[key]
               for key in ('name', 'scope', 'status')):
            raise ReadError('malformed', 'datafusion_profile_identity_invalid')
        provisioner = row.get('provisioner')
        if (not isinstance(provisioner, dict)
                or not isinstance(provisioner.get('name'), str)
                or not isinstance(provisioner.get('properties'), list)):
            raise ReadError('malformed', 'datafusion_profile_provisioner_invalid')
        properties = {}
        for prop in provisioner['properties']:
            if not isinstance(prop, dict) or not isinstance(prop.get('name'), str):
                raise ReadError('malformed', 'datafusion_profile_property_invalid')
            if prop['name'] in ('serviceAccount', 'projectId'):
                if prop['name'] in properties or not isinstance(prop.get('value'), str):
                    raise ReadError('malformed', 'datafusion_profile_property_invalid')
                properties[prop['name']] = {
                    'value': prop['value'], 'isEditable': prop.get('isEditable')}
        result.append({'name': row['name'], 'scope': row['scope'].upper(),
                       'status': row['status'].upper(),
                       'provisioner': provisioner['name'],
                       'runnerServiceAccount': properties.get('serviceAccount'),
                       'projectId': properties.get('projectId')})
    return {'items': result}


def _schedules(data):
    rows = data.get('items')
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ReadError('malformed', 'datafusion_schedule_list_invalid')
    result = []
    for row in rows:
        name = row.get('name')
        if not isinstance(name, str) or not name:
            raise ReadError('malformed', 'datafusion_schedule_identity_invalid')
        program = row.get('program')
        properties = row.get('properties', {})
        if not isinstance(properties, dict):
            raise ReadError('malformed', 'datafusion_schedule_properties_invalid')
        profile = properties.get('system.profile.name')
        override = properties.get('system.profile.properties.serviceAccount')
        if (profile is not None and not isinstance(profile, str)
                or override is not None and not isinstance(override, str)):
            raise ReadError('malformed', 'datafusion_schedule_profile_invalid')
        result.append({'name': name, 'status': row.get('status'),
                       'programName': program.get('programName') if isinstance(program, dict) else None,
                       'programType': program.get('programType') if isinstance(program, dict) else None,
                       'profileName': profile, 'runnerServiceAccountOverride': override})
    return {'items': result}


def project_cdap_response(data, path):
    """Drop raw pipeline configuration and preserve exact artifact references."""
    if _NAMESPACE.fullmatch(path):
        return _records(data, ('name',))
    if _APPS.fullmatch(path):
        return _records(data, ('name',))
    if _ARTIFACTS.fullmatch(path):
        return _records(data, ('name', 'version', 'scope'))
    if _EXTENSIONS.fullmatch(path):
        rows = data.get('items')
        if not isinstance(rows, list) or any(not isinstance(row, str) or
                                               not re.fullmatch(r'[a-z]+', row) for row in rows):
            raise ReadError('malformed', 'datafusion_extension_types_invalid')
        return {'items': [{'type': row} for row in rows]}
    if _EXTENSION_PLUGINS.fullmatch(path):
        rows = data.get('items')
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ReadError('malformed', 'datafusion_extension_plugins_invalid')
        projected = []
        for row in rows:
            artifact = row.get('artifact')
            if (any(not isinstance(row.get(key), str) or not row[key]
                    for key in ('name', 'type', 'className'))
                    or not isinstance(artifact, dict)
                    or any(not isinstance(artifact.get(key), str) or not artifact[key]
                           for key in ('name', 'version', 'scope'))):
                raise ReadError('malformed', 'datafusion_extension_plugin_identity_invalid')
            projected.append({'name': row['name'], 'type': row['type'],
                              'className': row['className'],
                              'artifact': {key: artifact[key] for key in ('name', 'version', 'scope')}})
        return {'items': projected}
    if _PROFILES.fullmatch(path):
        return _profiles(data)
    if _SCHEDULES.fullmatch(path):
        return _schedules(data)
    if _PREFERENCES.fullmatch(path) or _NS_PREFERENCES.fullmatch(path):
        name = data.get('system.profile.name')
        override = data.get('system.profile.properties.serviceAccount')
        if (name is not None and not isinstance(name, str)
                or override is not None and not isinstance(override, str)):
            raise ReadError('malformed', 'datafusion_profile_preference_invalid')
        return {'profileName': name, 'runnerServiceAccountOverride': override}
    if _APP.fullmatch(path):
        name = data.get('name')
        if not isinstance(name, str) or not name:
            raise ReadError('malformed', 'datafusion_cdap_app_identity_invalid')
        refs, complete = _plugins(data.get('configuration', data.get('config')))
        programs = data.get('programs')
        workflow = (any(isinstance(program, dict)
                        and str(program.get('type', '')).lower() == 'workflow'
                        and program.get('name') == 'DataPipelineWorkflow'
                        for program in programs) if isinstance(programs, list) else None)
        return {'name': name, 'pluginArtifacts': refs,
                'pluginReferencesComplete': complete,
                'hasDataPipelineWorkflow': workflow}
    raise ReadError('unsupported', 'datafusion_cdap_path_not_projected')


def _endpoint(value):
    try:
        parsed = urlsplit(value) if isinstance(value, str) else None
        port = parsed.port if parsed is not None else None
    except ValueError:
        raise ReadError('malformed', 'datafusion_api_endpoint_invalid') from None
    if (parsed is None or parsed.scheme != 'https' or port not in (None, 443)
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path.rstrip('/') != '/api' or not _CDAP_HOST.fullmatch(parsed.hostname or '')):
        raise ReadError('malformed', 'datafusion_api_endpoint_invalid')
    return 'https://' + parsed.hostname + '/api'


def _project(collector, scope, observed):
    project_id = scope.split('/', 1)[1]
    if observed == project_id:
        return
    binding = collector._data_project_binding(scope, require_alias=True)
    if observed not in {binding['project_id'], binding['project_number']}:
        raise ReadError('malformed', 'datafusion_foreign_project')


def _cdap_pages(collector, endpoint, suffix, scope, *, single=False, params=None):
    url = endpoint + '/v3/namespaces' + suffix
    options = dict(params or {})
    collector.transport.datafusion_cdap_reads[url] = (scope, options)
    yield from collector.pages(url, scope, params=options, page_size_key=None, single=single)


def _iam_policy(collector, resource, scope):
    url = 'https://datafusion.googleapis.com/v1beta1/' + resource + ':getIamPolicy'
    policies = []
    for rows, request_id in collector.pages(url, scope, single=True,
                                             params={'options.requestedPolicyVersion': 3}):
        for row in rows:
            validated = _validate_iam_policy(row)
            policies.append({'bindings': validated.get('bindings', []),
                             'version': validated.get('version', 1)})
        yield policies, request_id
    if len(policies) != 1:
        raise ReadError('malformed', 'datafusion_iam_policy_invalid')


def scope_jobs(collector, scope):
    if 'datafusion_privesc_instance' not in collector.needed or not scope.startswith('projects/'):
        return []

    def fetch():
        seen_instances = set()
        url = 'https://datafusion.googleapis.com/v1/' + scope + '/locations/-/instances'
        for page, request_id in collector.pages(url, scope, key='instances'):
            yield [], request_id
            for instance in page:
                name = instance.get('name')
                match = _INSTANCE.fullmatch(name) if isinstance(name, str) else None
                if not match:
                    raise ReadError('malformed', 'datafusion_instance_identity_invalid')
                _project(collector, scope, match[1])
                canonical = scope + '/locations/' + match[2] + '/instances/' + match[3]
                if canonical in seen_instances:
                    raise ReadError('malformed', 'datafusion_instance_duplicate')
                seen_instances.add(canonical)
                state = instance.get('state')
                if not isinstance(state, str):
                    raise ReadError('malformed', 'datafusion_instance_state_invalid')
                service_account = instance.get('dataprocServiceAccount')
                if (service_account is not None and (not isinstance(service_account, str)
                        or not (re.fullmatch(r'[^@\s]+@[^@\s]+\.iam\.gserviceaccount\.com',
                                             service_account)
                                or re.fullmatch(r'[0-9]+-compute@developer\.gserviceaccount\.com',
                                                service_account)))):
                    raise ReadError('malformed', 'datafusion_dataproc_identity_invalid')
                rbac = instance.get('enableRbac')
                if rbac is not None and type(rbac) is not bool:
                    raise ReadError('malformed', 'datafusion_rbac_mode_invalid')
                result = {'name': canonical, 'state': state,
                          'dataprocServiceAccount': service_account,
                          'enableRbac': rbac, 'namespaces': []}
                if state != 'RUNNING':
                    yield [result], request_id
                    continue
                for policies, policy_request in _iam_policy(collector, canonical, scope):
                    yield [], policy_request
                    if policies:
                        result['iamPolicy'] = policies[0]
                endpoint = _endpoint(instance.get('apiEndpoint'))
                namespaces = []
                for rows, cdap_request in _cdap_pages(collector, endpoint, '', scope):
                    yield [], cdap_request
                    namespaces.extend(rows)
                seen_namespaces = set()
                for namespace in namespaces:
                    ns = namespace['name']
                    if not re.fullmatch(r'[A-Za-z0-9_-]+', ns) or ns in seen_namespaces:
                        raise ReadError('malformed', 'datafusion_namespace_identity_invalid')
                    seen_namespaces.add(ns)
                    if ns == 'system':
                        continue
                    namespace_policy = None
                    if rbac is True:
                        for policies, policy_request in _iam_policy(
                                collector, canonical + '/namespaces/' + ns, scope):
                            yield [], policy_request
                            if policies:
                                namespace_policy = policies[0]
                    apps = []
                    for rows, cdap_request in _cdap_pages(collector, endpoint, '/' + ns + '/apps', scope):
                        yield [], cdap_request
                        apps.extend(rows)
                    artifacts = []
                    for rows, cdap_request in _cdap_pages(collector, endpoint, '/' + ns + '/artifacts', scope):
                        yield [], cdap_request
                        artifacts.extend(rows)
                    pipeline_plugins = []
                    for artifact in artifacts:
                        if artifact['name'] != 'cdap-data-pipeline':
                            continue
                        if (not re.fullmatch(r'[A-Za-z0-9_.-]+', artifact['version'])
                                or artifact['scope'] not in ('SYSTEM', 'USER')):
                            raise ReadError('malformed', 'datafusion_pipeline_artifact_invalid')
                        parent = ('/' + ns + '/artifacts/cdap-data-pipeline/versions/'
                                  + artifact['version'] + '/extensions')
                        extension_types = []
                        for rows, cdap_request in _cdap_pages(
                                collector, endpoint, parent, scope,
                                params={'scope': artifact['scope'].lower()}):
                            yield [], cdap_request
                            extension_types.extend(row['type'] for row in rows)
                        for plugin_type in set(extension_types) & {
                                'action', 'postaction', 'sparkcompute', 'transform'}:
                            for rows, cdap_request in _cdap_pages(
                                    collector, endpoint, parent + '/' + plugin_type, scope,
                                    params={'scope': artifact['scope'].lower()}):
                                yield [], cdap_request
                                if any(row['type'] != plugin_type for row in rows):
                                    raise ReadError('malformed', 'datafusion_plugin_type_conflict')
                                pipeline_plugins.extend({**row, 'parentVersion': artifact['version'],
                                                         'parentScope': artifact['scope']} for row in rows)
                    profiles = []
                    for rows, cdap_request in _cdap_pages(
                            collector, endpoint, '/' + ns + '/profiles', scope,
                            params={'includeSystem': 'true'}):
                        yield [], cdap_request
                        profiles.extend(rows)
                    default_preferences = []
                    for rows, cdap_request in _cdap_pages(
                            collector, endpoint, '/' + ns + '/preferences', scope,
                            params={'resolved': 'true'}, single=True):
                        yield [], cdap_request
                        default_preferences.extend(rows)
                    if len(default_preferences) != 1:
                        raise ReadError('malformed', 'datafusion_namespace_preferences_invalid')
                    applications = []
                    seen_apps = set()
                    for app in apps:
                        app_name = app['name']
                        if not re.fullmatch(r'[A-Za-z0-9_.-]+', app_name) or app_name in seen_apps:
                            raise ReadError('malformed', 'datafusion_app_identity_invalid')
                        seen_apps.add(app_name)
                        details = []
                        for rows, cdap_request in _cdap_pages(
                                collector, endpoint, '/' + ns + '/apps/' + app_name, scope,
                                single=True):
                            yield [], cdap_request
                            details.extend(rows)
                        if len(details) != 1 or details[0].get('name') != app_name:
                            raise ReadError('malformed', 'datafusion_app_details_invalid')
                        if details[0].get('hasDataPipelineWorkflow') is True:
                            preferences = []
                            for rows, cdap_request in _cdap_pages(
                                    collector, endpoint, '/' + ns + '/apps/' + app_name
                                    + '/workflows/DataPipelineWorkflow/preferences', scope,
                                    params={'resolved': 'true'}, single=True):
                                yield [], cdap_request
                                preferences.extend(rows)
                            if len(preferences) != 1:
                                raise ReadError('malformed', 'datafusion_app_preferences_invalid')
                            schedules = []
                            for rows, cdap_request in _cdap_pages(
                                    collector, endpoint, '/' + ns + '/apps/' + app_name
                                    + '/schedules', scope):
                                yield [], cdap_request
                                schedules.extend(rows)
                            enabled = []
                            for rows, cdap_request in _cdap_pages(
                                    collector, endpoint, '/' + ns + '/apps/' + app_name
                                    + '/schedules', scope,
                                    params={'schedule-status': 'SCHEDULED'}):
                                yield [], cdap_request
                                enabled.extend(rows)
                            schedule_names = [schedule['name'] for schedule in schedules]
                            enabled_names = [schedule['name'] for schedule in enabled]
                            if (len(schedule_names) != len(set(schedule_names))
                                    or len(enabled_names) != len(set(enabled_names))
                                    or not set(enabled_names) <= set(schedule_names)):
                                raise ReadError('malformed', 'datafusion_schedule_status_conflict')
                            schedules = [{**schedule, 'enabled': schedule['name'] in enabled_names}
                                         for schedule in schedules]
                            applications.append({**details[0], 'workflowProfile': preferences[0],
                                                 'schedules': schedules})
                        else:
                            applications.append({**details[0], 'workflowProfile': None,
                                                 'schedules': []})
                    result['namespaces'].append({'name': ns, 'applications': applications,
                                                 'artifacts': artifacts, 'profiles': profiles,
                                                 'pipelinePlugins': pipeline_plugins,
                                                 'defaultProfile': default_preferences[0],
                                                 'iamPolicy': namespace_policy})
                yield [result], request_id

    return [('datafusion_privesc_instance', scope, 'datafusion', fetch)]


def collect(collector):
    collector.run_jobs([job for scope in collector.scopes for job in scope_jobs(collector, scope)])
