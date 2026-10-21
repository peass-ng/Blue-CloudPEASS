"""Exact selected ECS task revision/container environment file association."""
from copy import deepcopy
import json
import re
from uuid import uuid4
from peaso.secret_scanning import _fingerprint
from . import aws_s3_selected_source_secret_indicators as s3
from .aws_content_sdk_logging import private_sdk_logs

KIND = 'ecs_selected_environment_file_content'
CHECK = 'aws.review.ecs.selected_environment_file_secret_indicators'
OPTION = 'selected_aws_ecs_environment_files'
PROFILE = 'aws-ecs-selected-environment-file-v1'
MARKER = 'EcsSelectedEnvironmentFileSecretIndicators'
SCHEMA = 'aws-ecs-selected-environment-file-v1'
MAX_TARGETS = 4
MAX_ENVIRONMENT_FILES = 10
SPECS = {KIND: ('ecs', 'describe_task_definition', None)}
NATIVE_IDS = {KIND: 'id'}


def enabled(options):
    return options.get('content_secret_scans') is True and KIND in options.get('_content_secret_scan_kinds', ())


def selected_targets(options, scopes):
    if OPTION not in options and not enabled(options):
        return []
    targets = options.get(OPTION)
    if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS:
        raise ValueError('invalid_ecs_environment_file_selection')
    if not isinstance(scopes, list) or len(set(scopes)) != len(scopes):
        raise ValueError('invalid_ecs_environment_file_scopes')
    s3_targets = s3.selected_targets(options, scopes)
    seen = set(); seen_sources = set()
    for target in targets:
        if not isinstance(target, dict) or set(target) != {'scope', 'task_definition_arn', 'container', 'environment_file_arn'}:
            raise ValueError('invalid_ecs_environment_file_selection')
        scope = target['scope']; match = s3.SCOPE.fullmatch(scope) if isinstance(scope, str) else None
        if not match or scope not in scopes or scope.startswith(('cn-', 'us-gov-')):
            raise ValueError('invalid_ecs_environment_file_scope')
        account, region = match.groups()
        if region.startswith(('cn-', 'us-gov-')) or '-iso' in region:
            raise ValueError('unsupported_ecs_partition')
        task = target['task_definition_arn']
        if not isinstance(task, str) or not re.fullmatch(r'arn:aws:ecs:' + region + ':' + account + r':task-definition/[A-Za-z0-9_-]{1,255}:[1-9][0-9]{0,9}', task):
            raise ValueError('invalid_ecs_task_revision')
        container = target['container']
        if not isinstance(container, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,255}', container):
            raise ValueError('invalid_ecs_container')
        source = target['environment_file_arn']
        if not isinstance(source, str) or not source.startswith('arn:aws:s3:::'):
            raise ValueError('invalid_ecs_environment_file_arn')
        suffix = source[len('arn:aws:s3:::'):]
        if '/' not in suffix or not suffix.endswith('.env'):
            raise ValueError('invalid_ecs_environment_file_arn')
        bucket, key = suffix.split('/', 1)
        selected = {'scope': scope, 'bucket': bucket, 'key': key, 'format': 'text'}
        s3.parse(selected)
        source_key = json.dumps(selected, sort_keys=True)
        if selected not in s3_targets or (task, container, source) in seen or source_key in seen_sources:
            raise ValueError('ecs_environment_file_requires_exact_selected_s3_source')
        seen.add((task, container, source)); seen_sources.add(source_key)
    if KIND in options.get('_content_secret_scan_kinds', ()) and s3.KIND not in options.get('_content_secret_scan_kinds', ()):
        delegated = [source_target(t) for t in targets]
        if 'workload_referenced_source_content' in options.get('_content_secret_scan_kinds', ()):
            from .aws_workload_referenced_source_indicators import source_target as workload_source_target, OPTION as workload_option
            delegated += [workload_source_target(t) for t in options.get(workload_option, ())]
        if 'build_deployment_referenced_source_content' in options.get('_content_secret_scan_kinds',()):
            from .aws_build_deployment_referenced_source_indicators import source_target as build_source_target, OPTION as build_option
            delegated += [build_source_target(t) for t in options.get(build_option,())]
        if len(delegated) != len(s3_targets) or {json.dumps(t, sort_keys=True) for t in delegated} != {json.dumps(t, sort_keys=True) for t in s3_targets}:
            raise ValueError('ecs_environment_file_extra_s3_selection')
    return deepcopy(targets)


def identity(target):
    return KIND + ':' + _fingerprint(json.dumps(target, sort_keys=True, separators=(',', ':')))


def source_target(target):
    bucket, key = target['environment_file_arn'][len('arn:aws:s3:::'):].split('/', 1)
    return {'scope': target['scope'], 'bucket': bucket, 'key': key, 'format': 'text'}


def initialize(requests, options, scopes):
    targets = selected_targets(options, scopes)
    requests.ecs_envfile_metadata = {KIND + '_authorized': enabled(options), KIND + '_capture': 'ecs-envfile:' + uuid4().hex,
        KIND + '_selection': {scope: [identity(t) for t in targets if t['scope'] == scope] for scope in scopes}}
    requests.ecs_envfile_targets = {identity(t): t for t in targets}
    requests.ecs_envfile_calls = {}
    requests.ecs_envfile_grants = {}


def profile_call(requests, session, service, region, operation, *, _projection_context, **args):
    from .aws import ReadFailure
    context = _projection_context
    try:
        target = context['target']; ident = identity(target)
        account, own_region = s3.SCOPE.fullmatch(target['scope']).groups()
        if (requests.content_secret_scans is not True or not requests.ecs_envfile_metadata[KIND + '_authorized']
                or KIND not in requests.content_secret_scan_kinds
                or ident not in requests.ecs_envfile_metadata[KIND + '_selection'][target['scope']]
                or requests.ecs_envfile_targets[ident] != target or region != own_region
                or (service, operation, args) != ('ecs', 'describe_task_definition', {'taskDefinition': target['task_definition_arn']})):
            raise ValueError()
        requests.check_deadline()
        with requests._lock:
            if requests.ecs_envfile_calls.get(ident, 0) >= 2 or requests.max_calls is not None and requests.calls >= requests.max_calls:
                raise ReadFailure('not_collected', 'ecs_environment_file_call_bound')
            requests.ecs_envfile_calls[ident] = requests.ecs_envfile_calls.get(ident, 0) + 1; requests.calls += 1
        with private_sdk_logs():
            client = requests.client(session, 'ecs', region, _metadata_profile='aws-selected-configuration-content-v1')
            from .aws_selected_configuration_secret_indicators import validate_native_client
            validate_native_client(client, 'ecs', region)
            response = client.describe_task_definition(**args)
        return association(response, target)
    except (KeyError, AttributeError, TypeError, ValueError):
        raise ReadFailure('not_collected', 'ecs_environment_file_request_unbound') from None


def association(response, target):
    """Only exact native task/container/file metadata escapes; no environment values."""
    if not isinstance(response, dict) or 'Error' in response or '_coverage' in response:
        raise ValueError('ecs_response_shape')
    meta = response.get('ResponseMetadata', {})
    if (not isinstance(meta, dict) or type(meta.get('HTTPStatusCode')) is not int or meta['HTTPStatusCode'] != 200
            or not isinstance(meta.get('RequestId'), str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}', meta['RequestId'])):
        raise ValueError('ecs_response_unbound')
    from .aws_selected_configuration_secret_indicators import response_size
    response_size(response)
    task = response.get('taskDefinition')
    arn = target['task_definition_arn']
    if (not isinstance(task, dict) or task.get('taskDefinitionArn') != arn or task.get('status') != 'ACTIVE'
            or task.get('family') != arn.split(':task-definition/', 1)[1].rsplit(':', 1)[0]
            or type(task.get('revision')) is not int or task['revision'] != int(arn.rsplit(':', 1)[1])):
        raise ValueError('ecs_task_revision_unbound')
    rows = task.get('containerDefinitions')
    if not isinstance(rows, list) or not 1 <= len(rows) <= 32:
        raise ValueError('ecs_containers_unbound')
    names = [r.get('name') if isinstance(r, dict) else None for r in rows]
    if any(not isinstance(n, str) or not n for n in names) or len(set(names)) != len(names) or names.count(target['container']) != 1:
        raise ValueError('ecs_container_unbound')
    container = rows[names.index(target['container'])]
    files = container.get('environmentFiles')
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_ENVIRONMENT_FILES:
        raise ValueError('ecs_environment_files_unbound')
    values = []
    for row in files:
        if not isinstance(row, dict) or set(row) != {'type', 'value'} or row['type'] != 's3' or not isinstance(row['value'], str):
            raise ValueError('ecs_environment_file_shape')
        values.append(row['value'])
    if len(set(values)) != len(values) or values.count(target['environment_file_arn']) != 1:
        raise ValueError('ecs_environment_file_unbound')
    association = {'task': arn, 'status': task['status'], 'family': task['family'],
        'revision': task['revision'], 'container': container['name'], 'environment_files': values}
    return {'associated': True, 'file_count': len(files), 'request': _fingerprint(meta['RequestId']),
        'association': _fingerprint(json.dumps(association, sort_keys=True, separators=(',', ':')))}


def collect_selected(requests, session, region, caller, options, scopes):
    from .aws import ReadResult
    if not enabled(options):
        return ReadResult([], 'not_collected', {'code': 'ecs_environment_file_disabled'})
    targets = selected_targets(options, scopes)
    rows = []
    for target in targets:
        account, own_region = s3.SCOPE.fullmatch(target['scope']).groups()
        if own_region != region or not isinstance(caller, dict) or caller.get('Account') != account:
            continue
        ident = identity(target)
        marker = {'schema': SCHEMA, 'identity': ident, 'scope': target['scope'],
            'capture': requests.ecs_envfile_metadata[KIND + '_capture'], 'associated': False,
            'file_count': None, 'ecs_request': None, 'ecs_after_request': None,
            'association': None, 'association_coherent': False,
            's3_identity': s3.identity(source_target(target)), 's3_item': None, 'uncovered_files': None}
        try:
            bound = requests.call(session, 'ecs', region, 'describe_task_definition', _metadata_profile=PROFILE,
                _projection_context={'target': target}, taskDefinition=target['task_definition_arn'])
            marker['associated'] = True; marker['file_count'] = bound['file_count']
            marker['ecs_request'] = bound['request']; marker['association'] = bound['association']
            selected_in_container = sum(t['scope'] == target['scope'] and t['task_definition_arn'] == target['task_definition_arn']
                and t['container'] == target['container'] for t in targets)
            marker['uncovered_files'] = bound['file_count'] - selected_in_container
            # The transient grant exists only for this exact selected file and session.
            requests.ecs_envfile_grants[marker['s3_identity']] = (id(session), target['scope'], ident)
            try:
                s3_result = s3.collect_selected(requests, session, region, caller,
                    {s3.OPTION: [source_target(target)], 'content_secret_scans': True,
                     '_content_secret_scan_kinds': [s3.KIND]}, scopes)
                if len(s3_result.items) == 1:
                    marker['s3_item'] = s3_result.items[0]
            finally:
                requests.ecs_envfile_grants.pop(marker['s3_identity'], None)
            after = requests.call(session, 'ecs', region, 'describe_task_definition', _metadata_profile=PROFILE,
                _projection_context={'target': target}, taskDefinition=target['task_definition_arn'])
            marker['ecs_after_request'] = after['request']
            marker['association_coherent'] = (after['association'] == bound['association']
                and after['file_count'] == bound['file_count'])
        except Exception:
            pass
        finally:
            requests.ecs_envfile_grants.pop(marker['s3_identity'], None)
        rows.append({'id': ident, MARKER: marker,
            '_provenance': {'scope': target['scope'], 'capture': marker['capture']}})
    return ReadResult(rows) if rows else ReadResult([], 'not_collected', {'code': 'ecs_environment_file_scope_omitted'})
