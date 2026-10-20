"""Opt-in bounded content inspection. Only metadata/categories survive the SDK boundary.

GetFile cannot limit network response size: the 1MiB limit is inspected bytes,
not transferred bytes (AWS may return up to 6MiB). No payload is cached.
Offline Kingfisher and TruffleHog detection is limited to the selected bounded content.
"""
from __future__ import annotations
import copy
import re
from .aws_user_data_secret_indicators import project

PROFILE = 'aws-code-log-content-indicators-v1'
PROJECTION_OPERATIONS = {('codecommit', op) for op in ('get_repository', 'get_branch', 'get_folder', 'get_file')} | {('logs', 'filter_log_events')}
READ_ACTIONS = PROJECTION_OPERATIONS | {('codecommit', 'list_repositories')}
SPECS = {'codecommit_repository': ('codecommit', 'list_repositories', 'repositories')}
NATIVE_IDS = {'codecommit_repository': 'repositoryName'}
MAX_BYTES, MAX_FILES, MAX_FOLDERS, MAX_MESSAGES = 1048576, 128, 128, 100
CATEGORIES = {'private_key', 'cloud_credential', 'password_assignment', 'secret'}


def _text(value, maximum=2048):
    return isinstance(value, str) and 0 < len(value) <= maximum and '\x00' not in value


def validate_request(service, operation, arguments, *, region=None, request_context=None):
    from .aws import ReadFailure
    valid = (service, operation) in PROJECTION_OPERATIONS and _text(region, 64) and isinstance(arguments, dict)
    allowed = {'get_repository': {'repositoryName'}, 'get_branch': {'repositoryName', 'branchName'},
               'get_folder': {'repositoryName', 'commitSpecifier', 'folderPath'},
               'get_file': {'repositoryName', 'commitSpecifier', 'filePath'},
               'filter_log_events': {'logGroupName', 'startTime', 'endTime', 'limit', 'nextToken'}}
    valid = valid and set(arguments) <= allowed.get(operation, set())
    if operation in ('get_file', 'filter_log_events'):
        valid = valid and isinstance(request_context, dict) and set(request_context) == {'remaining_bytes'} and type(request_context['remaining_bytes']) is int and 0 <= request_context['remaining_bytes'] <= MAX_BYTES
    elif request_context is not None:
        valid = False
    if service == 'codecommit':
        valid = valid and _text(arguments.get('repositoryName'), 100) and re.fullmatch(r'[\w.-]+', arguments['repositoryName']) is not None
        if operation == 'get_branch':
            valid = valid and _text(arguments.get('branchName'), 256)
        if operation in ('get_folder', 'get_file'):
            valid = valid and isinstance(arguments.get('commitSpecifier'), str) and re.fullmatch('[0-9a-f]{40}', arguments['commitSpecifier']) is not None
            path = arguments.get('filePath' if operation == 'get_file' else 'folderPath')
            valid = valid and _text(path) and path.startswith('/') and '..' not in path.split('/')
    elif service == 'logs':
        start, end, limit = (arguments.get(k) for k in ('startTime', 'endTime', 'limit'))
        valid = valid and _text(arguments.get('logGroupName'), 512) and type(start) is int and type(end) is int and 0 <= start < end and end-start <= 86400000 and type(limit) is int and 1 <= limit <= MAX_MESSAGES
        if 'nextToken' in arguments:
            valid = valid and _text(arguments['nextToken'], 1024)
    if not valid:
        raise ReadFailure('malformed', 'content_profile_arguments_invalid')


def _categories(text):
    return project(text, '')['MatchedCategories']


def project_response(response, service, operation, arguments, *, request_context=None, region=None):
    """No raw content, response metadata or arbitrary exception text leaves here."""
    from .aws import ReadFailure
    validate_request(service, operation, arguments, region=region, request_context=request_context)
    if not isinstance(response, dict):
        raise ReadFailure('malformed', 'content_response_shape')
    binding = {'service': service, 'operation': operation, 'region': region, 'arguments': copy.deepcopy(arguments), 'context': copy.deepcopy(request_context)}
    try:
        if operation == 'get_repository':
            row = response['repositoryMetadata']
            value = {k: row[k] for k in ('repositoryName', 'Arn', 'accountId', 'defaultBranch')}
            if 'repositoryId' in row:
                value['repositoryId'] = row['repositoryId']
            if any(not _text(v) for v in value.values()) or value['repositoryName'] != arguments['repositoryName']:
                raise ValueError()
        elif operation == 'get_branch':
            value = {k: response['branch'][k] for k in ('branchName', 'commitId')}
            if value['branchName'] != arguments['branchName'] or re.fullmatch('[0-9a-f]{40}', value['commitId']) is None:
                raise ValueError()
        elif operation == 'get_folder':
            if response['commitId'] != arguments['commitSpecifier'] or response['folderPath'] != arguments['folderPath']:
                raise ValueError()
            value = {'files': [], 'folders': []}
            for source, target in (('files', 'files'), ('subFolders', 'folders')):
                rows = response.get(source, [])
                if not isinstance(rows, list) or len(rows) > 10000:
                    raise ValueError()
                for row in rows:
                    path = row['absolutePath']
                    if not _text(path) or not path.startswith('/') or '..' in path.split('/') or path == arguments['folderPath'] or path.rsplit('/', 1)[0] != arguments['folderPath'].rstrip('/'):
                        raise ValueError()
                    value[target].append(path)
            value['unsupported_entries'] = bool(response.get('symbolicLinks') or response.get('subModules'))
        elif operation == 'get_file':
            if response['commitId'] != arguments['commitSpecifier'] or response['filePath'] != arguments['filePath']:
                raise ValueError()
            payload = response['fileContent']
            if not isinstance(payload, bytes) or type(response['fileSize']) is not int or len(payload) != response['fileSize']:
                raise ValueError()
            value = {'size': len(payload), 'inspected_bytes': len(payload) if len(payload) <= request_context['remaining_bytes'] else 0, 'categories': [], 'readable': len(payload) <= request_context['remaining_bytes']}
            if value['readable']:
                try:
                    text = payload.decode('utf-8')
                    if any(ord(char) < 32 and char not in '\t\r\n' for char in text):
                        raise UnicodeError()
                    from peaso.secret_scanning import scan_content
                    outcome = scan_content(payload, arguments['filePath'])
                    value.update(leaks=outcome['leaks'], scanner_complete=outcome['complete'])
                    value['categories'] = sorted(set(_categories(text)) | ({'secret'} if outcome['leaks'] else set()))
                except UnicodeError:
                    value['readable'] = False
        else:
            events = response['events']
            if not isinstance(events, list) or len(events) > arguments['limit']:
                raise ValueError()
            value = {'events': [], 'nextToken': response.get('nextToken')}
            if value['nextToken'] is not None and not _text(value['nextToken'], 1024):
                raise ValueError()
            remaining = request_context['remaining_bytes']
            for row in events:
                timestamp, message = row['timestamp'], row['message']
                if type(timestamp) is not int or not arguments['startTime'] <= timestamp < arguments['endTime'] or not isinstance(message, str):
                    raise ValueError()
                size = len(message.encode('utf-8'))
                readable = size <= remaining
                from peaso.secret_scanning import scan_content
                outcome = scan_content(message.encode('utf-8'), 'log-message') if readable else {'leaks': [], 'complete': False}
                value['events'].append({'timestamp': timestamp, 'size': size, 'readable': readable,
                    'leaks': outcome['leaks'], 'scanner_complete': outcome['complete'],
                    'categories': sorted(set(_categories(message)) | ({'secret'} if outcome['leaks'] else set())) if readable else []})
                if readable:
                    remaining -= size
        return {'binding': binding, 'value': value}
    except (KeyError, TypeError, ValueError, UnicodeError):
        raise ReadFailure('malformed', 'content_response_invalid') from None


def _call(requests, session, region, service, operation, *, remaining_bytes=None, **arguments):
    context = {'remaining_bytes': remaining_bytes} if remaining_bytes is not None else None
    validate_request(service, operation, arguments, region=region, request_context=context)
    value = requests.call(session, service, region, operation, _metadata_profile=PROFILE, _projection_context=context, **arguments)
    expected = {'service': service, 'operation': operation, 'region': region, 'arguments': arguments, 'context': context}
    if not isinstance(value, dict) or value.get('binding') != expected or not isinstance(value.get('value'), dict):
        raise ValueError('content_projection_binding_invalid')
    return value['value']


def _base(item, region, scope):
    return {'profile': PROFILE, 'collection_status': 'not_collected', 'scope': scope, 'region': region, 'complete': False,
            'records': [], 'file_requests': 0, 'inspected_bytes': 0, 'errors': [], 'identity': item.get('Arn') or item.get('arn')}


def _failure(scan, exc):
    from .aws import _failure as failure
    info = failure(exc)
    # Never retain arbitrary exception messages, request IDs or SDK response data.
    status = 'malformed' if isinstance(exc, (ValueError, TypeError, KeyError)) else info.status
    scan['errors'].append({'status': status, 'code': 'content_read_incomplete'})
    scan['collection_status'] = 'partial' if scan['records'] else status
    return scan


def scan_repository(requests, session, region, item):
    scan = _base(item, region, 'bounded_default_commit_files')
    if getattr(requests, 'content_secret_scans', False) is not True:
        return scan
    try:
        name = item['repositoryName']
        repo = _call(requests, session, region, 'codecommit', 'get_repository', repositoryName=name)
        arn = repo['Arn']
        if re.fullmatch(r'arn:[a-z0-9-]+:codecommit:' + re.escape(region) + r':\d{12}:' + re.escape(name), arn) is None or repo['accountId'] != arn.split(':')[4] or item.get('Arn', arn) != arn:
            raise ValueError()
        if 'repositoryId' in item and item['repositoryId'] != repo.get('repositoryId'):
            raise ValueError()
        scan.update(identity=arn, repository=name, account_id=repo['accountId'], branch=repo['defaultBranch'])
        branch = _call(requests, session, region, 'codecommit', 'get_branch', repositoryName=name, branchName=scan['branch'])
        commit = scan['commit'] = branch['commitId']
        pending, seen, paths, incomplete = ['/'], set(), set(), False
        while pending and len(seen) < MAX_FOLDERS:
            folder = pending.pop(0)
            if folder in seen:
                raise ValueError()
            seen.add(folder)
            row = _call(requests, session, region, 'codecommit', 'get_folder', repositoryName=name, commitSpecifier=commit, folderPath=folder)
            incomplete |= row['unsupported_entries']
            pending.extend(row['folders'])
            for path in row['files']:
                if path in paths:
                    raise ValueError()
                paths.add(path)
                if scan['file_requests'] >= MAX_FILES or scan['inspected_bytes'] >= MAX_BYTES:
                    incomplete = True
                    continue
                try:
                    scan['file_requests'] += 1
                    content = _call(requests, session, region, 'codecommit', 'get_file', repositoryName=name, commitSpecifier=commit, filePath=path, remaining_bytes=MAX_BYTES-scan['inspected_bytes'])
                    readable = content['readable'] and scan['inspected_bytes'] + content['size'] <= MAX_BYTES
                    scan['inspected_bytes'] += content['inspected_bytes']
                    scan['records'].append({'path': path, 'size': content['size'], 'inspected_bytes': content['inspected_bytes'], 'readable': readable, 'categories': content['categories'] if readable else [], 'leaks': content.get('leaks', []), 'scanner_complete': content.get('scanner_complete', False)})
                    incomplete |= not readable or not content.get('scanner_complete', False)
                except Exception as exc:
                    _failure(scan, exc)
                    incomplete = True
        scan['complete'] = not (pending or incomplete or scan['errors'])
        scan['collection_status'] = 'collected' if scan['complete'] else 'partial'
        return scan
    except Exception as exc:
        return _failure(scan, exc)


def scan_logs(requests, session, region, item):
    scan = _base(item, region, 'bounded_log_window')
    if getattr(requests, 'content_secret_scans', False) is not True:
        return scan
    try:
        name = item['logGroupName']
        arn = item.get('arn') or item.get('logGroupArn')
        if not isinstance(arn, str) or re.fullmatch(r'arn:[a-z0-9-]+:logs:' + re.escape(region) + r':\d{12}:log-group:' + re.escape(name) + r'(?::\*)?', arn) is None:
            raise ValueError()
        end = int(requests.observed_at.timestamp() * 1000)
        if 'repositoryId' in item and item['repositoryId'] != repo.get('repositoryId'):
            raise ValueError()
        scan.update(identity=arn, group=name, account_id=arn.split(':')[4], start=end-86400000, end=end)
        token, seen = None, set()
        for _ in range(min(getattr(requests, 'max_pages', None) or 10, 10)):
            args = {'logGroupName': name, 'startTime': scan['start'], 'endTime': end, 'limit': MAX_MESSAGES-len(scan['records'])}
            if token is not None:
                args['nextToken'] = token
            row = _call(requests, session, region, 'logs', 'filter_log_events', remaining_bytes=MAX_BYTES-scan['inspected_bytes'], **args)
            for event in row['events']:
                readable = event['readable'] and scan['inspected_bytes'] + event['size'] <= MAX_BYTES
                if readable:
                    scan['inspected_bytes'] += event['size']
                scan['records'].append({'timestamp': event['timestamp'], 'size': event['size'], 'inspected_bytes': event['size'] if readable else 0, 'readable': readable, 'categories': event['categories'] if readable else [], 'leaks': event.get('leaks', []), 'scanner_complete': event.get('scanner_complete', False)})
            token = row['nextToken']
            if token is None:
                scan['complete'] = all(r['readable'] and r.get('scanner_complete', False) for r in scan['records'])
                break
            if token in seen or len(scan['records']) >= MAX_MESSAGES:
                break
            seen.add(token)
        scan['collection_status'] = 'collected' if scan['complete'] else 'partial'
        return scan
    except Exception as exc:
        return _failure(scan, exc)


def _enricher(scanner):
    def enrich(requests, session, region, items):
        output = copy.deepcopy(items)
        for item in output:
            item['ContentSecretIndicators'] = scanner(requests, session, region, item)
        return output
    return enrich


ENRICHERS = {'codecommit_repository': _enricher(scan_repository), 'log_group': _enricher(scan_logs)}
