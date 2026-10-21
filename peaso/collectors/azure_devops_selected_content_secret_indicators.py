"""Unregistered, default-off named DevOps content reads; no content cache or writes."""
import base64
from peaso.secret_evidence import scan_with_source, source_context, target_source

from copy import deepcopy
import hashlib
import http.client
import json
import re
import time
from urllib.parse import urlencode
from uuid import uuid4

from peaso.azure_devops_git_policy import normalize, UUID, ORG
from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint, redact_matches

KIND = 'azure_devops_selected_content'
CHECK = 'azure.review.devops.selected_content_secret_indicators'
OPTION = 'selected_azure_devops_content'
MARKER = 'SelectedDevOpsContentSecretIndicators'
SCHEMA = 'selected-devops-content-v1'
HOST = 'dev.azure.com'
MAX_TARGETS = 8
MAX_CALLS = 24
MAX_WIRE = 2 * 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
MAX_CONTENT = 256 * 1024
MAX_PARTS = 33
MAX_SECONDS = 120
SHA = r'[0-9a-f]{40}'


class Incomplete(ValueError):
    pass


def enabled(options):
    return (options.get('content_secret_scans') is True and
            isinstance(options.get('_content_secret_scan_kinds'), list) and
            KIND in options['_content_secret_scan_kinds'])


def path_valid(path):
    return (isinstance(path, str) and 1 < len(path.encode('utf-8')) <= 1024
            and path.startswith('/') and not path.endswith('/')
            and not any(c in path for c in ('\\', '\x00', '%'))
            and not any(ord(c) < 32 or ord(c) == 127 for c in path)
            and all(p not in ('', '.', '..') for p in path[1:].split('/')))


def selected_targets(options, scopes, auth):
    if not isinstance(options, dict) or ('content_secret_scans' in options and type(options['content_secret_scans']) is not bool):
        raise Incomplete('invalid_selection')
    if OPTION not in options and not enabled(options):
        return []
    bindings = normalize(options, auth)
    targets = options.get(OPTION)
    if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS:
        raise Incomplete('invalid_selection')
    seen = set()
    for target in targets:
        common = {'surface', 'scope', 'organization', 'project_id', 'commit'}
        if not isinstance(target, dict) or target.get('surface') not in ('git_file', 'pipeline'):
            raise Incomplete('invalid_selection')
        extra = {'repository_id', 'path'} if target['surface'] == 'git_file' else {'pipeline_id', 'definition_revision'}
        if set(target) != common | extra:
            raise Incomplete('invalid_selection')
        scope = target['scope']; org = target['organization']; pid = target['project_id']
        if (not isinstance(scope, str) or scope not in scopes or scope not in bindings
                or bindings[scope]['organization'] != org or pid not in bindings[scope]['project_ids']
                or not isinstance(target['commit'], str) or not re.fullmatch(SHA, target['commit'])):
            raise Incomplete('invalid_selection')
        if target['surface'] == 'git_file':
            if (not isinstance(target['repository_id'], str) or not re.fullmatch(UUID, target['repository_id'])
                    or target['repository_id'] != target['repository_id'].lower() or not path_valid(target['path'])):
                raise Incomplete('invalid_selection')
        elif any(type(target[k]) is not int or not 1 <= target[k] <= 2147483647 for k in extra):
            raise Incomplete('invalid_selection')
        key = json.dumps(target, sort_keys=True)
        if key in seen:
            raise Incomplete('duplicate_selection')
        seen.add(key)
    return deepcopy(targets)


def identity(target):
    return KIND + ':' + _fingerprint(json.dumps(target, sort_keys=True))


def route(target, operation, repo=None, path=None):
    prefix = '/' + target['organization']
    query = {'api-version': '7.1'}
    if operation == 'definition':
        suffix = '/' + target['project_id'] + '/_apis/build/definitions/' + str(target['pipeline_id'])
        query['revision'] = str(target['definition_revision'])
    else:
        if not isinstance(repo, str) or not re.fullmatch(UUID, repo):
            raise Incomplete('invalid_repository')
        suffix = '/' + target['project_id'] + '/_apis/git/repositories/' + repo
        if operation == 'item':
            if not path_valid(path):
                raise Incomplete('invalid_path')
            suffix += '/items'
            query.update({'path': path, 'includeContent': 'true', 'includeContentMetadata': 'true',
                'recursionLevel': 'none', 'resolveLfs': 'false', 'download': 'false', '$format': 'json',
                'versionDescriptor.version': target['commit'], 'versionDescriptor.versionType': 'commit',
                'versionDescriptor.versionOptions': 'none'})
        elif operation != 'repository':
            raise Incomplete('invalid_operation')
    return prefix + suffix + '?' + urlencode(query)


def remaining(reader, state):
    reader.check_cancelled()
    left = state['deadline'] - time.monotonic()
    if left <= 0:
        raise Incomplete('deadline')
    return min(left, 10)


def _pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise Incomplete('duplicate_field')
        out[k] = v
    return out


def _read(reader, credential, target, operation, state, receipts, repo=None, path=None):
    """Fixed-origin bounded ephemeral GET; never follows URLs returned by provider."""
    endpoint = route(target, operation, repo, path)
    remaining(reader, state)
    if state['calls'] >= MAX_CALLS:
        raise Incomplete('call_budget')
    state['calls'] += 1
    receipt = {'id': 'devops-read-' + str(len(receipts) + 1), 'identity': identity(target),
        'scope': target['scope'], 'capture': state['capture'], 'operation': operation,
        'host': HOST, 'method': 'GET', 'version': '7.1', 'request_digest': _fingerprint(endpoint),
        'bytes': 0, 'http_status': None, 'bound': False}
    receipts.append(receipt)
    connection = response = None
    try:
        token = credential['token']
        authorization = ('Bearer ' + token if credential['method'] == 'bearer' else
            'Basic ' + base64.b64encode((':' + token).encode()).decode())
        connection = http.client.HTTPSConnection(HOST, timeout=remaining(reader, state))
        connection.set_debuglevel(0)
        connection.request('GET', endpoint, body=None, headers={'Authorization': authorization,
            'Accept': 'application/json', 'Accept-Encoding': 'identity', 'Content-Length': '0'})
        del token, authorization
        response = connection.getresponse(); receipt['http_status'] = response.status
        if (response.status != 200 or response.getheader('Content-Encoding') not in (None, '', 'identity')
                or (response.getheader('Content-Type') or '').split(';')[0].strip().lower() != 'application/json'
                or response.getheader('x-ms-continuationtoken') is not None):
            raise Incomplete('native_unavailable')
        length = response.getheader('Content-Length')
        if length is not None and (not re.fullmatch('[0-9]{1,8}', length) or not 0 < int(length) <= MAX_WIRE):
            raise Incomplete('wire_budget')
        chunks = []; size = 0
        while True:
            left = remaining(reader, state)
            if getattr(connection, 'sock', None) is not None:
                connection.sock.settimeout(left)
            chunk = response.read(min(16384, MAX_WIRE - size + 1, MAX_TOTAL - state['bytes'] + 1))
            if not chunk:
                break
            size += len(chunk); state['bytes'] += len(chunk); receipt['bytes'] = size
            if size > MAX_WIRE or state['bytes'] > MAX_TOTAL:
                raise Incomplete('wire_budget')
            chunks.append(chunk)
        if length is not None and int(length) != size:
            raise Incomplete('truncated')
        raw = b''.join(chunks); del chunks
        result = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Incomplete('nonfinite')))
        del raw
        if not isinstance(result, dict) or any(k in result for k in ('nextLink', 'continuationToken')):
            raise Incomplete('native_shape')
        return result, receipt
    finally:
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()


def _yaml_complete(text):
    """Only the selected file is inspected; template/variable expansion never runs."""
    import yaml
    try:
        events = list(yaml.parse(text))
        if (len(events) > 16384 or sum(isinstance(e, yaml.DocumentStartEvent) for e in events) != 1
                or not any(isinstance(e, yaml.MappingStartEvent) for e in events)):
            return False
        depth = 0
        for event in events:
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
                if depth > 32:
                    return False
            if isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
        tokens = list(yaml.scan(text))
        if len(tokens) > 16384 or any(isinstance(t, (yaml.AliasToken, yaml.AnchorToken, yaml.TagToken)) for t in tokens):
            return False
        # Tokens suffice: no YAML objects, tags or code are constructed.
        scalars = [t.value for t in tokens if isinstance(t, yaml.ScalarToken)]
        return not any(re.search(r'(?i)(template|extends|\$\(|\$\[|\$\{\{|^group$|^repositories$)', s) for s in scalars)
    except (yaml.YAMLError, ValueError, RecursionError):
        return False


def _part(reader, state, marker, payload, label, redactions):
    if not isinstance(payload, str):
        raise Incomplete('literal_unavailable')
    data = payload.encode('utf-8')
    if not data or len(data) > MAX_CONTENT or len(marker['parts']) >= MAX_PARTS:
        raise Incomplete('content_budget')
    if sum(p['bytes'] for p in marker['parts']) + len(data) > MAX_CONTENT:
        raise Incomplete('content_budget')
    result = scan_with_source(scan_content, data, marker['identity'] + '.' + label, source={},
        timeout=remaining(reader, state) / 2, _redact_values=redactions.update)
    marker['parts'].append({'location': label, 'bytes': len(data), 'engines': deepcopy(result['engines']),
        'complete': result['complete']})
    merged = merge_leaks(marker['leaks'] + result['leaks'])
    overflow = len(merged) > 256 or sum(len(l['locations']) for l in merged) > 512
    bounded = []; locations_left = 512
    for leak in merged[:256]:
        if not locations_left:
            break
        row = deepcopy(leak); row['locations'] = row['locations'][:locations_left]
        locations_left -= len(row['locations']); bounded.append(row)
    marker['leaks'] = merge_leaks(bounded)
    if overflow:
        # Keep supported completed-engine witnesses when bounded output truncates.
        raise Incomplete('finding_budget')


def _scan(reader, request, transport, credential, target, state, receipts, redactions):
    ident = identity(target)
    marker = {'schema': SCHEMA, 'identity': ident, 'surface': target['surface'], 'scope': target['scope'],
        'capture': state['capture'], 'complete': False, 'parts': [], 'leaks': [],
        'source_requests': [], 'verification': 'not_attempted', 'source_bound': False}
    start = len(receipts)
    try:
        remaining(reader, state)
        tenant = getattr(transport, 'verified_tenant', None)
        if (not isinstance(tenant, str) or not re.fullmatch(UUID, tenant)
                or str(getattr(transport, 'tenant', '')).lower() != tenant.lower()):
            raise Incomplete('tenant_unbound')
        subscription = reader.call(request, 'https://management.azure.com' + target['scope'] + '?api-version=2022-12-01')
        if (not isinstance(subscription, dict) or str(subscription.get('id', '')).lower() != target['scope']
                or str(subscription.get('tenantId', '')).lower() != tenant.lower()):
            raise Incomplete('owner_unbound')
        del subscription
        complete = True
        if target['surface'] == 'pipeline':
            definition, proof = reader.call(_read, reader, credential, target, 'definition', state, receipts)
            process = definition.get('process'); repository = definition.get('repository')
            if (type(definition.get('id')) is not int or definition['id'] != target['pipeline_id']
                    or type(definition.get('revision')) is not int or definition['revision'] != target['definition_revision']
                    or definition.get('project', {}).get('id') != target['project_id']
                    or definition.get('project', {}).get('state') != 'wellFormed'
                    or not isinstance(process, dict) or type(process.get('type')) is not int or process['type'] != 2
                    or not isinstance(repository, dict) or repository.get('type') != 'TfsGit'
                    or not isinstance(repository.get('id'), str) or not re.fullmatch(UUID, repository['id'])):
                raise Incomplete('definition_unbound')
            repo = repository['id'].lower(); path = process.get('yamlFilename')
            # Native YAML filenames can be repository-relative. Resolve root once.
            if isinstance(path, str) and not path.startswith('/'):
                path = '/' + path
            if not path_valid(path):
                raise Incomplete('yaml_path_unavailable')
            proof['bound'] = True; marker['source_bound'] = True
            variables = definition.get('variables')
            if not isinstance(variables, dict) or len(variables) > 32:
                raise Incomplete('variables_unavailable')
            for n, (name, row) in enumerate(variables.items()):
                if not isinstance(name, str) or not isinstance(row, dict):
                    complete = False; continue
                if row.get('isSecret') is not False:
                    complete = False; continue
                value = row.get('value')
                if not isinstance(value, str) or not value or '***' in value:
                    complete = False; continue
                if any(s in value for s in ('$(', '$[', '${{')):
                    complete = False
                with source_context(**target_source(target, resource_id=ident, path='variables[' + json.dumps(name) + '].value', location_kind='configuration')):
                    _part(reader, state, marker, value, 'variable-' + str(n + 1), redactions)
            if definition.get('variableGroups') not in (None, []):
                complete = False
            del definition, variables, repository, process
        else:
            repo, path = target['repository_id'], target['path']
        metadata, proof = reader.call(_read, reader, credential, target, 'repository', state, receipts, repo)
        if (metadata.get('id') != repo or metadata.get('project', {}).get('id') != target['project_id']
                or metadata.get('project', {}).get('state') != 'wellFormed'):
            raise Incomplete('repository_unbound')
        proof['bound'] = True; del metadata
        native, proof = reader.call(_read, reader, credential, target, 'item', state, receipts, repo, path)
        text = native.get('content'); encoding = native.get('contentMetadata', {})
        if (native.get('path') != path or native.get('commitId') != target['commit']
                or native.get('gitObjectType') != 'blob' or native.get('isFolder') is not False
                or native.get('isSymLink') is not False or not isinstance(text, str)
                or not isinstance(encoding, dict) or encoding.get('isBinary') is not False
                or encoding.get('encoding') != 65001 or not isinstance(native.get('objectId'), str)
                or not re.fullmatch(SHA, native['objectId'])):
            raise Incomplete('item_unbound')
        encoded = text.encode('utf-8')
        if len(encoded) > MAX_CONTENT or hashlib.sha1(b'blob ' + str(len(encoded)).encode() + b'\0' + encoded).hexdigest() != native['objectId']:
            raise Incomplete('item_bytes_unbound')
        if encoded.startswith(b'version https://git-lfs.github.com/spec/v1'):
            raise Incomplete('lfs_excluded')
        proof['bound'] = True; marker['source_bound'] = True
        del native, encoded, encoding
        if any(reference in text for reference in ('***', '$(', '$[', '${{')):
            complete = False
        if target['surface'] == 'pipeline':
            complete = _yaml_complete(text) and complete
        with source_context(**target_source(target, resource_id=repo, path=path)):
            _part(reader, state, marker, text, 'selected-file', redactions)
        del text
        remaining(reader, state)
        marker['complete'] = complete and all(p['complete'] for p in marker['parts'])
    except Exception:
        # Provider messages/URLs/content are deliberately discarded.
        marker['complete'] = False
    marker['source_requests'] = [r['id'] for r in receipts[start:]]
    return {'id': ident, MARKER: marker, '_provenance': {'scope': target['scope'], 'capture': state['capture']}}


def collect(reader, request, transport, scopes, wanted, options, auth):
    if KIND not in wanted:
        return
    targets = selected_targets(options, scopes, auth)
    reader.devops_selected_redactions = set()
    capture = 'devops-content:' + uuid4().hex
    reader.devops_selected_metadata = {KIND + '_authorized': enabled(options), KIND + '_capture': capture,
        KIND + '_selection': {s: [identity(t) for t in targets if t['scope'] == s] for s in scopes},
        KIND + '_receipts': [], KIND + '_tenant': getattr(transport, 'verified_tenant', None)}
    if not enabled(options):
        return
    state = {'calls': 0, 'bytes': 0, 'deadline': time.monotonic() + MAX_SECONDS, 'capture': capture}
    credentials = {c['server']: c for c in auth.get('devops_credentials', [])}
    for scope in scopes:
        names = [t for t in targets if t['scope'] == scope]
        if not names:
            continue
        def fetch(names=names):
            rows = []
            for target in names:
                credential = credentials.get('https://dev.azure.com/' + target['organization'])
                if credential is None:
                    # Exact selection remains incomplete; no content is requested.
                    credential = {}
                rows.append(_scan(reader, request, transport, credential, target, state,
                    reader.devops_selected_metadata[KIND + '_receipts'], reader.devops_selected_redactions))
            yield rows
        reader.run([(KIND, scope, 'AzureDevOps', fetch)])


def final_snapshot(reader, snapshot):
    """Root hook proposal: merge safe receipts, union scrub then reseal before return."""
    from peaso.snapshot import seal
    values = getattr(reader, 'devops_selected_redactions', set())
    try:
        snapshot.setdefault('metadata', {}).update(getattr(reader, 'devops_selected_metadata', {}))
        return seal(redact_matches(snapshot, values) if values else snapshot)
    finally:
        values.clear()
