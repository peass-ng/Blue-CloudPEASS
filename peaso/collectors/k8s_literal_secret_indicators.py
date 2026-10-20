"""Default-off exact Kubernetes GETs; native literal content never enters snapshots.

The configured SDK's authenticated TLS pool is reused, but SDK deserialization
(and its last_response / exception-body retention) is deliberately bypassed.
"""
from copy import deepcopy
import base64
import json
import re
import time
from urllib.parse import urlsplit
from peaso.secret_scanning import scan_content, merge_leaks, redact_matches, _fingerprint

KIND = 'k8s_selected_literals'
CHECK = 'k8s.review.selected_literals.secret_indicators'
OPTION = 'selected_k8s_literal_resources'
MARKER = 'SelectedKubernetesLiteralSecretIndicators'
SCHEMA = 'k8s-selected-literal-secrets-v1'
NATIVE_KINDS = {
    'Pod': ('v1', 'pods', ('spec',)),
    'ConfigMap': ('v1', 'configmaps', None),
    'Deployment': ('apps/v1', 'deployments', ('spec', 'template', 'spec')),
    'DaemonSet': ('apps/v1', 'daemonsets', ('spec', 'template', 'spec')),
    'StatefulSet': ('apps/v1', 'statefulsets', ('spec', 'template', 'spec')),
    'ReplicaSet': ('apps/v1', 'replicasets', ('spec', 'template', 'spec')),
    'Job': ('batch/v1', 'jobs', ('spec', 'template', 'spec')),
    'CronJob': ('batch/v1', 'cronjobs', ('spec', 'jobTemplate', 'spec', 'template', 'spec')),
    'ReplicationController': ('v1', 'replicationcontrollers', ('spec', 'template', 'spec')),
    'PodTemplate': ('v1', 'podtemplates', ('template', 'spec')),
}
MAX_WIRE = 2 * 1024 * 1024
MAX_CONTENT = 256 * 1024
MAX_VALUE = 65536
MAX_TOTAL = 8 * 1024 * 1024
MAX_SECONDS = 60
MAX_LITERALS = 512
MAX_LEAKS = 256
MAX_LOCATIONS = 512
_NAMESPACE = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
_NAME = re.compile(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z')


class Incomplete(ValueError):
    """Only constant error codes; never native text or selected resource names."""


def enabled(options):
    return (options.get('content_secret_scans') is True
        and isinstance(options.get('_content_secret_scan_kinds'), list)
        and KIND in options['_content_secret_scan_kinds'])


def selected_targets(options, scopes):
    if (not isinstance(options, dict) or ('content_secret_scans' in options
            and type(options['content_secret_scans']) is not bool)):
        raise Incomplete('invalid_selection')
    if OPTION not in options and not enabled(options):
        return []
    targets = options.get(OPTION)
    if (not isinstance(scopes, list) or not scopes or len(set(scopes)) != len(scopes)
            or (scopes != ['*'] and any(not isinstance(s, str) or not _NAMESPACE.fullmatch(s) for s in scopes))
            or not isinstance(targets, list) or not 1 <= len(targets) <= 8):
        raise Incomplete('invalid_selection')
    seen = set()
    clusters = set()
    for target in targets:
        if (not isinstance(target, dict) or set(target) != {'cluster_id', 'namespace', 'kind', 'name'}
                or not isinstance(target['cluster_id'], str) or not 1 <= len(target['cluster_id']) <= 512
                or any(ord(c) < 33 or ord(c) > 126 for c in target['cluster_id'])
                or not isinstance(target['kind'], str) or target['kind'] not in NATIVE_KINDS
                or not isinstance(target['namespace'], str) or not _NAMESPACE.fullmatch(target['namespace'])
                or (scopes != ['*'] and target['namespace'] not in scopes)
                or not isinstance(target['name'], str) or not _NAME.fullmatch(target['name'])
                or any(not _NAMESPACE.fullmatch(part) for part in target['name'].split('.'))):
            raise Incomplete('invalid_selection')
        key = json.dumps(target, sort_keys=True, separators=(',', ':'))
        if key in seen:
            raise Incomplete('duplicate_selection')
        seen.add(key)
        clusters.add(target['cluster_id'])
    if len(clusters) != 1:
        raise Incomplete('conflicting_cluster_selection')
    return deepcopy(targets)


def identity(target):
    return KIND + ':' + _fingerprint(json.dumps(target, sort_keys=True, separators=(',', ':')))


def _path(target):
    version, plural, _ = NATIVE_KINDS[target['kind']]
    prefix = '/api/v1' if version == 'v1' else '/apis/' + version
    return prefix + '/namespaces/' + target['namespace'] + '/' + plural + '/' + target['name']


def _remaining(reader, state):
    reader.check_cancelled()
    left = state['deadline'] - time.monotonic()
    if left <= 0:
        raise Incomplete('deadline_exceeded')
    return min(left, 10)


def _pairs(pairs):
    value = {}
    for key, member in pairs:
        if key in value:
            raise Incomplete('duplicate_native_field')
        value[key] = member
    return value


def _read(reader, api, target, state):
    from .k8s import _BoundedPool
    client = getattr(getattr(api, 'api', api), 'api_client', None)
    pool = getattr(getattr(client, 'rest_client', None), 'pool_manager', None)
    host = getattr(getattr(client, 'configuration', None), 'host', None)
    if (not isinstance(pool, _BoundedPool) or not pool.server or not isinstance(host, str)
            or urlsplit(host) != pool.server or not callable(getattr(client, 'update_params_for_auth', None))):
        raise Incomplete('bounded_native_transport_required')
    path = _path(target)
    if path not in pool.literal_paths:
        raise Incomplete('unselected_native_path')
    headers = dict(getattr(client, 'default_headers', {}) or {})
    headers.update({'Accept': 'application/json', 'Accept-Encoding': 'identity'})
    query = []
    client.update_params_for_auth(headers, query, ['BearerToken'])
    if query:
        raise Incomplete('query_auth_unsupported')
    timeout = _remaining(reader, state)
    response = None
    try:
        # reader.call counts one attempt; HTTP failure is inspected here without
        # SDK exception-body reads, automatic retries or redirect following.
        def native_request():
            if state['calls'] >= 16:
                raise Incomplete('native_call_limit')
            state['calls'] += 1
            try:
                return pool.request('GET', host.rstrip('/') + path, headers=headers,
                    preload_content=False, decode_content=False, timeout=timeout)
            except Exception:
                raise Incomplete('native_transport_unavailable') from None
        response = reader.call(native_request)
        if getattr(response, 'status', None) != 200:
            raise Incomplete('native_get_denied' if getattr(response, 'status', None) in (401, 403) else 'native_get_unavailable')
        encoding = response.headers.get('Content-Encoding', 'identity')
        content_type = response.headers.get('Content-Type', '').split(';', 1)[0].lower()
        if encoding != 'identity' or content_type != 'application/json':
            raise Incomplete('unsupported_native_response')
        length = response.headers.get('Content-Length')
        if length is not None and (not isinstance(length, str) or not length.isdecimal()
                or not 1 <= int(length) <= MAX_WIRE):
            raise Incomplete('native_byte_limit')
        chunks, count = [], 0
        while True:
            _remaining(reader, state)
            chunk = response.read(min(16384, MAX_WIRE + 1 - count))
            if not isinstance(chunk, bytes):
                raise Incomplete('malformed_native_stream')
            if not chunk:
                break
            count += len(chunk)
            state['bytes'] += len(chunk)
            if count > MAX_WIRE or state['bytes'] > MAX_TOTAL:
                raise Incomplete('native_byte_limit')
            chunks.append(chunk)
        if not count or (length is not None and count != int(length)):
            raise Incomplete('truncated_native_response')
        document = json.loads(b''.join(chunks).decode('utf-8'), object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Incomplete('non_json_number')))
        if not isinstance(document, dict):
            raise Incomplete('malformed_native_response')
        return document, count
    finally:
        if response is not None:
            response.close()
            release = getattr(response, 'release_conn', None)
            if callable(release):
                release()


def _extract(document, target):
    meta = document.get('metadata')
    if (document.get('apiVersion') != NATIVE_KINDS[target['kind']][0] or document.get('kind') != target['kind']
            or any(k in document for k in ('continue', 'nextLink', 'items', 'partial', '_partial',
                'hasMore', 'continuationToken', 'remainingItemCount', '_coverage'))
            or not isinstance(meta, dict) or any(k in meta for k in ('continue', 'remainingItemCount', '_partial', '_coverage'))
            or meta.get('name') != target['name']
            or meta.get('namespace') != target['namespace'] or meta.get('deletionTimestamp') is not None
            or any(not isinstance(meta.get(k), str) or not 1 <= len(meta[k]) <= 253
                or any(ord(c) < 33 or ord(c) > 126 for c in meta[k]) for k in ('uid', 'resourceVersion'))):
        raise Incomplete('native_identity_unresolved')
    # The opaque UID/resourceVersion are compared exactly, never interpreted as
    # numbers or exported in plaintext. Names and keys are scanned as literals
    # too, so a detected value embedded in identity cannot survive elsewhere.
    values = [target['cluster_id'], meta['namespace'], meta['name'], meta['uid'], meta['resourceVersion']]
    literal_count, references = 0, 0
    def add(value, *, literal=False):
        nonlocal literal_count
        if not isinstance(value, str) or '\x00' in value or len(value.encode('utf-8')) > MAX_VALUE:
            raise Incomplete('unsupported_literal')
        values.append(value)
        if literal and value:
            literal_count += 1
        if literal_count > MAX_LITERALS or len(values) > MAX_LITERALS * 4:
            raise Incomplete('literal_count_limit')
    if target['kind'] == 'ConfigMap':
        if any(k in document and not isinstance(document[k], dict) for k in ('data', 'binaryData')):
            raise Incomplete('malformed_configmap')
        data, binary = document.get('data', {}), document.get('binaryData', {})
        if set(data).intersection(binary) or len(data) + len(binary) > MAX_LITERALS:
            raise Incomplete('ambiguous_configmap')
        for mapping in (data, binary):
            for key, value in mapping.items():
                if not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,253}', key):
                    raise Incomplete('malformed_configmap_key')
                add(key)
                if mapping is binary:
                    if not isinstance(value, str) or len(value) > MAX_VALUE * 2:
                        raise Incomplete('unsupported_binary_literal')
                    try:
                        value = base64.b64decode(value, validate=True).decode('utf-8')
                    except (ValueError, UnicodeError):
                        raise Incomplete('unsupported_binary_literal') from None
                add(value, literal=True)
    else:
        spec = document
        for field in NATIVE_KINDS[target['kind']][2]:
            if not isinstance(spec, dict):
                raise Incomplete('malformed_podspec_path')
            spec = spec.get(field)
        if not isinstance(spec, dict) or not isinstance(spec.get('containers'), list) or not spec['containers']:
            raise Incomplete('malformed_pod')
        seen_names = set()
        for field in ('containers', 'initContainers', 'ephemeralContainers'):
            containers = spec.get(field, [])
            if not isinstance(containers, list) or len(containers) > 128:
                raise Incomplete('malformed_containers')
            for container in containers:
                if (not isinstance(container, dict) or not isinstance(container.get('name'), str)
                        or not _NAMESPACE.fullmatch(container['name']) or container['name'] in seen_names):
                    raise Incomplete('malformed_container_identity')
                seen_names.add(container['name'])
                add(container['name'])
                for field_name in ('command', 'args'):
                    sequence = container.get(field_name, [])
                    if not isinstance(sequence, list) or len(sequence) > MAX_LITERALS:
                        raise Incomplete('malformed_command')
                    for value in sequence:
                        add(value, literal=True)
                env = container.get('env', [])
                if not isinstance(env, list) or len(env) > MAX_LITERALS:
                    raise Incomplete('malformed_environment')
                env_names = set()
                for entry in env:
                    if (not isinstance(entry, dict) or not isinstance(entry.get('name'), str)
                            or not entry['name'] or entry['name'] in env_names
                            or any(k not in ('name', 'value', 'valueFrom') for k in entry)):
                        raise Incomplete('ambiguous_environment')
                    env_names.add(entry['name'])
                    add(entry['name'])
                    if 'valueFrom' in entry:
                        source = entry['valueFrom']
                        if ('value' in entry and entry['value'] != '') or not isinstance(source, dict) or len(source) != 1:
                            raise Incomplete('ambiguous_environment_source')
                        if next(iter(source), '') not in ('secretKeyRef', 'configMapKeyRef', 'fieldRef', 'resourceFieldRef'):
                            raise Incomplete('unsupported_environment_source')
                        source_kind, reference = next(iter(source.items()))
                        if not isinstance(reference, dict):
                            raise Incomplete('malformed_environment_source')
                        if source_kind in ('secretKeyRef', 'configMapKeyRef'):
                            if (set(reference) - {'name', 'key', 'optional'}
                                    or any(not isinstance(reference.get(k), str) or not reference[k] for k in ('name', 'key'))
                                    or ('optional' in reference and type(reference['optional']) is not bool)):
                                raise Incomplete('malformed_environment_source')
                        elif source_kind == 'fieldRef':
                            if (set(reference) - {'fieldPath', 'apiVersion'}
                                    or not isinstance(reference.get('fieldPath'), str) or not reference['fieldPath']
                                    or ('apiVersion' in reference and reference['apiVersion'] != 'v1')):
                                raise Incomplete('malformed_environment_source')
                        elif (set(reference) - {'resource', 'containerName', 'divisor'}
                                or not isinstance(reference.get('resource'), str) or not reference['resource']
                                or any(not isinstance(reference[k], str) or not reference[k]
                                    for k in ('containerName', 'divisor') if k in reference)):
                            raise Incomplete('malformed_environment_source')
                        references += 1
                    elif 'value' in entry:
                        add(entry['value'], literal=True)
                env_from = container.get('envFrom', [])
                if not isinstance(env_from, list) or any(not isinstance(r, dict) or
                        len(set(r).intersection({'secretRef', 'configMapRef'})) != 1 for r in env_from):
                    raise Incomplete('malformed_environment_source')
                for reference in env_from:
                    if (set(reference) - {'prefix', 'secretRef', 'configMapRef'}
                            or ('prefix' in reference and not isinstance(reference['prefix'], str))):
                        raise Incomplete('malformed_environment_source')
                    value = reference.get('secretRef', reference.get('configMapRef'))
                    if (not isinstance(value, dict) or set(value) - {'name', 'optional'}
                            or not isinstance(value.get('name'), str) or not value['name']
                            or ('optional' in value and type(value['optional']) is not bool)):
                        raise Incomplete('malformed_environment_source')
                references += len(env_from)
    if not literal_count:
        raise Incomplete('no_nonempty_supported_literals')
    # Newline boundaries expose whole literal values to both detectors without
    # JSON escaping or expansion of Kubernetes $(VAR) substitutions.
    payload = '\n'.join(values).encode('utf-8')
    if len(payload) > MAX_CONTENT:
        raise Incomplete('literal_byte_limit')
    return payload, meta['uid'], meta['resourceVersion'], literal_count, references


def collect(reader, api, options, scopes, cluster):
    """Return safe selection metadata plus transient union-redaction callback state."""
    targets = selected_targets(options, scopes)
    authorized = enabled(options)
    metadata = {KIND + '_authorized': authorized, KIND + '_selection': {
        scope: [identity(t) for t in targets if scope == '*' or t['namespace'] == scope] for scope in scopes},
        KIND + '_receipts': [], KIND + '_cluster_binding': _fingerprint(cluster or '')}
    state = {'deadline': time.monotonic() + MAX_SECONDS, 'bytes': 0, 'calls': 0}
    matches = set()
    original_pool = None
    client = getattr(getattr(api, 'api', api), 'api_client', None)
    pool = getattr(getattr(client, 'rest_client', None), 'pool_manager', None)
    from .k8s import _BoundedPool
    if isinstance(pool, _BoundedPool):
        original_pool = pool.literal_paths
        pool.literal_paths = frozenset(_path(t) for t in targets) if authorized else frozenset()
    try:
        for scope in scopes:
            selected = [t for t in targets if scope == '*' or t['namespace'] == scope]
            rows = []
            complete = bool(authorized and selected)
            reason = 'complete' if complete else 'disabled_or_unselected'
            for target in selected if authorized else []:
                if reader.budget.max_items is not None and reader.total >= reader.budget.max_items:
                    complete, reason = False, 'resource_limit'
                    break
                ident = identity(target)
                marker = {'schema': SCHEMA, 'identity': ident, 'scope': scope, 'kind': target['kind'],
                    'complete': False, 'reason': 'unavailable', 'verification': 'not_attempted',
                    'parts': [], 'leaks': [], 'source_requests': [], 'literal_count': 0, 'reference_count': 0,
                    'cluster_binding': _fingerprint(cluster or '')}
                try:
                    if target['cluster_id'] != cluster:
                        raise Incomplete('cluster_identity_mismatch')
                    before = None
                    for ordinal in (1, 2):
                        document, byte_count = _read(reader, api, target, state)
                        extracted = _extract(document, target)
                        if before is not None and extracted != before:
                            raise Incomplete('native_object_changed')
                        before = extracted
                        ref = 'k8s-literal-read-' + str(len(metadata[KIND + '_receipts']) + 1)
                        metadata[KIND + '_receipts'].append({'id': ref, 'identity': ident, 'scope': scope,
                            'method': 'GET', 'route': 'exact_selected_native_object', 'status': 200,
                            'bytes': byte_count, 'ordinal': ordinal, 'identity_bound': True})
                        marker['source_requests'].append(ref)
                    payload, uid, version, count, references = before
                    _remaining(reader, state)
                    outcome = scan_content(payload, ident + '.literals', timeout=_remaining(reader, state) / 2,
                        _redact_values=matches.update)
                    _remaining(reader, state)
                    if (len(outcome['leaks']) > MAX_LEAKS or
                            sum(len(l['locations']) for l in outcome['leaks']) > MAX_LOCATIONS):
                        raise Incomplete('detector_output_limit')
                    marker.update(complete=outcome['complete'], reason='complete' if outcome['complete'] else 'detectors_incomplete',
                        parts=[{'part': 'literals', 'bytes': len(payload), 'engines': outcome['engines'], 'complete': outcome['complete']}],
                        leaks=merge_leaks(outcome['leaks']), literal_count=count, reference_count=references,
                        uid_binding=_fingerprint(uid), version_binding=_fingerprint(version))
                except Exception as exc:
                    # No response/error text, native path or credential reaches evidence.
                    marker['reason'] = str(exc) if isinstance(exc, Incomplete) else 'native_or_detector_unavailable'
                if not marker['complete']:
                    complete, reason = False, 'selected_content_incomplete'
                rows.append({'id': ident, MARKER: marker})
                reader.total += 1
            reader.collections.append({'type': KIND, 'scope': scope, 'service': 'kubernetes',
                'status': 'collected' if complete else 'partial' if rows else 'unknown', 'items': rows,
                **({} if complete else {'error': {'code': reason}})})
    finally:
        if original_pool is not None:
            pool.literal_paths = original_pool
    return metadata, matches


def redact_output(scopes, collections, metadata, matches):
    """Apply the union across ALL selected objects before snapshot/cache/export."""
    try:
        safe = redact_matches({'scopes': scopes, 'collections': collections, 'metadata': metadata}, matches)
        return safe['scopes'], safe['collections'], safe['metadata']
    finally:
        matches.clear()
