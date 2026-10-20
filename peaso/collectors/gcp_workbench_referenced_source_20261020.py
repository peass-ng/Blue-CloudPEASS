"""Unregistered selected v2 Workbench startup reference -> captured plain GCS source.

Uncached GETs only. Closing reads prove observed association, not executed bytes.
No delegation to another optional kind and no mutation of immutable GCS helpers.
"""
from copy import deepcopy
from datetime import datetime, timezone
import http.client
import json
import logging
import re
import threading
import time
from urllib.parse import quote, urlsplit
from uuid import uuid4

from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint, redact_matches
from . import gcp_selected_object_secret_indicators as objects
from . import gcp_git_transport as git
from . import gcp_dataproc_referenced_source_secret_indicators as reviewed
from .gcp_dataform_secret_indicators import _json

SCHEMA = 'gcp-workbench-referenced-source-20261020-v1'
MARKER = 'WorkbenchReferencedSourceSecretIndicators'
OPTION = 'selected_workbench_referenced_sources'
MAX_TARGETS, MAX_CALLS, MAX_SECONDS = 4, 36, 120
MAX_METADATA, MAX_CONTENT, MAX_TOTAL = 65536, 1048576, 8388608
MAX_LEAKS, MAX_LOCATIONS = 256, 512
SCOPE = re.compile(r'projects/([a-z][a-z0-9-]{4,28}[a-z0-9])\Z')
FIELDS = frozenset({'gceSetup.metadata.post-startup-script', 'gceSetup.metadata.startup-script-url'})
PROFILES = {
    'instance': {'kind': 'workbench_selected_referenced_source_20261020',
        'check': 'gcp.review.workbench.selected_referenced_source_secret_indicators_20261020',
        'title': 'Captured selected Workbench startup source has no detected secrets'},
}
OPERATIONS = ('project_before', 'reference_before', 'bucket_before', 'latest_before', 'content',
              'latest_after', 'reference_after', 'bucket_after', 'project_after')
Incomplete = objects.Incomplete


def enabled(options, profile):
    kinds = options.get('_content_secret_scan_kinds')
    return (options.get('content_secret_scans') is True and isinstance(kinds, list)
            and PROFILES[profile]['kind'] in kinds
            and options.get('_workbench_source_named_checks') == [PROFILES[profile]['check']])


def parse(target):
    """Exact current-v2 native field plus an immutable selected object; no URLs."""
    if not isinstance(target, dict) or set(target) != {'resource', 'field', 'bucket', 'object', 'generation'}:
        raise Incomplete('invalid_selection')
    resource = target['resource']
    match = re.fullmatch(r'(projects/[a-z][a-z0-9-]{4,28}[a-z0-9])/locations/[a-z][a-z0-9-]{0,62}/instances/[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?', resource) if isinstance(resource, str) else None
    if not match or not isinstance(target['field'], str) or target['field'] not in FIELDS:
        raise Incomplete('invalid_selection')
    try:
        target['object'].encode('utf-8') if isinstance(target['object'], str) else None
    except UnicodeError:
        raise Incomplete('invalid_selection') from None
    # Reuse the low-level GCS selection contract on the actual selected object.
    objects.selected_targets({'content_secret_scans': True,
        '_content_secret_scan_kinds': [objects.KIND], objects.OPTION: [dict(
            project_scope=match[1], **{k: target[k] for k in ('bucket', 'object', 'generation')})]}, [match[1]])
    name = target['object']
    if (name.endswith('/') or any(c in name for c in '%?#\\')
            or any(p in ('', '.', '..') for p in name.split('/'))
            or int(target['generation']) > 9223372036854775807):
        raise Incomplete('invalid_selection')
    return match[1]


def identity(target):
    return PROFILES['instance']['kind'] + ':' + _fingerprint(json.dumps(target, sort_keys=True, separators=(',', ':')))


def selected_targets(options, scopes):
    """Exported pure validator, including disabled provided selectors, before auth.

    Private kind selection is a root planner authorization seam; root must derive
    it exclusively from the exact named checks, never category/default requests.
    """
    if not isinstance(options, dict) or 'content_secret_scans' in options and type(options['content_secret_scans']) is not bool:
        raise Incomplete('invalid_selection')
    active = any(enabled(options, p) for p in PROFILES)
    if OPTION not in options and not active:
        return []
    rows = options.get(OPTION)
    if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 8
            or any(not isinstance(s, str) or not SCOPE.fullmatch(s) for s in scopes)
            or len(set(scopes)) != len(scopes) or not isinstance(rows, list) or not 1 <= len(rows) <= MAX_TARGETS):
        raise Incomplete('invalid_selection')
    seen = set()
    for row in rows:
        scope = parse(row)
        ident = identity(row)
        if scope not in scopes or ident in seen:
            raise Incomplete('invalid_selection')
        seen.add(ident)
    return deepcopy(rows)


def remaining(transport, state):
    transport.check_cancelled()
    seconds = state['deadline'] - time.monotonic()
    if transport.deadline is not None:
        seconds = min(seconds, transport.deadline - time.time())
    if transport.deadline_seconds is not None:
        seconds = min(seconds, transport.deadline_seconds - (time.monotonic() - transport.started))
    if seconds <= 0:
        raise Incomplete('deadline')
    return min(transport.timeout, seconds)


def _read_instance(transport, state, ident, scope, operation, url, params, expected=None):
    """Internally constructed exact route; raw/error/credential bytes never cached."""
    remaining(transport, state)
    origin = urlsplit(url).netloc
    if origin not in {'notebooks.googleapis.com'}:
        raise Incomplete('invalid_route')
    receipt = dict(id='workbench-source-read:' + uuid4().hex, identity=ident, scope=scope,
                   capture=state['capture'], operation=operation, method='GET', origin=origin,
                   request=_fingerprint(url + '\n' + json.dumps(params, sort_keys=True)),
                   principal=None, bound=False, status='unavailable', bytes=0)
    state['ledger'].append(receipt)
    response = session = None
    try:
        from urllib3.connection import HTTPSConnection
        if (http.client.HTTPConnection.debuglevel or http.client.HTTPSConnection.debuglevel or HTTPSConnection.debuglevel
                or logging.getLogger('urllib3.connectionpool').isEnabledFor(logging.DEBUG)):
            raise Incomplete('unsafe_http_diagnostics')
        with transport.lock:
            if state['calls'] >= MAX_CALLS or transport.max_calls is not None and transport.calls >= transport.max_calls:
                raise Incomplete('call_limit')
            state['calls'] += 1
            transport.calls += 1
        native_headers = transport.credentials.headers()
        auth = native_headers.get('Authorization')
        if not isinstance(auth, str) or not re.fullmatch(r'Bearer [A-Za-z0-9._~+/-]+=*', auth) or len(auth) > 16384:
            raise Incomplete('auth_unavailable')
        principal = _fingerprint(auth)
        if state.setdefault('principal', principal) != principal:
            raise Incomplete('principal_changed')
        receipt['principal'] = principal
        headers = {'Authorization': auth, 'Accept': '*/*' if expected else 'application/json',
                   'Accept-Encoding': 'identity', 'Cache-Control': 'no-store'}
        # Quota headers cannot be provider-chosen free text.
        quota = transport.options.get('quota_project')
        if quota is not None:
            if not isinstance(quota, str) or not re.fullmatch(r'[a-z][a-z0-9-]{4,28}[a-z0-9]|[1-9][0-9]{0,19}', quota):
                raise Incomplete('invalid_quota')
            headers['X-Goog-User-Project'] = quota
        session = git._session()
        response = session.request('GET', url, params=params, headers=headers, stream=True,
                                   allow_redirects=False, timeout=remaining(transport, state))
        import requests
        if response.url != requests.Request('GET', url, params=params).prepare().url or response.history:
            raise Incomplete('response_route')
        if response.status_code != 200:
            raise Incomplete('denied' if response.status_code in (401, 403) else 'native_unavailable')
        hdr = {k.lower(): v for k, v in response.headers.items()}
        length = hdr.get('content-length')
        limit = MAX_CONTENT if expected else MAX_METADATA
        if (not isinstance(length, str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', length)
                or not 0 < int(length) <= limit or hdr.get('content-encoding', 'identity').lower() != 'identity'
                or 'content-range' in hdr or 'transfer-encoding' in hdr or 'location' in hdr
                or 'link' in hdr or not expected and hdr.get('content-type', '').split(';')[0].strip().lower() != 'application/json'):
            raise Incomplete('framing_or_bound')
        if expected and (int(length) != expected['size'] or hdr.get('x-goog-generation') != expected['generation']
                         or hdr.get('content-type', '').split(';')[0].strip().lower() != expected['type']):
            raise Incomplete('media_binding')
        raw = bytearray()
        while True:
            timeout = remaining(transport, state)
            sock = getattr(getattr(getattr(getattr(response.raw, '_fp', None), 'fp', None), 'raw', None), '_sock', None)
            if sock is not None:
                sock.settimeout(timeout)
            chunk = response.raw.read(min(16384, limit + 1 - len(raw)), decode_content=False)
            remaining(transport, state)
            if not isinstance(chunk, bytes):
                raise Incomplete('invalid_stream')
            if not chunk:
                break
            raw.extend(chunk)
            state['bytes'] += len(chunk)
            receipt['bytes'] = len(raw)
            if len(raw) > limit or state['bytes'] > MAX_TOTAL:
                raise Incomplete('byte_limit')
        if len(raw) != int(length):
            raise Incomplete('truncated')
        result = bytes(raw) if expected else _json(bytes(raw))
        if not expected and any(k in result for k in ('error', 'nextPageToken', 'unreachable', 'unreachables', 'warning', '_coverage', 'partial')):
            raise Incomplete('partial_native')
        receipt['status'] = 'collected'
        return result
    except Incomplete:
        raise
    except Exception:
        raise Incomplete('read_unavailable') from None
    finally:
        for resource in (response, session):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    pass


def _read(transport, state, ident, scope, operation, url, params, expected=None):
    from urllib3.connection import HTTPSConnection
    if (http.client.HTTPConnection.debuglevel or http.client.HTTPSConnection.debuglevel or HTTPSConnection.debuglevel
            or logging.getLogger('urllib3.connectionpool').getEffectiveLevel() <= logging.DEBUG):
        raise Incomplete('unsafe_http_diagnostics')
    # The reviewed GCS stream, framing, pinned content and request ledger remain unchanged.
    if operation.startswith('reference_'):
        return _read_instance(transport, state, ident, scope, operation, url, params, expected)
    return reviewed._read(transport, state, ident, scope, operation, url, params, expected)


def _project(data, scope):
    return reviewed._project(data, scope)


def _bucket(project, data, scope, bucket):
    # Compare actual native reads directly; do not synthesize parent collections.
    if (set(data) != {'name', 'projectNumber'} or data.get('name') != bucket
            or data.get('projectNumber') != project['name'].split('/')[1]):
        raise Incomplete('bucket_binding')
    return data


def reference(data, target):
    """Return HMAC of actual v2 incarnation and the selected returned relationship."""
    parse(target)
    _, selected_map, key = target['field'].split('.')
    setup = data.get('gceSetup')
    uri = 'gs://' + target['bucket'] + '/' + target['object']
    if (data.get('name') != target['resource'] or not isinstance(setup, dict)
            or not isinstance(setup.get(selected_map), dict) or setup[selected_map].get(key) != uri):
        raise Incomplete('reference_binding')
    # Both maps can be returned; contradictions cannot be hidden by field selection.
    for name in ('metadata', 'systemMetadata'):
        if name in setup and (not isinstance(setup[name], dict)
                or key in setup[name] and setup[name][key] != uri):
            raise Incomplete('reference_binding')
    native_id = data.get('id')
    if not isinstance(native_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', native_id):
        raise Incomplete('native_identity')
    incarnation = {'name': data['name'], 'id': native_id, 'field': target['field'], 'uri': uri}
    if key == 'post-startup-script':
        behaviors = [setup[name]['post-startup-script-behavior'] for name in ('metadata', 'systemMetadata')
                     if isinstance(setup.get(name), dict) and 'post-startup-script-behavior' in setup[name]]
        if (any(not isinstance(b, str) or b not in ('run_once', 'run_every_start', 'download_and_run_every_start') for b in behaviors)
                or len(set(behaviors)) > 1):
            raise Incomplete('reference_binding')
        # Missing behavior uses the documented run_once default. Presence itself is
        # also bound, so a changed returned shape cannot hide an intervening edit.
        incarnation['behavior'] = behaviors or ['documented_default_run_once']
    # Creation time and underlying VM ID are real optional v2 fields: if returned,
    # require well-formed stable evidence; their absence is not invented identity.
    if 'createTime' in data:
        try:
            if not isinstance(data['createTime'], str) or datetime.fromisoformat(data['createTime'].replace('Z', '+00:00')).utcoffset() is None:
                raise ValueError()
        except (ValueError, TypeError, OverflowError):
            raise Incomplete('native_identity') from None
        incarnation['createTime'] = data['createTime']
    if 'instanceId' in setup:
        if not isinstance(setup['instanceId'], str) or not re.fullmatch(r'[1-9][0-9]{0,19}', setup['instanceId']):
            raise Incomplete('native_identity')
        incarnation['instanceId'] = setup['instanceId']
    return _fingerprint(json.dumps(incarnation, sort_keys=True))


def collect_sources(collector, scope, profile='instance'):
    targets = selected_targets(collector.options, collector.scopes)
    if not enabled(collector.options, profile):
        return []
    transport = collector.transport
    with transport.lock:
        if not hasattr(transport, '_workbench_source_state'):
            transport._workbench_source_state = {'capture': uuid4().hex, 'deadline': time.monotonic() + MAX_SECONDS,
                'calls': 0, 'bytes': 0, 'ledger': [], 'redactions': set(), 'lock': threading.RLock(), 'items': {}}
        state = transport._workbench_source_state
    output = []
    with state['lock']:
        for target in targets:
            if parse(target) != scope:
                continue
            ident = identity(target)
            if ident not in state['items']:
                marker = dict(schema=SCHEMA, identity=ident, scope=scope, profile=profile, capture=state['capture'],
                    complete=False, native_complete=False, association=None, generation=target['generation'],
                    parts=[], leaks=[], source_requests=[], verification='not_attempted', reason='unavailable',
                    captured_at=None, executed_bytes_proven=False)
                start = len(state['ledger'])
                try:
                    def get(op, url, params, expected=None):
                        return _read(transport, state, ident, scope, op, url, params, expected)
                    project_url = 'https://cloudresourcemanager.googleapis.com/v3/' + scope
                    project_params = {'fields': 'name,projectId,state'}
                    project = _project(get('project_before', project_url, project_params), scope)
                    state['ledger'][-1]['bound'] = True
                    native_url = 'https://notebooks.googleapis.com/v2/' + target['resource']
                    # Full bounded metadata: no field masks hiding native union contradictions.
                    association = reference(get('reference_before', native_url, {}), target)
                    state['ledger'][-1]['bound'] = True
                    bucket_url = 'https://storage.googleapis.com/storage/v1/b/' + quote(target['bucket'], safe='')
                    bucket_params = {'fields': 'name,projectNumber', 'projection': 'noAcl'}
                    bucket = _bucket(project, get('bucket_before', bucket_url, bucket_params), scope, target['bucket'])
                    state['ledger'][-1]['bound'] = True
                    object_url = bucket_url + '/o/' + quote(target['object'], safe='')
                    metadata_params = {'fields': objects.FIELDS, 'projection': 'noAcl'}
                    object_target = {k: target[k] for k in ('bucket', 'object', 'generation')}
                    before = get('latest_before', object_url, metadata_params)
                    metadata = objects._metadata(json.dumps(before).encode(), object_target)
                    if metadata['size'] == 0:
                        raise Incomplete('empty_content')
                    state['ledger'][-1]['bound'] = True
                    payload = get('content', object_url, {'generation': target['generation'],
                        'ifGenerationMatch': target['generation'], 'alt': 'media'}, {**metadata, 'generation': target['generation']})
                    objects._text(payload)
                    state['ledger'][-1]['bound'] = True
                    after = get('latest_after', object_url, metadata_params)
                    objects._metadata(json.dumps(after).encode(), object_target)
                    if after != before:
                        raise Incomplete('object_changed')
                    state['ledger'][-1]['bound'] = True
                    if reference(get('reference_after', native_url, {}), target) != association:
                        raise Incomplete('association_changed')
                    state['ledger'][-1]['bound'] = True
                    if _bucket(project, get('bucket_after', bucket_url, bucket_params), scope, target['bucket']) != bucket:
                        raise Incomplete('bucket_changed')
                    state['ledger'][-1]['bound'] = True
                    if _project(get('project_after', project_url, project_params), scope) != project:
                        raise Incomplete('project_changed')
                    state['ledger'][-1]['bound'] = True
                    marker.update(native_complete=True, association=association,
                                  captured_at=datetime.now(timezone.utc).isoformat())
                    outcome = scan_content(payload, ident + '.source', timeout=min(10, remaining(transport, state) / 2),
                                           _redact_values=state['redactions'].update)
                    del payload
                    remaining(transport, state)
                    leaks = merge_leaks(outcome['leaks'])
                    if len(leaks) > MAX_LEAKS or sum(len(l['locations']) for l in leaks) > MAX_LOCATIONS:
                        raise Incomplete('finding_limit')
                    marker.update(parts=[dict(bytes=metadata['size'], complete=outcome['complete'], engines=outcome['engines'])],
                                  leaks=leaks, complete=outcome['complete'], reason='complete' if outcome['complete'] else 'detector_unavailable')
                except Incomplete as exc:
                    marker['reason'] = str(exc) if str(exc) in {'unavailable', 'invalid_selection', 'deadline', 'invalid_route', 'unsafe_http_diagnostics', 'call_limit', 'auth_unavailable', 'principal_changed', 'invalid_quota', 'response_route', 'denied', 'native_unavailable', 'framing_or_bound', 'media_binding', 'invalid_stream', 'byte_limit', 'truncated', 'partial_native', 'read_unavailable', 'project_binding', 'bucket_binding', 'bucket_project_mismatch', 'project_binding_unavailable', 'reference_binding', 'native_identity', 'metadata_identity_mismatch', 'oversize', 'unsupported_format_or_encryption', 'malformed_metadata', 'empty_content', 'object_changed', 'association_changed', 'bucket_changed', 'project_changed', 'unsupported_archive', 'unsupported_utf8', 'unsupported_binary', 'finding_limit'} else 'unavailable'
                except Exception:
                    marker['reason'] = 'unavailable'
                marker['source_requests'] = [e['id'] for e in state['ledger'][start:]]
                state['items'][ident] = {'name': ident, MARKER: marker,
                    '_provenance': {'scope': scope, 'capture': state['capture'], 'source_requests': marker['source_requests']},
                    '_coverage': {MARKER: {'status': 'collected', 'source_requests': marker['source_requests']}}}
            output.append(deepcopy(state['items'][ident]))
    return output


def selection_metadata(collector):
    targets = selected_targets(collector.options, collector.scopes)
    state = getattr(collector.transport, '_workbench_source_state', {})
    result = {'workbench_source_capture': state.get('capture'), 'workbench_source_receipts': deepcopy(state.get('ledger', []))}
    for profile, p in PROFILES.items():
        result[p['kind'] + '_authorized'] = enabled(collector.options, profile)
        result[p['kind'] + '_selection'] = {s: [identity(t) for t in targets if parse(t) == s]
                                           for s in collector.scopes}
    return result


def redaction_values(transport):
    """Ephemeral union seam; never serialize these values or retain after teardown."""
    state = getattr(transport, '_workbench_source_state', {})
    return frozenset(state.get('redactions', ()))


def collection_pages(collector, scope, profile):
    for row in collect_sources(collector, scope, profile):
        refs = row[MARKER]['source_requests']
        for ref in refs[:-1]:
            yield [], ref
        yield [row], refs[-1] if refs else 'local:workbench-source-unavailable'


def jobs(collector, scope, profile):
    if enabled(collector.options, profile):
        return [(PROFILES[profile]['kind'], scope, 'workbench', lambda: collection_pages(collector, scope, profile))]
    return []


def final_snapshot(collector, snapshot, *, redactions=()):
    """Root-proposed final union hook; run before existing final unions/cleanup.

    Match values remain transient until ALL metadata/cache/options is scrubbed.
    Root should also merge this private redaction set into other active readers'
    transient sets before their final hooks, then clear every set at teardown.
    """
    state = getattr(collector.transport, '_workbench_source_state', {})
    values = set(state.get('redactions', ())) | set(redactions)
    try:
        snapshot = deepcopy(snapshot)
        snapshot.setdefault('metadata', {}).update(selection_metadata(collector))
        # Selection itself may contain a matched value, so persist only opaque IDs.
        if isinstance(snapshot['metadata'].get('options'), dict):
            snapshot['metadata']['options'].pop(OPTION, None)
            snapshot['metadata']['options'].pop('_cancel_check', None)
            snapshot['metadata']['options'].pop('cancel_event', None)
        collector.transport.cache = redact_matches(collector.transport.cache, values)
        collector.transport.evidence = redact_matches(collector.transport.evidence, values)
        collector.transport.options.pop(OPTION, None)
        collector.transport.options = redact_matches(collector.transport.options, values)
        collector.options.pop(OPTION, None)
        collector.options = redact_matches(collector.options, values)
        collector.collections = redact_matches(collector.collections, values)
        from peaso.snapshot import seal
        return seal(redact_matches(snapshot, values))
    finally:
        clear_pending(collector.transport)


def clear_pending(transport):
    state = getattr(transport, '_workbench_source_state', None)
    if state is not None:
        with state['lock']:
            state['redactions'].clear()
            state['items'].clear()
            delattr(transport, '_workbench_source_state')
