"""Explicit selected GCS text reads; uninstalled collector seam, no raw cache.

The caller owns admission and collection envelopes. This adapter independently
requires content opt-in, a named-check planner kind and exact immutable targets.
It uses the existing Transport session/call/deadline/cancellation machinery;
media never enters Transport.request's JSON cache. No retries or enumeration.
"""
from copy import deepcopy
import hashlib
import json
import re
import threading
import time
from urllib.parse import quote

from peaso.secret_scanning import scan_content, merge_leaks

SCHEMA = 'gcp-selected-object-secrets-v1'
MARKER = 'SelectedObjectSecretIndicators'
KIND = 'gcs_selected_object'
OPTION = 'selected_gcs_objects'
MAX_OBJECTS = 10
MAX_OBJECT_BYTES = 1048576
MAX_TOTAL_BYTES = 8388608
MAX_METADATA_BYTES = 16384
MAX_CALLS = 20
MAX_SECONDS = 30
MAX_LEAKS = 256
MAX_LOCATIONS = 512
FIELDS = 'bucket,name,generation,size,contentType,contentEncoding,customerEncryption'
_SCOPE = re.compile(r'projects/(?:[a-z][a-z0-9-]{0,62}|[1-9][0-9]{0,19})\Z')
_BUCKET = re.compile(r'[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]\Z')
_DECIMAL = re.compile(r'[1-9][0-9]{0,19}\Z')
_TYPES = {'application/json', 'application/yaml', 'application/x-yaml',
          'application/toml', 'application/xml', 'application/javascript'}


class Incomplete(Exception):
    """Only static, non-provider reason codes may escape the read boundary."""


def selected_targets(options, scopes):
    """Validate the entire selection before credentials or any object calls."""
    if (options.get('content_secret_scans') is not True
            or KIND not in options.get('_content_secret_scan_kinds', [])):
        return []
    rows = options.get(OPTION)
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_OBJECTS:
        raise Incomplete('invalid_selection')
    result, seen = [], set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'project_scope', 'bucket', 'object', 'generation'}:
            raise Incomplete('invalid_selection')
        scope, bucket, name, generation = (row[k] for k in ('project_scope', 'bucket', 'object', 'generation'))
        if (not isinstance(scope, str) or not _SCOPE.fullmatch(scope) or scope not in scopes
                or not isinstance(bucket, str) or not _BUCKET.fullmatch(bucket)
                or any(len(part) > 63 for part in bucket.split('.'))
                or not isinstance(name, str) or not name or len(name.encode('utf-8')) > 1024
                or any(ord(c) < 32 or ord(c) == 127 for c in name)
                or not isinstance(generation, str) or not _DECIMAL.fullmatch(generation)):
            raise Incomplete('invalid_selection')
        ident = identity(row)
        if ident in seen:
            raise Incomplete('duplicate_selection')
        seen.add(ident)
        result.append(dict(row))
    return result


def identity(target):
    # Opaque reference, not a hash of content; names may themselves contain a secret.
    return 'gcs-selected-object:' + hashlib.sha256(json.dumps(target, sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def _bound_bucket(collector, scope, bucket):
    project = collector.collections.get(('project', scope), {})
    buckets = collector.collections.get(('bucket', scope), {})
    if (project.get('coverage_status') != 'collected' or buckets.get('coverage_status') != 'collected'
            or len(project.get('items', [])) != 1):
        raise Incomplete('project_binding_unavailable')
    row = project['items'][0]
    # scope_jobs.scope_metadata reads CRM v3: the numeric identifier is in
    # name=projects/{number}; projectNumber belongs to the legacy v1 shape.
    native_name = row.get('name')
    match = re.fullmatch(r'projects/([1-9][0-9]{0,19})', native_name) if isinstance(native_name, str) else None
    number = match[1] if match else None
    project_id = row.get('projectId')
    sid = scope.split('/', 1)[1]
    if (number is None or not isinstance(project_id, str)
            or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', project_id)
            or sid not in (project_id, number)
            or 'projectNumber' in row and row['projectNumber'] != number):
        raise Incomplete('project_binding_unavailable')
    matches = [b for b in buckets.get('items', []) if isinstance(b, dict) and b.get('name') == bucket]
    if len(matches) != 1 or matches[0].get('projectNumber') != number:
        raise Incomplete('bucket_project_mismatch')


def _check(transport, state):
    transport.check_cancelled()
    if time.monotonic() - state['started'] >= MAX_SECONDS:
        raise Incomplete('content_deadline')


def _remaining(transport, state):
    _check(transport, state)
    seconds = MAX_SECONDS - (time.monotonic() - state['started'])
    if transport.deadline is not None:
        seconds = min(seconds, transport.deadline - time.time())
    if transport.deadline_seconds is not None:
        seconds = min(seconds, transport.deadline_seconds - (time.monotonic() - transport.started))
    if seconds <= 0:
        raise Incomplete('content_deadline')
    return min(transport.timeout, seconds)


def _read(transport, state, target, *, media=False, expected=None):
    """Fixed native endpoint, validated targets, exact request, bounded raw stream."""
    _check(transport, state)
    url = ('https://storage.googleapis.com/storage/v1/b/' + quote(target['bucket'], safe='')
           + '/o/' + quote(target['object'], safe=''))
    params = {'generation': target['generation'], 'ifGenerationMatch': target['generation']}
    params.update({'alt': 'media'} if media else {'fields': FIELDS, 'projection': 'noAcl'})
    evidence = {'scope': target['project_scope'], 'method': 'GET',
        'operation': 'storage.objects.get.media' if media else 'storage.objects.get.metadata',
        'resource_id': identity(target), 'status': 'unavailable'}
    response = None
    try:
        with transport.lock:
            if (state['calls'] >= MAX_CALLS or
                    transport.max_calls is not None and transport.calls >= transport.max_calls):
                raise Incomplete('call_limit')
            transport.calls += 1
            state['calls'] += 1
        # All endpoint/target validation happens before credential acquisition.
        headers = dict(transport.credentials.headers())
        headers['Accept-Encoding'] = 'identity'
        if transport.options.get('quota_project'):
            headers['X-Goog-User-Project'] = transport.options['quota_project']
        _check(transport, state)
        from .gcp import native_header_session
        response = native_header_session(transport).request('GET', url, params=params, headers=headers,
            stream=True, allow_redirects=False, timeout=_remaining(transport, state))
        evidence['http_status'] = response.status_code
        if response.status_code != 200:
            raise Incomplete('denied' if response.status_code in (401, 403) else 'http_incomplete')
        hdr = {k.lower(): v for k, v in response.headers.items()}
        if hdr.get('content-encoding', 'identity').lower() != 'identity' or 'content-range' in hdr:
            raise Incomplete('unsupported_encoding_or_range')
        length = hdr.get('content-length')
        if length is not None and (not isinstance(length, str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', length)):
            raise Incomplete('invalid_length')
        limit = MAX_OBJECT_BYTES if media else MAX_METADATA_BYTES
        if length is not None and int(length) > limit:
            raise Incomplete('oversize')
        if media:
            if (length is None or int(length) != expected['size']
                    or hdr.get('x-goog-generation') != target['generation']
                    or hdr.get('content-type', '').split(';')[0].strip().lower() != expected['type']):
                raise Incomplete('media_identity_or_length_mismatch')
        chunks, count = [], 0
        while True:
            _check(transport, state)
            # requests/urllib3 uses a socket timeout per read. Tighten it to
            # the remaining scan/transport deadline before every blocking read.
            # In-memory injected streams have no socket and never block on I/O.
            raw_socket = getattr(getattr(getattr(getattr(response.raw, '_fp', None),
                'fp', None), 'raw', None), '_sock', None)
            if raw_socket is not None:
                raw_socket.settimeout(_remaining(transport, state))
            chunk = response.raw.read(min(16384, limit - count + 1), decode_content=False)
            if not chunk:
                break
            if not isinstance(chunk, bytes):
                raise Incomplete('invalid_stream')
            count += len(chunk)
            if media:
                state['bytes'] += len(chunk)
            if count > limit or state['bytes'] > MAX_TOTAL_BYTES:
                raise Incomplete('oversize')
            chunks.append(chunk)
        if length is not None and count != int(length):
            raise Incomplete('truncated_or_overlong')
        if media and count != expected['size']:
            raise Incomplete('truncated_or_overlong')
        evidence.update(status='collected', bytes=count)
        return b''.join(chunks)
    except Incomplete as exc:
        evidence['reason'] = str(exc)
        raise
    except Exception:
        evidence['reason'] = 'read_unavailable'
        raise Incomplete('read_unavailable') from None
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        with transport.lock:
            evidence['id'] = 'request-' + str(len(transport.evidence) + 1)
            transport.evidence.append(evidence)


def _metadata(raw, target):
    try:
        data = json.loads(raw)
        if (not isinstance(data, dict) or set(data) - set(FIELDS.split(','))
                or any(data.get(k) != target[k if k != 'name' else 'object']
                       for k in ('bucket', 'name', 'generation'))
                or not isinstance(data.get('size'), str)
                or not re.fullmatch(r'0|[1-9][0-9]{0,19}', data['size'])):
            raise Incomplete('metadata_identity_mismatch')
        size = int(data['size'])
        mime = data.get('contentType', '').split(';')[0].strip().lower()
        if size > MAX_OBJECT_BYTES:
            raise Incomplete('oversize')
        if (not (mime.startswith('text/') or mime in _TYPES)
                or data.get('contentEncoding', 'identity') != 'identity' or 'customerEncryption' in data):
            raise Incomplete('unsupported_format_or_encryption')
        return {'size': size, 'type': mime}
    except Incomplete:
        raise
    except Exception:
        raise Incomplete('malformed_metadata') from None


def _text(payload):
    if payload.startswith((b'PK\x03\x04', b'\x1f\x8b', b'BZh', b'\xfd7zXZ', b'7z\xbc\xaf', b'Rar!')) or payload[257:262] == b'ustar':
        raise Incomplete('unsupported_archive')
    try:
        value = payload.decode('utf-8', errors='strict')
    except UnicodeError:
        raise Incomplete('unsupported_utf8') from None
    if any(ord(c) < 32 and c not in '\t\r\n' or ord(c) == 127 for c in value):
        raise Incomplete('unsupported_binary')


def collect_selected_objects(collector, scope):
    """Return redacted native-produced items, for a root-owned collection job.

    Requires completed native project/bucket dependencies in collector.collections.
    State and redacted outcomes are shared per Transport across selected scopes.
    """
    options = collector.options
    targets = selected_targets(options, collector.scopes)
    if not targets:
        return []
    transport = collector.transport
    with transport.lock:
        if not hasattr(transport, '_selected_object_secret_state'):
            transport._selected_object_secret_state = {'started': time.monotonic(), 'bytes': 0,
                'calls': 0, 'lock': threading.Lock(), 'items': {}}
        state = transport._selected_object_secret_state
    result = []
    with state['lock']:
        for target in targets:
            if target['project_scope'] != scope:
                continue
            ident = identity(target)
            if ident not in state['items']:
                marker = {'schema': SCHEMA, 'identity': ident, 'scope': scope,
                    'status': 'incomplete', 'complete': False, 'bytes': 0, 'engines': [],
                    'leaks': [], 'verification': 'not_attempted', 'reason': 'unavailable'}
                try:
                    _check(transport, state)
                    _bound_bucket(collector, scope, target['bucket'])
                    metadata = _metadata(_read(transport, state, target), target)
                    if state['bytes'] + metadata['size'] > MAX_TOTAL_BYTES:
                        raise Incomplete('total_byte_limit')
                    payload = _read(transport, state, target, media=True, expected=metadata)
                    _text(payload)
                    _check(transport, state)
                    remaining = MAX_SECONDS - (time.monotonic() - state['started'])
                    outcome = scan_content(payload, 'object.content', timeout=min(5, remaining / 2))
                    del payload
                    _check(transport, state)
                    leaks = merge_leaks(outcome['leaks'])
                    if len(leaks) > MAX_LEAKS or sum(len(x['locations']) for x in leaks) > MAX_LOCATIONS:
                        raise Incomplete('finding_limit')
                    marker.update(bytes=metadata['size'], engines=outcome['engines'], leaks=leaks,
                        complete=outcome['complete'], status='collected' if outcome['complete'] else 'incomplete',
                        reason='complete' if outcome['complete'] else 'detector_unavailable')
                except Incomplete as exc:
                    marker['reason'] = str(exc)
                except Exception:
                    marker['reason'] = 'unavailable'
                state['items'][ident] = {'name': ident, MARKER: marker}
            result.append(deepcopy(state['items'][ident]))
    return result


def collection_pages(collector, scope):
    """Native collector page seam, preserving safe HTTP request provenance."""
    rows = collect_selected_objects(collector, scope)
    for row in rows:
        with collector.transport.lock:
            refs = [e['id'] for e in collector.transport.evidence
                    if e.get('scope') == scope and e.get('resource_id') == row['name']
                    and e.get('operation') in ('storage.objects.get.metadata', 'storage.objects.get.media')]
        for ref in refs[:-1]:
            yield [], ref
        row.setdefault('_coverage', {})[MARKER] = {'status': 'collected', 'source_requests': refs}
        yield [row], refs[-1] if refs else 'local:gcs_selected_object'
