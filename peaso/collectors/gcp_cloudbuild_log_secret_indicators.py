"""Default-off exact Cloud Build stored-log generation observation.

Root owns admission, dependencies and installation. Only metadata is discovered;
content uses the existing uncached, bounded, generation-pinned text reader.
"""
from copy import deepcopy
from datetime import datetime
import hashlib
import http.client
import json
import logging
import re
import threading
import time
from types import SimpleNamespace
from urllib.parse import quote

from . import gcp_selected_object_secret_indicators as objects
from . import gcp_cloudbuild_logging_entries as logging_entries
from .gcp_composer_source_secret_indicators import _refs, _pairs

KIND = 'cloudbuild_log_source'
OPTION = 'selected_cloudbuild_builds'
MARKER = 'CloudBuildLogSecretIndicators'
SCHEMA = 'gcp-cloudbuild-stored-log-secrets-v1'
MAX_BUILDS = 4
BUILD_FIELDS = 'id,name,projectId,logsBucket,status,createTime,startTime,finishTime,options(logging)'
BUILD_NAME = re.compile(r'projects/([a-z][a-z0-9-]{0,62}|[1-9][0-9]{0,19})/locations/([a-z][a-z0-9-]{0,62})/builds/([a-zA-Z0-9][a-zA-Z0-9_-]{0,127})\Z')
TERMINAL = {'SUCCESS', 'FAILURE', 'INTERNAL_ERROR', 'TIMEOUT', 'CANCELLED', 'EXPIRED'}
Incomplete = objects.Incomplete


def enabled(options):
    kinds = options.get('_content_secret_scan_kinds')
    return options.get('content_secret_scans') is True and isinstance(kinds, list) and KIND in kinds


def selected_builds(options, scopes):
    if not enabled(options):
        return []
    rows = options.get(OPTION)
    if (not isinstance(scopes, list) or len(scopes) != 1 or not isinstance(scopes[0], str)
            or not objects._SCOPE.fullmatch(scopes[0]) or not isinstance(rows, list)
            or not 1 <= len(rows) <= MAX_BUILDS):
        raise Incomplete('invalid_selection')
    names = []
    for name in rows:
        match = BUILD_NAME.fullmatch(name) if isinstance(name, str) else None
        if match is None or 'projects/' + match[1] != scopes[0] or name in names:
            raise Incomplete('invalid_selection')
        names.append(name)
    return names


def selection_metadata(collector):
    return {'cloudbuild_log_source_authorized': enabled(collector.options)}


def identity(name):
    return 'cloudbuild-stored-log:' + hashlib.sha256(name.encode()).hexdigest()


def _json_get(transport, state, scope, url, params, operation, resource):
    """Bounded uncached metadata only; no provider bodies/URLs in receipts."""
    objects._check(transport, state)
    response = None
    receipt = {'scope': scope, 'method': 'GET', 'operation': operation,
               'resource_id': resource, 'status': 'unavailable'}
    try:
        with transport.lock:
            if (state['calls'] >= objects.MAX_CALLS
                    or transport.max_calls is not None and transport.calls >= transport.max_calls):
                raise Incomplete('call_limit')
            state['calls'] += 1
            transport.calls += 1
        headers = dict(transport.credentials.headers())
        headers['Accept-Encoding'] = 'identity'
        if transport.options.get('quota_project'):
            headers['X-Goog-User-Project'] = transport.options['quota_project']
        from .gcp import native_header_session
        response = native_header_session(transport).request('GET', url, params=params, headers=headers,
            stream=True, allow_redirects=False, timeout=objects._remaining(transport, state))
        receipt['http_status'] = response.status_code
        if response.status_code != 200:
            raise Incomplete('metadata_denied' if response.status_code in (401, 403) else 'metadata_unavailable')
        hdr = {k.lower(): v for k, v in response.headers.items()}
        length = hdr.get('content-length')
        if (hdr.get('content-encoding', 'identity').lower() != 'identity' or 'content-range' in hdr
                or length is not None and (not isinstance(length, str)
                    or not re.fullmatch(r'0|[1-9][0-9]{0,19}', length) or int(length) > objects.MAX_METADATA_BYTES)):
            raise Incomplete('metadata_encoding_or_limit')
        chunks, count = [], 0
        while True:
            objects._check(transport, state)
            sock = getattr(getattr(getattr(getattr(response.raw, '_fp', None), 'fp', None), 'raw', None), '_sock', None)
            if sock is not None:
                sock.settimeout(objects._remaining(transport, state))
            chunk = response.raw.read(min(16384, objects.MAX_METADATA_BYTES - count + 1), decode_content=False)
            if not chunk:
                break
            if not isinstance(chunk, bytes):
                raise Incomplete('malformed_metadata')
            count += len(chunk)
            if count > objects.MAX_METADATA_BYTES:
                raise Incomplete('metadata_byte_limit')
            chunks.append(chunk)
        if length is not None and int(length) != count:
            raise Incomplete('truncated_metadata')
        data = json.loads(b''.join(chunks).decode('utf-8'), object_pairs_hook=_pairs)
        if not isinstance(data, dict):
            raise Incomplete('malformed_metadata')
        receipt.update(status='collected', bytes=count)
        return data
    except Incomplete:
        raise
    except Exception:
        raise Incomplete('metadata_unavailable') from None
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        with transport.lock:
            receipt['id'] = 'request-' + str(len(transport.evidence) + 1)
            transport.evidence.append(receipt)


def _time(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z', value):
        raise Incomplete('build_time_unavailable')
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def build_binding(build, name, project):
    """Validate native identity and terminal observation, never consult logUrl."""
    match = BUILD_NAME.fullmatch(name)
    if (not isinstance(build, dict) or set(build) - set(BUILD_FIELDS.split(',')[:-1] + ['options'])
            or build.get('name') != name or build.get('id') != match[3]
            or build.get('projectId') != project.get('projectId')
            or match[1] not in (project.get('projectId'), project.get('name', '').split('/')[-1])
            or build.get('status') not in TERMINAL):
        raise Incomplete('build_identity_or_state_unavailable')
    created, finished = _time(build.get('createTime')), _time(build.get('finishTime'))
    if created > finished or 'startTime' in build and not created <= _time(build['startTime']) <= finished:
        raise Incomplete('build_time_unavailable')
    options = build.get('options', {})
    if (not isinstance(options, dict) or set(options) - {'logging'}
            or options.get('logging', 'LOGGING_UNSPECIFIED') not in ('LOGGING_UNSPECIFIED', 'LEGACY', 'GCS_ONLY')):
        raise Incomplete('gcs_logging_unavailable')
    logs = build.get('logsBucket')
    # Only a bucket root is documented/supported here; no console URLs or paths.
    m = re.fullmatch(r'gs://([a-z0-9][a-z0-9._-]{1,220}[a-z0-9])/?', logs) if isinstance(logs, str) else None
    if m is None or any(len(p) > 63 for p in m[1].split('.')):
        raise Incomplete('logs_bucket_unavailable')
    return m[1], 'log-' + match[3] + '.txt'


def logging_binding(build, name, project):
    match = BUILD_NAME.fullmatch(name)
    if (not isinstance(build, dict) or set(build) - set(BUILD_FIELDS.split(',')[:-1] + ['options'])
            or build.get('name') != name or build.get('id') != match[3]
            or build.get('projectId') != project.get('projectId')
            or match[1] not in (project.get('projectId'), project.get('name', '').split('/')[-1])
            or build.get('status') not in TERMINAL
            or build.get('options') != {'logging': 'CLOUD_LOGGING_ONLY'}):
        raise Incomplete('logging_build_identity_or_state_unavailable')
    created, finished = _time(build.get('createTime')), _time(build.get('finishTime'))
    if created > finished or 'startTime' in build and not created <= _time(build['startTime']) <= finished:
        raise Incomplete('build_time_unavailable')
    if 'logsBucket' in build and build['logsBucket'] not in ('', None):
        raise Incomplete('ambiguous_logging_destination')


def _project(collector, scope):
    source = collector.collections.get(('project', scope), {})
    rows = source.get('items')
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise Incomplete('project_binding_unavailable')
    if set(rows[0].get('_coverage', {})) & {'name', 'projectId', 'projectNumber', '*'}:
        raise Incomplete('project_binding_unavailable')
    refs = _refs(collector, 'project', scope, rows[0], 'https://cloudresourcemanager.googleapis.com/v3/' + scope)
    return rows[0], refs


def collect_sources(collector, scope):
    if not enabled(collector.options):
        return []
    try:
        names = selected_builds(collector.options, collector.scopes)
        if scope != collector.scopes[0]:
            raise Incomplete('invalid_selection')
    except Incomplete:
        return [{'name': identity(scope), MARKER: {'schema': SCHEMA, 'complete': False, 'reason': 'invalid_selection'}}]
    transport = collector.transport
    with transport.lock:
        if not hasattr(transport, '_selected_object_secret_state'):
            transport._selected_object_secret_state = {'started': time.monotonic(), 'bytes': 0,
                'calls': 0, 'lock': threading.Lock(), 'items': {}}
        state = transport._selected_object_secret_state
    result = []
    for name in names:
        ident = identity(name)
        marker = {'schema': SCHEMA, 'complete': False, 'scope': scope, 'build_name': name,
                  'build': {}, 'bucket_sha256': '', 'generation': '', 'object': {},
                  'native_requests': [], 'read_receipts': [], 'source_requests': [],
                  'reason': 'source_unavailable', 'verification': 'not_attempted'}
        start = len(transport.evidence)
        object_id = None
        try:
            from urllib3.connection import HTTPSConnection
            if (http.client.HTTPConnection.debuglevel or http.client.HTTPSConnection.debuglevel
                    or HTTPSConnection.debuglevel
                    or logging.getLogger('urllib3.connectionpool').isEnabledFor(logging.DEBUG)):
                raise Incomplete('unsafe_http_diagnostics')
            with state['lock']:
                project, refs = _project(collector, scope)
                marker['native_requests'] = refs
                build = _json_get(transport, state, scope, 'https://cloudbuild.googleapis.com/v1/' + name,
                    {'fields': BUILD_FIELDS}, 'cloudbuild.builds.get.log_source', ident)
                if isinstance(build, dict) and build.get('options') == {'logging': 'CLOUD_LOGGING_ONLY'}:
                    marker['mode'] = 'cloud_logging_entries'
                    marker['build'] = {k: v for k, v in build.items() if k != 'logsBucket'}
                    marker['logging'] = logging_entries.collect(transport, state, scope, name, build, project, ident,
                        lambda: _json_get(transport, state, scope, 'https://cloudbuild.googleapis.com/v1/' + name,
                            {'fields': BUILD_FIELDS}, 'cloudbuild.builds.get.log_source_after', ident), logging_binding)
                    marker['complete'] = marker['logging']['complete']
                    marker['reason'] = marker['logging']['reason']
                else:
                    bucket, object_name = build_binding(build, name, project)
                    objects._bound_bucket(collector, scope, bucket)
                    bucket_row = next(r for r in collector.collections[('bucket', scope)]['items'] if r.get('name') == bucket)
                    if set(bucket_row.get('_coverage', {})) & {'name', 'projectNumber', '*'}:
                        raise Incomplete('bucket_binding_unavailable')
                    marker['native_requests'] += _refs(collector, 'bucket', scope, bucket_row,
                        'https://storage.googleapis.com/storage/v1/b', {'project': scope.split('/')[1], 'projection': 'full'})
                    target = {'project_scope': scope, 'bucket': bucket, 'object': object_name}
                    metadata = _json_get(transport, state, scope,
                        'https://storage.googleapis.com/storage/v1/b/' + quote(bucket, safe='') + '/o/' + quote(object_name, safe=''),
                        {'fields': objects.FIELDS, 'projection': 'noAcl'}, 'storage.objects.get.cloudbuild_log_generation', ident)
                    generation = metadata.get('generation')
                    if not isinstance(generation, str) or not objects._DECIMAL.fullmatch(generation):
                        raise Incomplete('generation_unavailable')
                    target['generation'] = generation
                    observed = objects._metadata(json.dumps(metadata).encode(), target)
                    if observed['size'] == 0:
                        raise Incomplete('empty_log')
                    object_id = objects.identity(target)
                    marker.update(build={k: v for k, v in build.items() if k != 'logsBucket'},
                                  bucket_sha256=hashlib.sha256(bucket.encode()).hexdigest(), generation=generation)
            # The reader owns the shared state lock and performs both pinned reads.
            if marker.get('mode') != 'cloud_logging_entries':
                facade = SimpleNamespace(options={'content_secret_scans': True,
                    '_content_secret_scan_kinds': [objects.KIND], objects.OPTION: [target]},
                    scopes=[scope], transport=transport, collections=collector.collections)
                selected, = objects.collect_selected_objects(facade, scope)
                marker['object'] = selected
                marker['complete'] = selected[objects.MARKER]['complete'] is True
                marker['reason'] = 'complete' if marker['complete'] else 'object_incomplete'
        except Incomplete as exc:
            marker['reason'] = str(exc)
        except Exception:
            marker['reason'] = 'source_unavailable'
        with transport.lock:
            receipts = [e for e in transport.evidence[start:] if e.get('scope') == scope
                        and e.get('resource_id') in (ident, object_id)]
            marker['read_receipts'] = [{k: e[k] for k in ('id', 'scope', 'method', 'operation', 'resource_id', 'status', 'http_status') if k in e}
                                       for e in receipts]
        marker['source_requests'] = sorted(set(marker['native_requests'] + [e['id'] for e in receipts]))
        result.append({'name': ident, MARKER: marker, '_coverage': {MARKER: {
            'status': 'collected' if marker['complete'] else 'unknown', 'source_requests': marker['source_requests']}}})
    return deepcopy(result)


def collection_pages(collector, scope):
    for row in collect_sources(collector, scope):
        refs = row[MARKER].get('source_requests', [])
        for ref in refs[:-1]:
            yield [], ref
        yield [row], refs[-1] if refs else 'local:cloudbuild_log_source_unavailable'


def jobs(collector, scope):
    """Run only after native project and bucket dependencies have completed."""
    if enabled(collector.options):
        return [(KIND, scope, 'cloudbuild', lambda: collection_pages(collector, scope))]
    return []
