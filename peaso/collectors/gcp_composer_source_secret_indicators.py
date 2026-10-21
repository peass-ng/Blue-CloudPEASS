"""Opted-in native Composer DAG prefix reads; source text never enters JSON cache."""

from peaso.secret_evidence import scan_with_source, target_source
from copy import deepcopy
import hashlib
import http.client
import logging
import json
import re
import threading
import time
from urllib.parse import quote, urlsplit

from peaso.secret_scanning import scan_content, merge_leaks
from . import gcp_selected_object_secret_indicators as objects

KIND = 'composer_dag_source'
MARKER = 'ComposerSourceSecretIndicators'
SCHEMA = 'gcp-composer-dag-source-secrets-v1'
MAX_ENVIRONMENTS = 3
MAX_FILES = 6
MAX_PAGES = 3
MAX_LIST_BYTES = 16384
MAX_LEAKS = 256
MAX_LOCATIONS = 512
EXTENSIONS = {'.py', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.txt', '.sql', '.sqlx'}
Incomplete = objects.Incomplete


def enabled(options):
    return options.get('content_secret_scans') is True and KIND in options.get('_content_secret_scan_kinds', [])


def identity(owner):
    return 'composer-dag-source:' + hashlib.sha256(owner.encode()).hexdigest()


def _refs(collector, kind, scope, row, expected_url, query=None):
    collection = collector.collections.get((kind, scope), {})
    refs = row.get('_provenance', {}).get('source_requests', [])
    if collection.get('coverage_status') != 'collected' or not isinstance(refs, list) or not refs:
        raise Incomplete('native_source_unavailable')
    evidence = {r['id']: r for r in collector.transport.evidence}
    valid = []
    for ref in refs:
        e = evidence.get(ref, {})
        if (ref in collection.get('source_requests', []) and e.get('scope') == scope
                and e.get('method') == 'GET' and e.get('status') == 'collected'
                and e.get('url') == expected_url and not e.get('query', {}).get('fields')
                and (query is None or all(e.get('query', {}).get(k) == v for k, v in query.items()))):
            valid.append(ref)
    if not valid:
        raise Incomplete('native_source_unavailable')
    return valid


def _binding(collector, scope, row):
    if scope not in collector.scopes or not isinstance(scope, str) or not objects._SCOPE.fullmatch(scope):
        raise Incomplete('project_binding_unavailable')
    project_source = collector.collections.get(('project', scope), {})
    projects = project_source.get('items', [])
    if not isinstance(projects, list) or len(projects) != 1 or not isinstance(projects[0], dict):
        raise Incomplete('project_binding_unavailable')
    project = projects[0]
    aliases = {scope, project.get('name'), 'projects/' + str(project.get('projectId', ''))}
    name = row.get('name')
    if (not isinstance(name, str) or '/'.join(name.split('/')[:2]) not in aliases or not re.fullmatch(r'projects/(?:[a-z][a-z0-9-]{0,62}|[1-9][0-9]{0,19})' +
            r'/locations/[a-z][a-z0-9-]{0,62}/environments/[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?', name)):
        raise Incomplete('environment_identity_mismatch')
    parent = scope + '/' + name.split('/', 2)[2].rsplit('/', 1)[0]
    refs = _refs(collector, 'composer_environment', scope, row, 'https://composer.googleapis.com/v1/' + parent)
    config = row.get('config')
    if not isinstance(config, dict) or any(k in config.get('_coverage', {}) for k in ('dagGcsPrefix', '*')):
        raise Incomplete('dag_prefix_unavailable')
    if any(k in row.get('_coverage', {}) for k in ('name', 'config', '*')):
        raise Incomplete('dag_prefix_unavailable')
    prefix = config.get('dagGcsPrefix')
    if not isinstance(prefix, str) or len(prefix.encode()) > 1250:
        raise Incomplete('dag_prefix_unavailable')
    parsed = urlsplit(prefix)
    bucket, path = parsed.netloc, parsed.path.lstrip('/')
    if (parsed.scheme != 'gs' or parsed.query or parsed.fragment or parsed.username or parsed.port
            or not objects._BUCKET.fullmatch(bucket) or any(len(p) > 63 for p in bucket.split('.'))
            or not parsed.path.startswith('/') or parsed.path.startswith('//')
            or not path or '%' in path or '\\' in path or any(ord(c) < 32 or ord(c) == 127 for c in path)
            or any(p in ('.', '..', '') for p in path.rstrip('/').split('/'))):
        raise Incomplete('dag_prefix_unavailable')
    path = path.rstrip('/') + '/'
    objects._bound_bucket(collector, scope, bucket)
    project = collector.collections[('project', scope)]['items'][0]
    refs += _refs(collector, 'project', scope, project, 'https://cloudresourcemanager.googleapis.com/v3/' + scope)
    bucket_row = next(b for b in collector.collections[('bucket', scope)]['items'] if b.get('name') == bucket)
    refs += _refs(collector, 'bucket', scope, bucket_row,
                  'https://storage.googleapis.com/storage/v1/b', {'project': scope.split('/')[1], 'projection': 'full'})
    return bucket, path, sorted(set(refs))


def _pairs(pairs):
    output = {}
    for k, v in pairs:
        if k in output:
            raise Incomplete('malformed_list')
        output[k] = v
    return output


def _list(transport, state, scope, bucket, prefix, owner, token=None):
    """Dedicated uncached bounded metadata reader; no URL, names or cursors in receipts."""
    objects._check(transport, state)
    response = None
    receipt = {'scope': scope, 'method': 'GET', 'operation': 'storage.objects.list.composer_dags',
               'resource_id': identity(owner), 'status': 'unavailable'}
    try:
        with transport.lock:
            if state['calls'] >= objects.MAX_CALLS or transport.max_calls is not None and transport.calls >= transport.max_calls:
                raise Incomplete('call_limit')
            state['calls'] += 1
            transport.calls += 1
        from .gcp import native_header_session
        headers = dict(transport.credentials.headers())
        headers['Accept-Encoding'] = 'identity'
        if transport.options.get('quota_project'):
            headers['X-Goog-User-Project'] = transport.options['quota_project']
        params = {'prefix': prefix, 'maxResults': MAX_FILES + 1, 'projection': 'noAcl',
                  'fields': 'items(' + objects.FIELDS + '),nextPageToken'}
        if token is not None:
            params['pageToken'] = token
        response = native_header_session(transport).request('GET',
            'https://storage.googleapis.com/storage/v1/b/' + quote(bucket, safe='') + '/o',
            params=params, headers=headers, stream=True, allow_redirects=False, timeout=objects._remaining(transport, state))
        if response.status_code != 200:
            raise Incomplete('list_denied' if response.status_code in (401, 403) else 'list_unavailable')
        hdr = {k.lower(): v for k, v in response.headers.items()}
        length = hdr.get('content-length')
        if (hdr.get('content-encoding', 'identity').lower() != 'identity' or 'content-range' in hdr
                or length is not None and (not isinstance(length, str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', length)
                                           or int(length) > MAX_LIST_BYTES)):
            raise Incomplete('list_encoding_or_limit')
        chunks, count = [], 0
        while True:
            objects._check(transport, state)
            sock = getattr(getattr(getattr(getattr(response.raw, '_fp', None), 'fp', None), 'raw', None), '_sock', None)
            if sock is not None:
                sock.settimeout(objects._remaining(transport, state))
            chunk = response.raw.read(min(16384, MAX_LIST_BYTES - count + 1), decode_content=False)
            if not chunk:
                break
            if not isinstance(chunk, bytes):
                raise Incomplete('malformed_list')
            count += len(chunk)
            if count > MAX_LIST_BYTES:
                raise Incomplete('list_byte_limit')
            chunks.append(chunk)
        if length is not None and count != int(length):
            raise Incomplete('truncated_list')
        data = json.loads(b''.join(chunks).decode('utf-8'), object_pairs_hook=_pairs)
        if (not isinstance(data, dict) or set(data) - {'items', 'nextPageToken'}
                or not isinstance(data.get('items', []), list)):
            raise Incomplete('malformed_list')
        token = data.get('nextPageToken')
        if token is not None and (not isinstance(token, str) or not token or len(token.encode()) > 2048):
            raise Incomplete('malformed_list')
        receipt.update(status='collected', bytes=count)
        return data.get('items', []), token
    except Incomplete:
        raise
    except Exception:
        raise Incomplete('list_unavailable') from None
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        with transport.lock:
            receipt['id'] = 'request-' + str(len(transport.evidence) + 1)
            transport.evidence.append(receipt)


def collect_sources(collector, scope):
    if not enabled(collector.options):
        return []
    source = collector.collections.get(('composer_environment', scope), {})
    environments = source.get('items', [])
    if not isinstance(environments, list) or len(environments) > MAX_ENVIRONMENTS:
        environments = [{}]
    if not environments and source.get('coverage_status') != 'collected':
        environments = [{}]
    transport = collector.transport
    with transport.lock:
        if not hasattr(transport, '_selected_object_secret_state'):
            transport._selected_object_secret_state = {'started': time.monotonic(), 'bytes': 0,
                'calls': 0, 'lock': threading.Lock(), 'items': {}}
        state = transport._selected_object_secret_state
    result = []
    with state['lock']:
        for row in environments:
            if not isinstance(row, dict):
                row = {}
            owner = row.get('name', scope + '/composer-source-unavailable')
            if not isinstance(owner, str):
                owner = scope + '/composer-source-unavailable'
            ident = identity(owner)
            marker = {'schema': SCHEMA, 'identity': ident, 'owner': owner, 'scope': scope,
                'complete': False, 'status': 'incomplete', 'reason': 'source_unavailable',
                'verification': 'not_attempted', 'source_requests': [], 'native_requests': [], 'read_receipts': [],
                'files': [], 'engines': [], 'leaks': [], 'bytes': 0}
            start = len(transport.evidence)
            attempted = set()
            try:
                from urllib3.connection import HTTPSConnection as UrllibHTTPSConnection
                if (http.client.HTTPConnection.debuglevel or http.client.HTTPSConnection.debuglevel
                        or UrllibHTTPSConnection.debuglevel
                        or logging.getLogger('urllib3.connectionpool').isEnabledFor(logging.DEBUG)):
                    raise Incomplete('unsafe_http_diagnostics')
                if sum(isinstance(r, dict) and r.get('name') == owner for r in environments) != 1:
                    raise Incomplete('ambiguous_environment')
                bucket, prefix, refs = _binding(collector, scope, row)
                marker['source_requests'] = refs
                marker['native_requests'] = list(refs)
                files, names, tokens, token = [], set(), set(), None
                for page in range(MAX_PAGES):
                    entries, token = _list(transport, state, scope, bucket, prefix, owner, token)
                    if len(files) + len(entries) > MAX_FILES:
                        raise Incomplete('file_limit')
                    for entry in entries:
                        if not isinstance(entry, dict):
                            raise Incomplete('malformed_list')
                        name, generation = entry.get('name'), entry.get('generation')
                        if (not isinstance(name, str) or not name.startswith(prefix) or name in names
                                or len(name.encode()) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in name)
                                or any(p in ('', '.', '..') for p in name.split('/')) or '\\' in name
                                or not isinstance(generation, str) or not objects._DECIMAL.fullmatch(generation)
                                or '.' + name.rsplit('.', 1)[-1].lower() not in EXTENSIONS):
                            raise Incomplete('unsupported_or_foreign_object')
                        target = {'project_scope': scope, 'bucket': bucket, 'object': name, 'generation': generation}
                        metadata = objects._metadata(json.dumps(entry).encode(), target)
                        files.append((target, metadata))
                        names.add(name)
                    if token is None:
                        break
                    if token in tokens:
                        raise Incomplete('pagination_incomplete')
                    tokens.add(token)
                else:
                    raise Incomplete('pagination_incomplete')
                # A complete listing precedes all media. Each object is revalidated at its listed generation.
                leaks, engines = [], []
                for target, listed in files:
                    attempted.add(objects.identity(target))
                    metadata = objects._metadata(objects._read(transport, state, target), target)
                    if metadata != listed:
                        raise Incomplete('metadata_changed')
                    payload = objects._read(transport, state, target, media=True, expected=metadata)
                    objects._text(payload)
                    outcome = scan_with_source(scan_content,payload, 'composer.dag.content/' + objects.identity(target).split(':', 1)[1], timeout=min(5, objects._remaining(transport, state) / 2), source=target_source(target, resource_id=ident, scope=scope))
                    # The matched generation and media read are already bound. Keep
                    # redacted observations even if a detector or a later file fails.
                    leaks = merge_leaks(leaks + outcome['leaks'])
                    if len(leaks) > MAX_LEAKS or sum(len(x['locations']) for x in leaks) > MAX_LOCATIONS:
                        raise Incomplete('finding_limit')
                    marker['leaks'] = leaks
                    prior_engines = {e['engine']: e for e in marker['engines']}
                    marker['engines'] = [prior_engines.get(e['engine'], e)
                        if prior_engines.get(e['engine'], {}).get('status') == 'complete' else e
                        for e in outcome['engines']]
                    marker['bytes'] += len(payload)
                    marker['files'].append(objects.identity(target))
                    objects._check(transport, state)
                    if not outcome['complete']:
                        raise Incomplete('detector_unavailable')
                    engines = outcome['engines']
                if not files:
                    # Never use an empty prefix as a detector-backed clean content verdict.
                    raise Incomplete('empty_prefix')
                marker.update(complete=True, status='collected', reason='complete', engines=engines, leaks=leaks)
            except Incomplete as exc:
                marker['reason'] = str(exc)
            except Exception:
                marker['reason'] = 'source_unavailable'
            with transport.lock:
                reads = [e for e in transport.evidence[start:] if e.get('scope') == scope and (
                    e.get('operation') == 'storage.objects.list.composer_dags' and e.get('resource_id') == ident
                    or e.get('operation') in ('storage.objects.get.metadata', 'storage.objects.get.media')
                    and e.get('resource_id') in attempted)]
                marker['read_receipts'] = [{k: e[k] for k in ('id', 'scope', 'operation', 'resource_id', 'status')} for e in reads]
            marker['source_requests'] = sorted(set(marker['native_requests'] + [e['id'] for e in reads]))
            result.append({'name': ident, MARKER: marker,
                '_coverage': {MARKER: {'status': 'collected', 'source_requests': marker['source_requests']}}})
    return deepcopy(result)


def collection_pages(collector, scope):
    for row in collect_sources(collector, scope):
        refs = row[MARKER]['source_requests']
        for ref in refs[:-1]:
            yield [], ref
        yield [row], refs[-1] if refs else 'local:composer_dag_source'
