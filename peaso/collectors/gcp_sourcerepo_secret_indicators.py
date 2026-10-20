"""Default-off bounded CSR selected-file adapter; explicit root installation only.

Git bytes stay in memory. Existing detector-private ephemeral input handling is
reused; only opaque paths, native binding and redacted findings survive.
"""
from copy import deepcopy
import hashlib
import http.client
import json
import logging
import re
import threading
import time

from . import gcp_git_content as content
from . import gcp_git_transport as git
from .gcp_cloudbuild_log_secret_indicators import _project
from .gcp_dataform_secret_indicators import _json
from peaso.secret_scanning import scan_content, merge_leaks

KIND = 'source_repository_file'
OPTION = 'selected_source_repository_files'
MARKER = 'SourceRepositoryFileSecretIndicators'
SCHEMA = 'gcp-sourcerepo-selected-file-secrets-v1'
MAX_SECONDS = 60
MAX_METADATA = 16384
MAX_LEAKS = 256
MAX_LOCATIONS = 512
Incomplete = git.Incomplete
_SCOPE = re.compile(r'projects/([a-z][a-z0-9-]{4,28}[a-z0-9])\Z')
_REPO = re.compile(r'projects/([a-z][a-z0-9-]{4,28}[a-z0-9])/repos/([A-Za-z0-9_.-]{1,100})\Z')


def enabled(options):
    kinds = options.get('_content_secret_scan_kinds')
    return options.get('content_secret_scans') is True and isinstance(kinds, list) and KIND in kinds


def selected_targets(options, scopes):
    """Entire public selection is validated before any credentials/session."""
    if not enabled(options):
        return []
    rows = options.get(OPTION)
    if (not isinstance(scopes, list) or len(scopes) != 1 or not isinstance(scopes[0], str)
            or not _SCOPE.fullmatch(scopes[0]) or not isinstance(rows, list) or len(rows) != 1):
        raise Incomplete('invalid_selection')
    row = rows[0]
    if not isinstance(row, dict) or set(row) != {'repository', 'commit', 'paths'}:
        raise Incomplete('invalid_selection')
    match = _REPO.fullmatch(row['repository']) if isinstance(row['repository'], str) else None
    if match is None or 'projects/' + match[1] != scopes[0] or match[2] in ('.', '..'):
        raise Incomplete('invalid_selection')
    try:
        paths = content.validate_selection(row['commit'], row['paths'])
    except content.GitContentError:
        raise Incomplete('invalid_selection') from None
    if not isinstance(row['paths'], list) or row['commit'] == '0' * 40:
        raise Incomplete('invalid_selection')
    return [{'repository': row['repository'], 'commit': row['commit'], 'paths': list(paths)}]


def path_identity(path):
    return hashlib.sha256(path.encode('utf-8')).hexdigest()


def selection(target):
    return {'repository': target['repository'], 'commit': target['commit'],
            'paths_sha256': [path_identity(p) for p in target['paths']]}


def identity(selected):
    return 'sourcerepo-selected-files:' + hashlib.sha256(json.dumps(selected,
        sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def blob_identity(selected, path_hash, blob_sha, size):
    return 'sourcerepo-selected-blob:' + hashlib.sha256(json.dumps(
        [selected['repository'], selected['commit'], path_hash, blob_sha, size],
        separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def selection_metadata(collector):
    rows = selected_targets(collector.options, collector.scopes)
    return {'source_repository_file_authorized': enabled(collector.options),
            'source_repository_file_selection': selection(rows[0]) if rows else None}


def clone_url(repository):
    match = _REPO.fullmatch(repository)
    if match is None:
        raise Incomplete('repository_binding')
    return 'https://source.developers.google.com/p/' + match[1] + '/r/' + match[2]


def _remaining(transport, deadline):
    transport.check_cancelled()
    seconds = deadline - time.monotonic()
    if transport.deadline is not None:
        seconds = min(seconds, transport.deadline - time.time())
    if transport.deadline_seconds is not None:
        seconds = min(seconds, transport.deadline_seconds - (time.monotonic() - transport.started))
    if seconds <= 0:
        raise Incomplete('content_deadline')
    return min(transport.timeout, seconds)


def _quota(value):
    if (not isinstance(value, str)
            or not re.fullmatch(r'(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[1-9][0-9]{0,19})', value)):
        raise Incomplete('quota_project_invalid')
    return value


def _repo_get(transport, scope, target, owner, deadline):
    """Dedicated uncached native GET; no arbitrary host, URL or projection input."""
    url = 'https://sourcerepo.googleapis.com/v1/' + target['repository']
    params = {'fields': 'name,url'}
    receipt = {'scope': scope, 'method': 'GET', 'operation': 'sourcerepo.repos.get.selected_files',
               'resource_id': owner, 'status': 'unavailable',
               'route': 'csr_native_repo_name_url_v1', 'final_route_verified': False}
    response = session = None
    try:
        _remaining(transport, deadline)
        from urllib3.connection import HTTPSConnection
        if (http.client.HTTPConnection.debuglevel or http.client.HTTPSConnection.debuglevel
                or HTTPSConnection.debuglevel or logging.getLogger('urllib3.connectionpool').isEnabledFor(logging.DEBUG)):
            raise Incomplete('unsafe_http_diagnostics')
        with transport.lock:
            if transport.max_calls is not None and transport.calls >= transport.max_calls:
                raise Incomplete('call_limit')
            transport.calls += 1
        configured_quota = transport.options.get('quota_project')
        if configured_quota is not None:
            _quota(configured_quota)
        headers = transport.credentials.headers()
        authorization = headers.get('Authorization')
        if not isinstance(authorization, str) or not re.fullmatch(r'Bearer [A-Za-z0-9._~+/-]+=*', authorization):
            raise Incomplete('credential_unavailable')
        native_quotas = [v for k, v in headers.items() if k.lower() == 'x-goog-user-project']
        if any(_quota(v) != v for v in native_quotas) or len(set(native_quotas)) > 1:
            raise Incomplete('quota_project_invalid')
        quota = configured_quota if configured_quota is not None else native_quotas[0] if native_quotas else None
        request_headers = {'Authorization': authorization, 'Accept': 'application/json',
                           'Accept-Encoding': 'identity', 'Cache-Control': 'no-store'}
        if quota is not None:
            request_headers['X-Goog-User-Project'] = quota
        session = git._session()
        response = session.request('GET', url, params=params,
            headers=request_headers,
            stream=True, allow_redirects=False, timeout=_remaining(transport, deadline))
        receipt['http_status'] = response.status_code
        import requests
        if response.url != requests.Request('GET', url, params=params).prepare().url or response.history:
            raise Incomplete('metadata_response_identity')
        receipt['final_route_verified'] = True
        if response.status_code != 200:
            raise Incomplete('metadata_denied' if response.status_code in (401, 403) else 'metadata_unavailable')
        hdr = {k.lower(): v for k, v in response.headers.items()}
        length = hdr.get('content-length')
        if (hdr.get('content-type', '').split(';')[0].strip().lower() != 'application/json'
                or hdr.get('content-encoding', 'identity').lower() != 'identity' or 'content-range' in hdr
                or length is not None and (not isinstance(length, str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', length)
                    or int(length) > MAX_METADATA)):
            raise Incomplete('metadata_encoding_or_limit')
        chunks, count = [], 0
        while True:
            remaining = _remaining(transport, deadline)
            sock = getattr(getattr(getattr(getattr(response.raw, '_fp', None), 'fp', None), 'raw', None), '_sock', None)
            if sock is not None:
                sock.settimeout(remaining)
            chunk = response.raw.read(min(16384, MAX_METADATA - count + 1), decode_content=False)
            _remaining(transport, deadline)
            if not chunk:
                break
            if not isinstance(chunk, bytes) or count + len(chunk) > MAX_METADATA:
                raise Incomplete('metadata_byte_limit')
            count += len(chunk)
            chunks.append(chunk)
        if length is not None and int(length) != count:
            raise Incomplete('metadata_truncated')
        repo = _json(b''.join(chunks))
        if set(repo) != {'name', 'url'} or repo['name'] != target['repository'] or repo['url'] != clone_url(target['repository']):
            raise Incomplete('repository_binding')
        receipt.update(status='collected', bytes=count)
        return repo
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
        if session is not None:
            try:
                session.close()
            except Exception:
                pass
        with transport.lock:
            receipt['id'] = 'request-' + str(len(transport.evidence) + 1)
            transport.evidence.append(receipt)


def collect_sources(collector, scope):
    if not enabled(collector.options):
        return []
    try:
        target, = selected_targets(collector.options, collector.scopes)
        if scope != collector.scopes[0]:
            raise Incomplete('invalid_selection')
    except Incomplete:
        return [{'name': 'sourcerepo-selection-unavailable', MARKER: {
            'schema': SCHEMA, 'complete': False, 'reason': 'invalid_selection'}}]
    transport = collector.transport
    with transport.lock:
        if not hasattr(transport, '_sourcerepo_secret_state'):
            transport._sourcerepo_secret_state = {'lock': threading.Lock(), 'items': {}}
        state = transport._sourcerepo_secret_state
    selected = selection(target)
    ident = identity(selected)
    with state['lock']:
        if ident in state['items']:
            return deepcopy([state['items'][ident]])
        deadline = time.monotonic() + MAX_SECONDS
        if transport.deadline is not None:
            deadline = min(deadline, time.monotonic() + transport.deadline - time.time())
        if transport.deadline_seconds is not None:
            deadline = min(deadline, transport.started + transport.deadline_seconds)
        marker = {'schema': SCHEMA, 'complete': False, 'scope': scope, 'selection': selected,
            'repository': {}, 'files': [], 'leaks': [], 'native_requests': [], 'read_receipts': [],
            'source_requests': [], 'reason': 'source_unavailable', 'verification': 'not_attempted',
            'content_accounting': {}}
        start = len(transport.evidence)
        git_owner = 'sourcerepo-content:' + hashlib.sha256((target['repository'] + ':' + target['commit']).encode()).hexdigest()
        try:
            _remaining(transport, deadline)
            project, refs = _project(collector, scope)
            if (project.get('projectId') != scope.split('/')[1]
                    or not re.fullmatch(r'projects/[1-9][0-9]{0,19}', project.get('name', ''))
                    or 'projectNumber' in project and project['projectNumber'] != project['name'].split('/')[1]
                    or len(refs) != 1):
                raise Incomplete('project_binding')
            marker['native_requests'] = refs
            marker['repository'] = _repo_get(transport, scope, target, ident, deadline)
            pack = git.fetch_pack(transport, scope, target['repository'], target['commit'], enabled=True, deadline=deadline)
            decoded = content.decode_selected_files(pack, target['commit'], target['paths'],
                cancelled=lambda: (_remaining(transport, deadline), False)[1], deadline=deadline)
            del pack
            marker['content_accounting'] = {'commit_sha': decoded.commit_sha,
                'object_count': decoded.object_count, 'inflated_bytes': decoded.inflated_bytes,
                'wire_bytes': decoded.wire_bytes, 'selected_bytes': decoded.selected_bytes}
            outcomes = []
            for selected_file in decoded.files:
                payload = selected_file.content
                try:
                    text = payload.decode('utf-8', errors='strict')
                except UnicodeError:
                    raise Incomplete('unsupported_text') from None
                if any(ord(c) < 32 and c not in '\t\r\n' or ord(c) == 127 for c in text):
                    raise Incomplete('unsupported_binary')
                del text
                path_hash = path_identity(selected_file.path)
                outcome = scan_content(payload, 'sourcerepo.selected_file.' + path_hash,
                    timeout=min(10, _remaining(transport, deadline) / 2))
                marker['files'].append({'path_sha256': path_hash, 'blob_sha1': selected_file.object_sha,
                    'identity': blob_identity(selected, path_hash, selected_file.object_sha, len(payload)),
                    'bytes': len(payload), 'complete': outcome['complete'], 'engines': outcome['engines']})
                # Retain only redacted observations after this blob's native
                # commit/path binding and content validation have succeeded.
                combined = merge_leaks(outcomes + outcome['leaks'])
                kept, remaining_locations = [], MAX_LOCATIONS
                for leak in combined[:MAX_LEAKS]:
                    if not remaining_locations:
                        break
                    locations = leak['locations'][:remaining_locations]
                    kept.append(dict(leak, locations=locations))
                    remaining_locations -= len(locations)
                marker['leaks'] = kept
                outcomes = kept
                if combined != kept:
                    raise Incomplete('finding_limit')
                _remaining(transport, deadline)
            leaks = merge_leaks(outcomes)
            if len(leaks) > MAX_LEAKS or sum(len(x['locations']) for x in leaks) > MAX_LOCATIONS:
                raise Incomplete('finding_limit')
            _remaining(transport, deadline)
            complete = all(file['complete'] is True for file in marker['files'])
            marker.update(complete=complete,
                          reason='complete' if complete else 'detectors_incomplete', leaks=leaks)
        except (Incomplete, content.GitContentError) as exc:
            marker['reason'] = str(exc)
        except Exception:
            marker['reason'] = 'source_unavailable'
        with transport.lock:
            receipts = [e for e in transport.evidence[start:] if e.get('scope') == scope
                        and e.get('resource_id') in (ident, git_owner)]
            marker['read_receipts'] = [{k: e[k] for k in ('id', 'scope', 'method', 'operation', 'resource_id',
                'status', 'http_status', 'bytes', 'route', 'final_route_verified') if k in e} for e in receipts]
        marker['source_requests'] = sorted(set(marker['native_requests'] + [e['id'] for e in receipts]))
        row = {'name': ident, MARKER: marker, '_coverage': {MARKER: {
            'status': 'collected' if marker['complete'] else 'unknown', 'source_requests': marker['source_requests']}}}
        state['items'][ident] = row
        return deepcopy([row])


def collection_pages(collector, scope):
    for row in collect_sources(collector, scope):
        refs = row[MARKER].get('source_requests', [])
        for ref in refs[:-1]:
            yield [], ref
        yield [row], refs[-1] if refs else 'local:sourcerepo_selected_files_unavailable'


def jobs(collector, scope):
    if enabled(collector.options):
        return [(KIND, scope, 'sourcerepo', lambda: collection_pages(collector, scope))]
    return []
