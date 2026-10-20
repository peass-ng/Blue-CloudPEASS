"""Default-off exact Cloud Tasks FULL payload and BigQuery routine text reads.

Only redacted scan results and opaque resource identities survive the read.
No dispatch, execution, URL following, enumeration or credential validation.
"""
from copy import deepcopy
import base64
import binascii
import hashlib
import http.client
import json
import logging
import re
import threading
import time

from . import gcp_git_transport as git
from .gcp_cloudbuild_log_secret_indicators import _project
from .gcp_dataform_secret_indicators import _json
from .gcp_sourcerepo_secret_indicators import _remaining, _quota
from peaso.secret_scanning import scan_content, merge_leaks

TASK_KIND = 'cloudtasks_selected_task'
ROUTINE_KIND = 'bigquery_selected_routine'
MARKER = 'SelectedTaskRoutineSecretIndicators'
SCHEMA = 'gcp-selected-task-routine-secrets-v1'
MAX_SECONDS = 60
MAX_WIRE = 2097152
MAX_CONTENT = 262144
MAX_TOTAL = 2097152
MAX_LEAKS = 256
MAX_LOCATIONS = 512
Incomplete = git.Incomplete
_SCOPE = re.compile(r'projects/([a-z][a-z0-9-]{4,28}[a-z0-9])\Z')
SPECS = {
    TASK_KIND: {
        'option': 'selected_cloudtasks_tasks',
        'check': 'gcp.review.cloudtasks.selected_payload_secret_indicators',
        'pattern': re.compile(r'projects/([a-z][a-z0-9-]{4,28}[a-z0-9])/locations/[a-z][a-z0-9-]{0,62}/queues/[A-Za-z0-9-]{1,100}/tasks/[A-Za-z0-9_-]{1,500}\Z'),
        'base': 'https://cloudtasks.googleapis.com/v2/',
        'operation': 'cloudtasks.tasks.get.full', 'route': 'cloudtasks_exact_task_full_v2',
        'service': 'cloudtasks', 'label': 'selected task body and headers',
    },
    ROUTINE_KIND: {
        'option': 'selected_bigquery_routines',
        'check': 'gcp.review.bigquery.selected_routine_secret_indicators',
        'pattern': re.compile(r'projects/([a-z][a-z0-9-]{4,28}[a-z0-9])/datasets/[A-Za-z0-9_]{1,1024}/routines/[A-Za-z_][A-Za-z0-9_]{0,255}\Z'),
        'base': 'https://bigquery.googleapis.com/bigquery/v2/',
        'operation': 'bigquery.routines.get.definition', 'route': 'bigquery_exact_routine_v2',
        'service': 'bigquery', 'label': 'selected routine definition',
    },
}


def enabled(options, kind):
    kinds = options.get('_content_secret_scan_kinds')
    return options.get('content_secret_scans') is True and isinstance(kinds, list) and kind in kinds


def selected_targets(options, scopes, kind):
    """Validate all selected native names before credentials or transport."""
    if kind not in SPECS:
        raise Incomplete('invalid_selection')
    if not enabled(options, kind):
        return []
    names = options.get(SPECS[kind]['option'])
    if (not isinstance(scopes, list) or len(scopes) != 1 or not isinstance(scopes[0], str)
            or not _SCOPE.fullmatch(scopes[0]) or not isinstance(names, list) or not 1 <= len(names) <= 8):
        raise Incomplete('invalid_selection')
    seen = set()
    for name in names:
        match = SPECS[kind]['pattern'].fullmatch(name) if isinstance(name, str) else None
        if match is None or 'projects/' + match[1] != scopes[0] or name in seen:
            raise Incomplete('invalid_selection')
        seen.add(name)
    return list(names)


def identity(name, kind):
    return kind + ':' + hashlib.sha256(name.encode('utf-8')).hexdigest()


def selection_metadata(collector):
    result = {}
    for kind in SPECS:
        names = selected_targets(collector.options, collector.scopes, kind)
        result[kind + '_authorized'] = enabled(collector.options, kind)
        result[kind + '_selection'] = [identity(n, kind) for n in names]
    return result


def _text(value):
    if not isinstance(value, str):
        raise Incomplete('content_omitted')
    try:
        raw = value.encode('utf-8', errors='strict')
    except UnicodeError:
        raise Incomplete('unsupported_text') from None
    if len(raw) > MAX_CONTENT:
        raise Incomplete('content_byte_limit')
    if any(ord(c) < 32 and c not in '\t\r\n' or ord(c) == 127 for c in value):
        raise Incomplete('unsupported_binary')
    return raw


def content(data, name, kind):
    """Native identity and exact supported fields, before any detector call."""
    if kind == TASK_KIND:
        if data.get('name') != name or data.get('view') != 'FULL':
            raise Incomplete('task_identity_or_view')
        targets = [k for k in ('httpRequest', 'appEngineHttpRequest') if k in data]
        if len(targets) != 1 or not isinstance(data[targets[0]], dict):
            raise Incomplete('unsupported_task_target')
        target = data[targets[0]]
        encoded = target.get('body')
        if not isinstance(encoded, str) or len(encoded) > (MAX_CONTENT + 2) // 3 * 4:
            raise Incomplete('content_omitted_or_limit')
        try:
            body = base64.b64decode(encoded, validate=True)
            if base64.b64encode(body).decode() != encoded:
                raise ValueError()
            body = _text(body.decode('utf-8', errors='strict'))
        except (UnicodeError, ValueError, binascii.Error):
            raise Incomplete('unsupported_body_encoding') from None
        headers = target.get('headers', {})
        if (not isinstance(headers, dict) or len(headers) > 256
                or any(not isinstance(k, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}", k)
                       or not isinstance(v, str) or '\r' in v or '\n' in v for k, v in headers.items())
                or len({k.lower() for k in headers}) != len(headers)):
            raise Incomplete('unsupported_headers')
        header_bytes = _text(json.dumps(headers, sort_keys=True, ensure_ascii=False))
        parts = [('body', body), ('headers', header_bytes)]
    else:
        bits = name.split('/')
        if (data.get('routineReference') != {'projectId': bits[1], 'datasetId': bits[3], 'routineId': bits[5]}
                or data.get('routineType') not in {'SCALAR_FUNCTION', 'PROCEDURE', 'TABLE_VALUED_FUNCTION'}):
            raise Incomplete('routine_identity_or_type')
        if 'remoteFunctionOptions' in data or 'sparkOptions' in data:
            raise Incomplete('unsupported_external_definition')
        language = data.get('language', 'SQL')
        if language not in {'SQL', 'JAVASCRIPT', 'PYTHON', 'JAVA', 'SCALA'}:
            raise Incomplete('unsupported_language')
        body = _text(data.get('definitionBody'))
        if not body:
            raise Incomplete('content_omitted')
        parts = [('definition', body)]
    if sum(len(raw) for _, raw in parts) > MAX_CONTENT:
        raise Incomplete('content_byte_limit')
    return parts


def _get(transport, scope, name, kind, owner, deadline):
    """Dedicated uncached native GET; no arbitrary host, URL or projection input."""
    spec = SPECS[kind]
    url = spec['base'] + name
    params = {'responseView': 'FULL'} if kind == TASK_KIND else {}
    receipt = {'scope': scope, 'method': 'GET', 'operation': spec['operation'],
               'resource_id': owner, 'status': 'unavailable',
               'route': spec['route'], 'final_route_verified': False}
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
                    or int(length) > MAX_WIRE)):
            raise Incomplete('metadata_encoding_or_limit')
        chunks, count = [], 0
        while True:
            remaining = _remaining(transport, deadline)
            sock = getattr(getattr(getattr(getattr(response.raw, '_fp', None), 'fp', None), 'raw', None), '_sock', None)
            if sock is not None:
                sock.settimeout(remaining)
            chunk = response.raw.read(min(16384, MAX_WIRE - count + 1), decode_content=False)
            _remaining(transport, deadline)
            if not chunk:
                break
            if not isinstance(chunk, bytes) or count + len(chunk) > MAX_WIRE:
                raise Incomplete('metadata_byte_limit')
            count += len(chunk)
            chunks.append(chunk)
        if length is not None and int(length) != count:
            raise Incomplete('metadata_truncated')
        data = _json(b''.join(chunks))
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
        if session is not None:
            try:
                session.close()
            except Exception:
                pass
        with transport.lock:
            receipt['id'] = 'request-' + str(len(transport.evidence) + 1)
            transport.evidence.append(receipt)


def collect_sources(collector, scope, kind):
    if not enabled(collector.options, kind):
        return []
    names = selected_targets(collector.options, collector.scopes, kind)
    if scope != collector.scopes[0]:
        raise Incomplete('invalid_selection')
    transport = collector.transport
    with transport.lock:
        if not hasattr(transport, '_task_routine_secret_state'):
            transport._task_routine_secret_state = {'lock': threading.Lock(), 'items': {}}
        state = transport._task_routine_secret_state
    output = []
    # One deadline and aggregate content bound across both reader kinds.
    with state['lock']:
        state.setdefault('deadline', time.monotonic() + MAX_SECONDS)
        state.setdefault('bytes', 0)
        for name in names:
            ident = identity(name, kind)
            if ident in state['items']:
                output.append(deepcopy(state['items'][ident]))
                continue
            marker = {'schema': SCHEMA, 'kind': kind, 'complete': False, 'scope': scope,
                'identity': ident, 'parts': [], 'leaks': [], 'native_requests': [],
                'read_receipts': [], 'source_requests': [], 'reason': 'source_unavailable',
                'verification': 'not_attempted'}
            try:
                _remaining(transport, state['deadline'])
                project, refs = _project(collector, scope)
                if (project.get('projectId') != scope.split('/')[1]
                        or not re.fullmatch(r'projects/[1-9][0-9]{0,19}', project.get('name', ''))
                        or 'projectNumber' in project and project['projectNumber'] != project['name'].split('/')[1]
                        or len(refs) != 1):
                    raise Incomplete('project_binding')
                marker['native_requests'] = refs
                data = _get(transport, scope, name, kind, ident, state['deadline'])
                parts = content(data, name, kind)
                del data
                size = sum(len(raw) for _, raw in parts)
                if state['bytes'] + size > MAX_TOTAL:
                    raise Incomplete('aggregate_byte_limit')
                state['bytes'] += size
                leaks = []
                for part, raw in parts:
                    outcome = scan_content(raw, ident + '.' + part,
                        timeout=min(10, _remaining(transport, state['deadline']) / 2))
                    marker['parts'].append({'part': part, 'bytes': len(raw),
                        'complete': outcome['complete'], 'engines': outcome['engines']})
                    leaks.extend(outcome['leaks'])
                    if outcome['complete'] is not True:
                        raise Incomplete('detector_unavailable')
                del parts
                merged = merge_leaks(leaks)
                if len(merged) > MAX_LEAKS or sum(len(l['locations']) for l in merged) > MAX_LOCATIONS:
                    raise Incomplete('finding_limit')
                _remaining(transport, state['deadline'])
                marker.update(complete=True, reason='complete', leaks=merged)
            except Incomplete as exc:
                marker['reason'] = str(exc)
            except Exception:
                marker['reason'] = 'source_unavailable'
            with transport.lock:
                receipts = [deepcopy(e) for e in transport.evidence
                            if e.get('scope') == scope and e.get('resource_id') == ident]
            marker['read_receipts'] = receipts
            marker['source_requests'] = sorted(set(marker['native_requests'] + [e['id'] for e in receipts]))
            row = {'name': ident, MARKER: marker, '_coverage': {MARKER: {
                'status': 'collected' if marker['complete'] else 'unknown', 'source_requests': marker['source_requests']}}}
            state['items'][ident] = row
            output.append(deepcopy(row))
    return output


def collection_pages(collector, scope, kind):
    for row in collect_sources(collector, scope, kind):
        refs = row[MARKER]['source_requests']
        for ref in refs[:-1]:
            yield [], ref
        yield [row], refs[-1] if refs else 'local:task_routine_content_unavailable'


def jobs(collector, scope, kind):
    if enabled(collector.options, kind):
        return [(kind, scope, SPECS[kind]['service'], lambda: collection_pages(collector, scope, kind))]
    return []
