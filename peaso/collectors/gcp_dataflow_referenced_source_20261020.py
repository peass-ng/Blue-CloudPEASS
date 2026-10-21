"""Unregistered, explicit Dataflow package capture proposal; no runtime wiring.

Native uncached exact GETs produce this reader's own receipts. Source bytes live
only in memory; no generic collector context or other reader receipts are made.
"""

from peaso.secret_evidence import scan_with_source, target_source
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import http.client
import json
import logging
import re
import time
from types import FunctionType, SimpleNamespace
from urllib.parse import quote, urlsplit
from uuid import uuid4
from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint
from . import gcp_selected_object_secret_indicators as objects
from . import gcp_selected_archive_secret_indicators as archives
from . import gcp_git_transport as git
from .gcp_dataform_secret_indicators import _json

SCHEMA = 'gcp-dataflow-referenced-source-20261020-v1'
CHECK = 'gcp.review.dataflow.selected_package_referenced_source_secret_indicators'
OPTION = 'selected_dataflow_referenced_sources'
MAX_TARGETS, MAX_CALLS, MAX_SECONDS = 4, 36, 120
MAX_METADATA, MAX_CONTENT, MAX_TOTAL = 65536, 1048576, 8388608
MAX_LEAKS, MAX_LOCATIONS = 256, 512
SCOPE = re.compile(r'projects/([a-z][a-z0-9-]{4,28}[a-z0-9])\Z')
OPERATIONS = ('project_before', 'reference_before', 'bucket_before', 'latest_before', 'content',
              'latest_after', 'reference_after', 'bucket_after', 'project_after')
Incomplete = objects.Incomplete

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

def _read(transport, state, ident, scope, operation, url, params, expected=None):
    """Internally constructed exact route; raw/error/credential bytes never cached."""
    remaining(transport, state)
    origin = urlsplit(url).netloc
    if origin not in {'cloudresourcemanager.googleapis.com', 'dataflow.googleapis.com', 'storage.googleapis.com'}:
        raise Incomplete('invalid_route')
    receipt = dict(id='dataflow-source-read:' + uuid4().hex, identity=ident, scope=scope,
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

def _project(data, scope):
    if (set(data) != {'name', 'projectId', 'state'} or data.get('projectId') != scope.split('/')[1]
            or not isinstance(data.get('name'), str) or not re.fullmatch(r'projects/[1-9][0-9]{0,19}', data['name'])
            or data.get('state') != 'ACTIVE'):
        raise Incomplete('project_binding')
    return data

def _bucket(project, data, scope, bucket):
    _project(project, scope)
    if (set(data) != {'name', 'projectNumber'} or data.get('name') != bucket
            or data.get('projectNumber') != project['name'].split('/')[1]):
        raise Incomplete('bucket_binding')
    return data


def parse(target):
    if not isinstance(target, dict) or set(target) != {'resource', 'worker_pool', 'package', 'name', 'bucket', 'object', 'generation', 'format'}:
        raise Incomplete('invalid_selection')
    resource = target['resource']
    match = re.fullmatch(r'(projects/[a-z][a-z0-9-]{4,28}[a-z0-9])/locations/[a-z][a-z0-9-]{0,62}/jobs/[A-Za-z0-9_-]{1,100}', resource) if isinstance(resource, str) else None
    if (match is None or any(type(target[k]) is not int or not 0 <= target[k] < 100 for k in ('worker_pool', 'package'))
            or not isinstance(target['name'], str) or not re.fullmatch(r'[A-Za-z0-9_.+-]{1,256}', target['name'])
            or not isinstance(target['format'], str) or target['format'] not in {'text', 'zip', 'tar', 'tar.gz'}):
        raise Incomplete('invalid_selection')
    # Same reviewed GCS syntax; no other reader's opt-in or collector is made.
    bucket, name, generation = (target[k] for k in ('bucket', 'object', 'generation'))
    try:
        size = len(name.encode('utf-8')) if isinstance(name, str) else 0
    except UnicodeError:
        raise Incomplete('invalid_selection') from None
    if (not isinstance(bucket, str) or not objects._BUCKET.fullmatch(bucket)
            or any(len(p) > 63 for p in bucket.split('.')) or not isinstance(name, str) or not 1 <= size <= 1024
            or not isinstance(generation, str) or not objects._DECIMAL.fullmatch(generation)
            or int(generation) > 9223372036854775807
            or any(c in name for c in '%?#\\') or any(ord(c) < 32 or ord(c) == 127 for c in name)
            or any(p in ('', '.', '..') for p in name.split('/'))):
        raise Incomplete('invalid_selection')
    return match[1]


def identity(target):
    return 'dataflow-source:' + _fingerprint(json.dumps(target, sort_keys=True, separators=(',', ':')))


def selection(scopes, options, check_ids):
    """No default/category/private-kind authorization: exact named check only."""
    if not isinstance(options, dict) or type(options.get('content_secret_scans', False)) is not bool:
        raise Incomplete('invalid_selection')
    authorized = options.get('content_secret_scans') is True and check_ids == [CHECK]
    if OPTION not in options and not authorized:
        return [], False
    rows = options.get(OPTION)
    if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 8
            or any(not isinstance(s, str) or not SCOPE.fullmatch(s) for s in scopes)
            or len(scopes) != len(set(scopes)) or not isinstance(rows, list) or not 1 <= len(rows) <= MAX_TARGETS):
        raise Incomplete('invalid_selection')
    seen = set()
    for row in rows:
        scope = parse(row)
        # A second format/generation for the same selected native slot is ambiguous.
        slot = (row['resource'], row['worker_pool'], row['package'])
        if scope not in scopes or slot in seen:
            raise Incomplete('invalid_selection')
        seen.add(slot)
    return deepcopy(rows), authorized


def reference(data, target):
    scope = parse(target)
    resource = target['resource'].split('/')
    if (data.get('projectId') != scope.split('/')[1] or data.get('id') != resource[-1]
            or data.get('location') != resource[3]
            or data.get('currentState') not in {'JOB_STATE_RUNNING', 'JOB_STATE_DONE', 'JOB_STATE_FAILED', 'JOB_STATE_CANCELLED', 'JOB_STATE_UPDATED', 'JOB_STATE_DRAINED'}
            or not isinstance(data.get('createTime'), str)):
        raise Incomplete('native_identity')
    try:
        if datetime.fromisoformat(data['createTime']).utcoffset() is None:
            raise ValueError('timezone')
        pools = data['environment']['workerPools']
        if not isinstance(pools, list) or not 1 <= len(pools) <= 100 or target['worker_pool'] >= len(pools):
            raise ValueError('pools')
        packages = pools[target['worker_pool']]['packages']
        if not isinstance(packages, list) or not 1 <= len(packages) <= 100 or target['package'] >= len(packages):
            raise ValueError('packages')
        package = packages[target['package']]
        bucket, name = target['bucket'], target['object']
        # Exact SDK/documented GCS spellings only; never follow this URL.
        paths = {host + '/' + name for host in ('storage.googleapis.com/' + bucket, bucket + '.storage.googleapis.com')}
        locations = paths | {'https://' + p for p in paths}
        checksum = package.get('sha256')
        if (set(package) - {'name', 'location', 'sha256'} or package.get('name') != target['name']
                or package.get('location') not in locations
                or checksum is not None and (not isinstance(checksum, str) or not re.fullmatch('[0-9a-fA-F]{64}', checksum))):
            raise ValueError('package')
        stable = dict(resource=target['resource'], created=data['createTime'], worker_pool=target['worker_pool'], package_index=target['package'], package=package)
        return _fingerprint(json.dumps(stable, sort_keys=True)), checksum
    except (KeyError, TypeError, ValueError, IndexError):
        raise Incomplete('reference_binding') from None


def inspect_payload(payload, target, transport, state, item):
    """Reuse immutable memory parsers with a local callback, retaining partial hits."""
    partial_class_content = False
    def inspect_text(raw, _name, requests=None):
        nonlocal partial_class_content
        remaining(transport, state)
        if _name.lower().endswith('.class'):
            from peaso.jvm_class_constant_text_20261021 import extract_constant_text
            # Constant-pool text is useful evidence, never complete bytecode coverage.
            raw = extract_constant_text(bytes(raw))
            partial_class_content = True
        if (len(raw) > archives.MAX_MEMBER_BYTES
                or _name.lower().endswith(('.zip', '.tar', '.tar.gz', '.tgz', '.gz', '.bz2', '.xz', '.7z', '.rar', '.bin', '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.exe', '.dll', '.so', '.pyc', '.wasm'))):
            raise Incomplete('unsupported_member')
        objects._text(bytes(raw))
        path = item['identity'] + '.part-' + str(len(item['parts']) + 1)
        outcome = scan_with_source(scan_content, bytes(raw), path, timeout=min(10, remaining(transport, state) / 2), source=target_source(target, resource_id=item['identity'], path=_name))
        item['parts'].append(dict(path=path, bytes=len(raw), engines=outcome['engines'], complete=outcome['complete']))
        merged = merge_leaks(item['leaks'] + outcome['leaks'])
        if len(merged) > MAX_LEAKS or sum(len(l['locations']) for l in merged) > MAX_LOCATIONS:
            raise Incomplete('finding_limit')
        item['leaks'] = merged
        remaining(transport, state)
        return []
    if target['format'] == 'text':
        inspect_text(payload, 'source')
        item['complete'] = all(p['complete'] for p in item['parts'])
        return
    expanded_cap = min(archives.MAX_EXPANDED_BYTES, archives.MAX_TOTAL_EXPANDED_BYTES - state['expanded'])
    member_cap = min(archives.MAX_MEMBERS, archives.MAX_TOTAL_MEMBERS - state['members'])
    if expanded_cap <= 0 or member_cap <= 0:
        raise Incomplete('archive_total_limit')
    parser = archives.scan_zip if target['format'] == 'zip' else archives.scan_tar
    local = dict(parser.__globals__, _scan=inspect_text, EXPANDED_LIMIT=expanded_cap, MEMBER_LIMIT=member_cap,
                 ZIP_LIMIT=MAX_CONTENT, LAYER_LIMIT=MAX_CONTENT)
    if target['format'] == 'tar.gz':
        local['EXPANDED_LIMIT'] = min(expanded_cap, max(1024, len(payload) * archives.MAX_RATIO))
    bounded = FunctionType(parser.__code__, local, parser.__name__, parser.__defaults__, parser.__closure__)
    facade = SimpleNamespace(check_deadline=lambda: remaining(transport, state))
    charged_expanded, charged_members = expanded_cap, member_cap
    try:
        if target['format'] == 'zip':
            _, charged_expanded, charged_members = bounded(payload, facade)
        else:
            mime = 'application/vnd.oci.image.layer.v1.tar' + ('+gzip' if target['format'] == 'tar.gz' else '')
            _, charged_expanded, charged_members = bounded(payload, mime, facade)
        item['complete'] = bool(item['parts']) and not partial_class_content and all(p['complete'] for p in item['parts'])
    finally:
        state['expanded'] += charged_expanded
        state['members'] += charged_members


def capture(transport, scopes, options, check_ids):
    """Optional reader proposal entry; returns only its native receipts and findings.

    No scheduler/registry integration. The caller must not persist raw options.
    Existing Transport provides auth/cancellation/call and deadline accounting;
    requests bypass its metadata cache to keep bodies and URLs transient.
    """
    targets, authorized = selection(scopes, options, check_ids)
    state = dict(capture=uuid4().hex, deadline=time.monotonic() + MAX_SECONDS,
                 calls=0, bytes=0, ledger=[], expanded=0, members=0)
    result = dict(schema=SCHEMA, capture=state['capture'], authorized=authorized,
                  selected=[identity(t) for t in targets] if authorized else [], items=[], receipts=state['ledger'])
    if not authorized:
        return result
    for target in targets:
        ident, scope = identity(target), parse(target)
        item = dict(identity=ident, scope=scope, capture=state['capture'], native_complete=False, complete=False,
                    association=None, generation=target['generation'], format=target['format'], source_bytes=0, parts=[], leaks=[], requests=[],
                    reason='unavailable', captured_at=None, executed_bytes_proven=False, credential_validation='not_attempted')
        start = len(state['ledger'])
        payload = None
        try:
            def get(op, url, params, expected=None):
                return _read(transport, state, ident, scope, op, url, params, expected)
            def bound():
                state['ledger'][-1]['bound'] = True
            project_url = 'https://cloudresourcemanager.googleapis.com/v3/' + scope
            project_params = {'fields': 'name,projectId,state'}
            project = _project(get('project_before', project_url, project_params), scope); bound()
            native_url = 'https://dataflow.googleapis.com/v1b3/' + target['resource']
            native_params = {'view': 'JOB_VIEW_ALL'}
            association, checksum = reference(get('reference_before', native_url, native_params), target); bound()
            bucket_url = 'https://storage.googleapis.com/storage/v1/b/' + quote(target['bucket'], safe='')
            bucket_params = {'fields': 'name,projectNumber', 'projection': 'noAcl'}
            bucket = _bucket(project, get('bucket_before', bucket_url, bucket_params), scope, target['bucket']); bound()
            object_url = bucket_url + '/o/' + quote(target['object'], safe='')
            metadata_params = {'fields': objects.FIELDS, 'projection': 'noAcl'}
            before = get('latest_before', object_url, metadata_params)
            base = {k: target[k] for k in ('bucket', 'object', 'generation')}
            metadata = (objects._metadata(json.dumps(before).encode(), base) if target['format'] == 'text' else
                        archives._native_metadata(json.dumps(before).encode(), {**base, 'format': target['format']}))
            if metadata['size'] == 0:
                raise Incomplete('empty_content')
            bound()
            payload = get('content', object_url, {'generation': target['generation'], 'ifGenerationMatch': target['generation'], 'alt': 'media'}, {**metadata, 'generation': target['generation']})
            if checksum is not None and hashlib.sha256(payload).hexdigest() != checksum.lower():
                raise Incomplete('package_checksum')
            bound()
            if get('latest_after', object_url, metadata_params) != before:
                raise Incomplete('object_changed')
            bound()
            if reference(get('reference_after', native_url, native_params), target) != (association, checksum):
                raise Incomplete('association_changed')
            bound()
            if _bucket(project, get('bucket_after', bucket_url, bucket_params), scope, target['bucket']) != bucket:
                raise Incomplete('bucket_changed')
            bound()
            if _project(get('project_after', project_url, project_params), scope) != project:
                raise Incomplete('project_changed')
            bound()
            item.update(native_complete=True, association=association, source_bytes=len(payload), captured_at=datetime.now(timezone.utc).isoformat())
            inspect_payload(payload, target, transport, state, item)
            item['reason'] = 'complete' if item['complete'] else 'detector_or_content_incomplete'
        except Exception:
            # Native/provider/parser messages can contain source or credentials.
            item['complete'] = False
            item['reason'] = 'capture_incomplete'
        finally:
            payload = None
        item['requests'] = [r['id'] for r in state['ledger'][start:]]
        result['items'].append(item)
    return result
