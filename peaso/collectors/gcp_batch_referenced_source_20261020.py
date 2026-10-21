"""Unregistered Batch host-script/GCS association proposal; GETs only.

Compose reviewed CRM/GCS streaming, metadata, text and scanner primitives.
Never synthesize parent collections, delegate optional kinds, or infer executed bytes.
"""

from peaso.secret_evidence import scan_with_source, target_source
from copy import deepcopy
from datetime import datetime, timezone
import http.client
import json
import logging
import re
import time
from urllib.parse import quote
from uuid import uuid4

from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint, redact_matches
from . import gcp_dataproc_referenced_source_secret_indicators as reads

objects = reads.objects
Incomplete = reads.Incomplete
SCHEMA = 'gcp-batch-referenced-source-v1'
MARKER = 'BatchReferencedSourceSecretIndicators'
KIND = 'batch_selected_mounted_script_source'
CHECK = 'gcp.review.batch.selected_mounted_script_source_secret_indicators'
OPTION = 'selected_batch_referenced_sources'
MAX_TARGETS, MAX_CALLS, MAX_SECONDS = 4, 36, 120
MAX_METADATA, MAX_CONTENT, MAX_TOTAL = 65536, 1048576, 8388608
MAX_LEAKS, MAX_LOCATIONS = 256, 512
SCOPE = reads.SCOPE
OPERATIONS = reads.OPERATIONS
_RESOURCE = re.compile(r'(projects/[a-z][a-z0-9-]{4,28}[a-z0-9])/locations/[a-z][a-z0-9-]{0,62}/jobs/[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
_REASONS = frozenset('invalid_selection reference_binding ambiguous_mount unsupported_mount_options unsupported_path native_identity project_binding bucket_binding object_changed association_changed bucket_changed project_changed empty_content finding_limit unavailable deadline invalid_route unsafe_http_diagnostics call_limit auth_unavailable principal_changed invalid_quota response_route denied native_unavailable framing_or_bound media_binding invalid_stream byte_limit truncated partial_native read_unavailable metadata_identity_mismatch oversize unsupported_format_or_encryption malformed_metadata unsupported_archive unsupported_utf8 unsupported_binary'.split())


def parse(target):
    if not isinstance(target, dict) or set(target) != {'resource', 'task_group', 'runnable', 'volume', 'bucket', 'object', 'generation'}:
        raise Incomplete('invalid_selection')
    match = _RESOURCE.fullmatch(target['resource']) if isinstance(target['resource'], str) else None
    if match is None or type(target['task_group']) is not int or target['task_group'] != 0:
        raise Incomplete('invalid_selection')
    if any(type(target[k]) is not int or not 0 <= target[k] < 100 for k in ('runnable', 'volume')):
        raise Incomplete('invalid_selection')
    # Reuse only the low-level GCS selector; this does not invoke a producer.
    try:
        objects.selected_targets({'content_secret_scans': True, '_content_secret_scan_kinds': [objects.KIND],
            objects.OPTION: [dict(project_scope=match[1], **{k: target[k] for k in ('bucket', 'object', 'generation')})]}, [match[1]])
        _path(target['object'])
    except (UnicodeError, ValueError, TypeError):
        raise Incomplete('invalid_selection') from None
    if int(target['generation']) > 9223372036854775807:
        raise Incomplete('invalid_selection')
    return match[1]


def identity(target):
    return KIND + ':' + _fingerprint(json.dumps(target, sort_keys=True, separators=(',', ':')))


def selected_targets(options, scopes):
    if (not isinstance(options, dict) or not isinstance(scopes, list) or not 1 <= len(scopes) <= 8
            or any(not isinstance(s, str) or not SCOPE.fullmatch(s) for s in scopes) or len(set(scopes)) != len(scopes)
            or 'content_secret_scans' in options and type(options['content_secret_scans']) is not bool):
        raise Incomplete('invalid_selection')
    if OPTION not in options:
        return []
    targets = options[OPTION]
    if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS:
        raise Incomplete('invalid_selection')
    seen = set()
    for target in targets:
        if parse(target) not in scopes or identity(target) in seen:
            raise Incomplete('invalid_selection')
        seen.add(identity(target))
    return deepcopy(targets)


def enabled(options, named):
    # Explicit public check selection only; private kinds/inventory/category cannot admit IO.
    return options.get('content_secret_scans') is True and isinstance(named, (list, tuple)) and CHECK in named


def _path(value, absolute=False):
    if (not isinstance(value, str) or not value or len(value.encode('utf-8')) > 2048
            or value.startswith('/') != absolute or value.endswith('/')
            or any(c in value for c in '%?#\\:$~') or any(ord(c) <= 32 or ord(c) == 127 for c in value)
            or any(p in ('', '.', '..') for p in value.split('/')[1 if absolute else 0:])):
        raise Incomplete('unsupported_path')
    return value


def reference(data, target, project):
    """Bind the actual Job UID, task-group, selected runnable and native volume.

    uid is an opaque native string, NOT a documented UUID. Path is a host path,
    NOT a gs:// URI. Reject any overlapping mount instead of guessing precedence.
    """
    scope = parse(target)
    suffix = target['resource'][len(scope):]
    if (data.get('name') not in (target['resource'], project['name'] + suffix)
            or not isinstance(data.get('uid'), str) or not 1 <= len(data['uid']) <= 256
            or any(ord(c) < 33 or ord(c) > 126 for c in data['uid'])):
        raise Incomplete('native_identity')
    groups = data.get('taskGroups')
    if not isinstance(groups, list) or len(groups) != 1 or not isinstance(groups[0], dict):
        raise Incomplete('reference_binding')
    group = groups[0]
    group_name = group.get('name')
    if (not isinstance(group_name, str) or not group_name.startswith(data['name'] + '/taskGroups/')
            or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', group_name[len(data['name'] + '/taskGroups/'):])
            or not isinstance(group.get('taskSpec'), dict)):
        raise Incomplete('reference_binding')
    spec = group['taskSpec']; runnables = spec.get('runnables'); volumes = spec.get('volumes')
    if (not isinstance(runnables, list) or not 1 <= len(runnables) <= 100
            or any(not isinstance(r, dict) for r in runnables) or target['runnable'] >= len(runnables)
            or not isinstance(volumes, list) or not 1 <= len(volumes) <= 100
            or any(not isinstance(v, dict) for v in volumes) or target['volume'] >= len(volumes)):
        raise Incomplete('reference_binding')
    runnable = runnables[target['runnable']]
    if (set(runnable) & {'script', 'container', 'barrier'} != {'script'}
            or not isinstance(runnable.get('script'), dict) or set(runnable['script']) != {'path'}):
        raise Incomplete('reference_binding')
    path = _path(runnable['script']['path'], True)
    for volume in volumes:
        _path(volume.get('mountPath'), True)
        if set(volume) & {'gcs', 'nfs', 'deviceName'} not in ({'gcs'}, {'nfs'}, {'deviceName'}):
            raise Incomplete('reference_binding')
    volume = volumes[target['volume']]
    mount = volume['mountPath']
    if (set(volume) - {'mountPath', 'mountOptions', 'gcs'} or not isinstance(volume.get('gcs'), dict)
            or set(volume['gcs']) != {'remotePath'} or not path.startswith(mount + '/')):
        raise Incomplete('reference_binding')
    if 'mountOptions' in volume and volume['mountOptions'] != []:
        # Includes only-dir/endpoint/implicit-dirs/symlink/cache options: no option interpretation.
        raise Incomplete('unsupported_mount_options')
    if any(i != target['volume'] and
           (v['mountPath'] == mount or v['mountPath'].startswith(mount + '/') or mount.startswith(v['mountPath'] + '/'))
           for i, v in enumerate(volumes)):
        raise Incomplete('ambiguous_mount')
    remote = volume['gcs']['remotePath']
    if not isinstance(remote, str):
        raise Incomplete('reference_binding')
    # Native remotePath is bucket[/prefix/], WITHOUT gs://. A trailing slash
    # is a directory delimiter, never URL decoding or path normalization.
    remote = remote[:-1] if remote.endswith('/') else remote
    _path(remote)
    bucket, sep, prefix = remote.partition('/')
    name = (prefix + '/' if sep else '') + path[len(mount) + 1:]
    if bucket != target['bucket'] or name != target['object']:
        raise Incomplete('reference_binding')
    binding = dict(name=data['name'], uid=data['uid'], group=group_name,
        task_group=target['task_group'], runnable=target['runnable'], volume_index=target['volume'],
        script=runnable['script'], volume=volume)
    return _fingerprint(json.dumps(binding, sort_keys=True, separators=(',', ':')))


def _job_read(transport, state, ident, scope, operation, target):
    """Only exact native jobs.get; no user-provided URL or generalized HTTP API."""
    parse(target)
    url = 'https://batch.googleapis.com/v1/' + target['resource']
    receipt = dict(id='batch-source-read:' + uuid4().hex, identity=ident, scope=scope,
        capture=state['capture'], operation=operation, method='GET', origin='batch.googleapis.com',
        request=_fingerprint(url + '\n{}'), principal=None, bound=False, status='unavailable', bytes=0)
    state['ledger'].append(receipt)
    response = session = None
    try:
        reads.remaining(transport, state)
        _diagnostics()
        with transport.lock:
            if state['calls'] >= MAX_CALLS or transport.max_calls is not None and transport.calls >= transport.max_calls:
                raise Incomplete('call_limit')
            state['calls'] += 1; transport.calls += 1
        auth = transport.credentials.headers().get('Authorization')
        if not isinstance(auth, str) or not re.fullmatch(r'Bearer [A-Za-z0-9._~+/-]+=*', auth) or len(auth) > 16384:
            raise Incomplete('auth_unavailable')
        principal = _fingerprint(auth)
        if state.setdefault('principal', principal) != principal:
            raise Incomplete('principal_changed')
        receipt['principal'] = principal
        headers = {'Authorization': auth, 'Accept': 'application/json', 'Accept-Encoding': 'identity', 'Cache-Control': 'no-store'}
        quota = transport.options.get('quota_project')
        if quota is not None:
            if not isinstance(quota, str) or not re.fullmatch(r'[a-z][a-z0-9-]{4,28}[a-z0-9]|[1-9][0-9]{0,19}', quota):
                raise Incomplete('invalid_quota')
            headers['X-Goog-User-Project'] = quota
        session = reads.git._session()
        response = session.request('GET', url, params={}, headers=headers, stream=True,
            allow_redirects=False, timeout=reads.remaining(transport, state))
        if response.url != url or response.history:
            raise Incomplete('response_route')
        if response.status_code != 200:
            raise Incomplete('denied' if response.status_code in (401, 403) else 'native_unavailable')
        hdr = {k.lower(): v for k, v in response.headers.items()}; length = hdr.get('content-length')
        if (not isinstance(length, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', length) or int(length) > MAX_METADATA
                or hdr.get('content-encoding', 'identity').lower() != 'identity'
                or any(h in hdr for h in ('content-range', 'transfer-encoding', 'location', 'link'))
                or hdr.get('content-type', '').split(';')[0].strip().lower() != 'application/json'):
            raise Incomplete('framing_or_bound')
        raw = bytearray()
        while True:
            timeout = reads.remaining(transport, state)
            sock = getattr(getattr(getattr(getattr(response.raw, '_fp', None), 'fp', None), 'raw', None), '_sock', None)
            if sock is not None:
                sock.settimeout(timeout)
            chunk = response.raw.read(min(16384, MAX_METADATA + 1 - len(raw)), decode_content=False)
            reads.remaining(transport, state)
            if not isinstance(chunk, bytes):
                raise Incomplete('invalid_stream')
            if not chunk:
                break
            raw.extend(chunk); state['bytes'] += len(chunk); receipt['bytes'] = len(raw)
            if len(raw) > MAX_METADATA or state['bytes'] > MAX_TOTAL:
                raise Incomplete('byte_limit')
        if len(raw) != int(length):
            raise Incomplete('truncated')
        result = reads._json(bytes(raw))
        if any(k in result for k in ('error', 'nextPageToken', 'unreachable', 'unreachables', 'warning', '_coverage', 'partial')):
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


def _bucket(project, data, bucket):
    # Native returned fields only. No manufactured parent collection facade.
    if set(data) != {'name', 'projectNumber'} or data['name'] != bucket or data['projectNumber'] != project['name'].split('/')[1]:
        raise Incomplete('bucket_binding')
    return data


def _diagnostics():
    from urllib3.connection import HTTPSConnection
    if (http.client.HTTPConnection.debuglevel or http.client.HTTPSConnection.debuglevel or HTTPSConnection.debuglevel
            or logging.getLogger('urllib3.connectionpool').getEffectiveLevel() <= logging.DEBUG):
        raise Incomplete('unsafe_http_diagnostics')


def collect(transport, options, scopes, *, named=()):
    """One optional batch -> sanitized self-contained evidence, no registration.

    Targets validate before credential access even when supplied but disabled.
    The caller can merge other readers' redaction values through finalize().
    """
    targets = selected_targets(options, scopes)
    if not enabled(options, named):
        return {'authorized': False, 'capture': None, 'selected': {}, 'items': [], 'receipts': []}
    if not targets:
        raise Incomplete('invalid_selection')
    state = dict(capture=uuid4().hex, deadline=time.monotonic() + MAX_SECONDS, calls=0, bytes=0, ledger=[], redactions=set())
    items = []
    try:
        for target in targets:
            scope = parse(target); ident = identity(target); start = len(state['ledger'])
            marker = dict(schema=SCHEMA, identity=ident, scope=scope, capture=state['capture'], complete=False,
                native_complete=False, association=None, generation=target['generation'], parts=[], leaks=[],
                source_requests=[], verification='not_attempted', reason='unavailable', captured_at=None, executed_bytes_proven=False)
            payload = None
            try:
                def get(op, url, params, expected=None):
                    _diagnostics()
                    return reads._read(transport, state, ident, scope, op, url, params, expected)
                def bound(): state['ledger'][-1]['bound'] = True
                project_url = 'https://cloudresourcemanager.googleapis.com/v3/' + scope
                project_params = {'fields': 'name,projectId,state'}
                project = reads._project(get('project_before', project_url, project_params), scope); bound()
                association = reference(_job_read(transport, state, ident, scope, 'reference_before', target), target, project); bound()
                bucket_url = 'https://storage.googleapis.com/storage/v1/b/' + quote(target['bucket'], safe='')
                bucket_params = {'fields': 'name,projectNumber', 'projection': 'noAcl'}
                bucket = _bucket(project, get('bucket_before', bucket_url, bucket_params), target['bucket']); bound()
                object_url = bucket_url + '/o/' + quote(target['object'], safe='')
                metadata_params = {'fields': objects.FIELDS, 'projection': 'noAcl'}
                object_target = {k: target[k] for k in ('bucket', 'object', 'generation')}
                before = get('latest_before', object_url, metadata_params)
                metadata = objects._metadata(json.dumps(before).encode(), object_target)
                if metadata['size'] == 0: raise Incomplete('empty_content')
                bound()
                payload = get('content', object_url, {'generation': target['generation'], 'ifGenerationMatch': target['generation'], 'alt': 'media'},
                    {**metadata, 'generation': target['generation']})
                objects._text(payload); bound()
                after = get('latest_after', object_url, metadata_params)
                objects._metadata(json.dumps(after).encode(), object_target)
                if after != before: raise Incomplete('object_changed')
                bound()
                if reference(_job_read(transport, state, ident, scope, 'reference_after', target), target, project) != association:
                    raise Incomplete('association_changed')
                bound()
                if _bucket(project, get('bucket_after', bucket_url, bucket_params), target['bucket']) != bucket:
                    raise Incomplete('bucket_changed')
                bound()
                if reads._project(get('project_after', project_url, project_params), scope) != project:
                    raise Incomplete('project_changed')
                bound()
                marker.update(native_complete=True, association=association, captured_at=datetime.now(timezone.utc).isoformat())
                outcome = scan_with_source(scan_content, payload, ident + '.source', timeout=min(10, reads.remaining(transport, state) / 2),
                    _redact_values=state['redactions'].update, source=target_source(target, resource_id=ident, scope=scope))
                reads.remaining(transport, state)
                leaks = merge_leaks(outcome['leaks'])
                if len(leaks) > MAX_LEAKS or sum(len(l['locations']) for l in leaks) > MAX_LOCATIONS:
                    raise Incomplete('finding_limit')
                marker.update(parts=[dict(bytes=metadata['size'], complete=outcome['complete'], engines=outcome['engines'])],
                    leaks=leaks, complete=outcome['complete'], reason='complete' if outcome['complete'] else 'detector_unavailable')
            except Incomplete as exc:
                marker['reason'] = str(exc) if str(exc) in _REASONS else 'unavailable'
            except Exception:
                marker['reason'] = 'unavailable'
            finally:
                payload = None
            marker['source_requests'] = [r['id'] for r in state['ledger'][start:]]
            items.append({'name': ident, MARKER: marker})
        return dict(authorized=True, capture=state['capture'],
            selected={s: [identity(t) for t in targets if parse(t) == s] for s in scopes}, items=items, receipts=state['ledger'])
    finally:
        # Union stays transient on the transport only until the mandatory finalizer.
        with transport.lock:
            existing = getattr(transport, '_batch_source_redactions', set())
            transport._batch_source_redactions = existing | state['redactions']
        state['redactions'].clear()


def finalize(transport, evidence, *, metadata=None, options=None, redactions=()):
    """Redact export AND retained cache/evidence/options, then erase our match set.

    Other active readers supply their transient union before cleanup. This
    unregistered entrypoint intentionally cannot finish a production snapshot.
    """
    values = set(getattr(transport, '_batch_source_redactions', ())) | set(redactions)
    try:
        if isinstance(options, dict): options.pop(OPTION, None)
        transport.options.pop(OPTION, None)
        for field in ('cache', 'evidence', 'options'):
            setattr(transport, field, redact_matches(getattr(transport, field), values))
        public_options = {k: v for k, v in (options or {}).items()
                          if isinstance(k, str) and not k.startswith('_') and k != 'cancel_event'}
        return redact_matches(dict(evidence=deepcopy(evidence), metadata=metadata or {}, options=public_options), values)
    finally:
        pending = getattr(transport, '_batch_source_redactions', None)
        if pending is not None:
            pending.clear(); delattr(transport, '_batch_source_redactions')
        values.clear()
