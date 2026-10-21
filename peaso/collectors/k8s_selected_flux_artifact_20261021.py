"""Exact Flux source-controller artifact inspection through the Kubernetes API Service proxy."""
from copy import deepcopy
from hashlib import sha256
import json
import re
import time
from types import FunctionType
from urllib.parse import urlsplit

from peaso.secret_evidence import scan_with_source
from peaso.secret_scanning import scan_content, merge_leaks
from .aws_package_content_indicators import scan_tar, scan_zip, PartialArchive

KIND = 'k8s_selected_flux_artifact'
CHECK = 'k8s.review.selected_flux_artifact_secret_indicators'
OPTION = 'selected_k8s_flux_artifacts'
SCHEMA = 'k8s-selected-flux-artifact-v1'
MAX_TARGETS = 2
MAX_BYTES = 12 * 1024 * 1024
MAX_EXPANDED = 8 * 1024 * 1024
MAX_MEMBERS = 100
MAX_MEMBER = 1024 * 1024
MAX_SECONDS = 90
MAX_CALLS = 10
MAX_REDACTION_VALUES = 512
MAX_REDACTION_BYTES = 65536
LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
SEGMENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,255}\Z')
FIELDS = {'cluster_id', 'kind', 'namespace', 'name', 'uid', 'resource_version', 'generation',
          'artifact_digest', 'artifact_revision', 'artifact_path', 'artifact_size',
          'service_namespace', 'service_uid', 'service_resource_version', 'service_port_name'}


class Incomplete(ValueError):
    """Fixed code only; no URLs, response text or detected values."""


class RedactionOverflow(BaseException):
    """Abort snapshot output when detected values cannot all be redacted."""


def redaction_callback(matches):
    """Keep the full bounded plaintext union only until snapshot finalization."""
    def add(values):
        if type(values) not in (set, frozenset):
            raise RedactionOverflow('redaction_ledger_bound')
        try:
            fresh = values - matches
            if (any(type(value) is not str or not value or len(value.encode('utf-8')) > 8192
                    for value in fresh) or len(matches) + len(fresh) > MAX_REDACTION_VALUES
                    or sum(len(value.encode('utf-8')) for value in matches) +
                       sum(len(value.encode('utf-8')) for value in fresh) > MAX_REDACTION_BYTES):
                raise RedactionOverflow('redaction_ledger_bound')
        except (TypeError, UnicodeError):
            raise RedactionOverflow('redaction_ledger_bound') from None
        matches.update(fresh)
    return add


def _path(value, kind, namespace, name):
    if (type(value) is not str or len(value) > 1024 or not value.startswith(kind.lower() + '/' + namespace + '/' + name + '/')
            or any(not SEGMENT.fullmatch(part) or part in ('.', '..') for part in value.split('/'))
            or not value.endswith(('.tar.gz', '.tgz', '.zip'))):
        raise Incomplete('invalid_artifact_path')
    return value


def selected_targets(options, scopes, named=()):
    if type(options) is not dict or ('content_secret_scans' in options and type(options['content_secret_scans']) is not bool):
        raise Incomplete('invalid_selection')
    if OPTION not in options and not (options.get('content_secret_scans') is True and CHECK in named):
        return []
    rows = options.get(OPTION)
    if (type(rows) is not list or not 1 <= len(rows) <= MAX_TARGETS or type(scopes) is not list
            or not 1 <= len(scopes) <= 8 or any(type(s) is not str or not LABEL.fullmatch(s) for s in scopes)):
        raise Incomplete('invalid_selection')
    seen = set()
    for row in rows:
        if type(row) is not dict or set(row) != FIELDS:
            raise Incomplete('invalid_selection')
        if (type(row['cluster_id']) is not str or not 1 <= len(row['cluster_id']) <= 512
                or not row['cluster_id'].isascii() or any(ord(c) < 33 or ord(c) > 126 for c in row['cluster_id'])
                or row['kind'] not in ('GitRepository', 'HelmChart')
                or any(type(row[f]) is not str or not LABEL.fullmatch(row[f]) for f in
                       ('namespace', 'name', 'service_namespace', 'service_port_name'))
                or row['namespace'] not in scopes or row['service_namespace'] not in scopes
                or any(type(row[f]) is not str or not TOKEN.fullmatch(row[f]) for f in
                       ('uid', 'resource_version', 'service_uid', 'service_resource_version'))
                or type(row['generation']) is not int or not 1 <= row['generation'] <= 10**15
                or type(row['artifact_size']) is not int or not 0 < row['artifact_size'] <= MAX_BYTES
                or type(row['artifact_digest']) is not str or not DIGEST.fullmatch(row['artifact_digest'])
                or type(row['artifact_revision']) is not str or not 1 <= len(row['artifact_revision']) <= 256
                or not row['artifact_revision'].isascii()
                or any(ord(c) < 33 or ord(c) > 126 for c in row['artifact_revision'])):
            raise Incomplete('invalid_selection')
        _path(row['artifact_path'], row['kind'], row['namespace'], row['name'])
        if row['kind'] == 'GitRepository' and not row['artifact_path'].endswith('.tar.gz'):
            raise Incomplete('unsupported_artifact_format')
        if row['kind'] == 'HelmChart' and not row['artifact_path'].endswith('.tgz'):
            raise Incomplete('unsupported_artifact_format')
        key = (row['cluster_id'], row['kind'], row['namespace'], row['name'])
        if key in seen:
            raise Incomplete('duplicate_selection')
        seen.add(key)
    return deepcopy(rows)


def enabled(options, named):
    return options.get('content_secret_scans') is True and CHECK in named


def identity(target):
    return 'k8s-flux-artifact:' + sha256(json.dumps(target, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def source_path(target):
    plural = 'gitrepositories' if target['kind'] == 'GitRepository' else 'helmcharts'
    return '/apis/source.toolkit.fluxcd.io/v1/namespaces/' + target['namespace'] + '/' + plural + '/' + target['name']


def service_path(target):
    return '/api/v1/namespaces/' + target['service_namespace'] + '/services/source-controller'


def proxy_path(target):
    return service_path(target).replace('/services/source-controller',
        '/services/http:source-controller:' + target['service_port_name'] + '/proxy/' + target['artifact_path'])


def _bind_source(target, source):
    try:
        if source.get('apiVersion') != 'source.toolkit.fluxcd.io/v1' or source.get('kind') != target['kind']:
            raise ValueError()
        meta, status = source['metadata'], source['status']
        if (meta['namespace'] != target['namespace'] or meta['name'] != target['name']
                or meta['uid'] != target['uid'] or meta['resourceVersion'] != target['resource_version']
                or meta['generation'] != target['generation'] or meta.get('deletionTimestamp') is not None
                or status['observedGeneration'] != target['generation']
                or not any(c.get('type') == 'Ready' and c.get('status') == 'True'
                           and c.get('observedGeneration', target['generation']) == target['generation']
                           for c in status['conditions'])):
            raise ValueError()
        artifact = status['artifact']
        if (artifact['digest'] != target['artifact_digest'] or artifact['revision'] != target['artifact_revision']
                or artifact['path'] != target['artifact_path'] or artifact['size'] != target['artifact_size']):
            raise ValueError()
        parsed = urlsplit(artifact['url'])
        hosts = {'source-controller.' + target['service_namespace'] + '.svc.cluster.local',
                 'source-controller.' + target['service_namespace'] + '.svc.cluster.local.'}
        if (parsed.scheme != 'http' or parsed.hostname not in hosts or parsed.port not in (None, 80)
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path != '/' + target['artifact_path']):
            raise ValueError()
        return {'uid': meta['uid'], 'resource_version': meta['resourceVersion'],
                'generation': meta['generation'], 'digest': artifact['digest'],
                'revision': artifact['revision'], 'path': artifact['path'], 'size': artifact['size'],
                'service_host': parsed.hostname}
    except (KeyError, TypeError, ValueError, AttributeError):
        raise Incomplete('flux_source_unbound') from None


def _bind_service(target, service):
    try:
        if service.get('apiVersion') != 'v1' or service.get('kind') != 'Service':
            raise ValueError()
        meta, spec = service['metadata'], service['spec']
        if (meta['namespace'] != target['service_namespace'] or meta['name'] != 'source-controller'
                or meta['uid'] != target['service_uid'] or meta['resourceVersion'] != target['service_resource_version']
                or meta.get('deletionTimestamp') is not None or spec['type'] != 'ClusterIP'
                or spec.get('externalIPs') or spec.get('externalName')):
            raise ValueError()
        selector = spec['selector']
        if not isinstance(selector, dict) or not (selector.get('app') == 'source-controller'
                or selector.get('app.kubernetes.io/name') == 'source-controller'):
            raise ValueError()
        ports = [p for p in spec['ports'] if p.get('name') == target['service_port_name']]
        if len(ports) != 1 or ports[0].get('port') != 80 or ports[0].get('protocol') != 'TCP':
            raise ValueError()
        return {'uid': meta['uid'], 'resource_version': meta['resourceVersion'],
                'namespace': meta['namespace'], 'name': meta['name'], 'port_name': ports[0]['name']}
    except (KeyError, TypeError, ValueError, AttributeError):
        raise Incomplete('flux_service_unbound') from None


class _Deadline:
    def __init__(self, check): self.check = check
    def check_deadline(self): self.check()


def _scan(raw, target, check, scanner, redact_values=None):
    """Use the accepted bounded TAR/ZIP parser and both offline secret engines."""
    findings, parts = [], []
    ident = identity(target)
    def visit(payload, name, requests):
        requests.check_deadline()
        if len(payload) > MAX_MEMBER or name.lower().endswith(('.tar', '.tar.gz', '.tgz', '.zip', '.gz', '.bz2', '.xz', '.7z', '.rar', '.bin', '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.exe', '.dll', '.so', '.class', '.pyc', '.wasm')):
            raise Incomplete('nested_or_binary_member')
        if not payload or any(b < 32 and b not in (9, 10, 13) or b == 127 for b in payload):
            raise Incomplete('binary_member_uninspected')
        try: payload.decode('utf-8')
        except UnicodeError: raise Incomplete('binary_member_uninspected') from None
        path = ident + '.member-' + str(len(parts) + 1)
        source = {'resource_id': ident, 'scope': target['cluster_id'] + '/' + target['namespace'],
                  'artifact_digest': target['artifact_digest'], 'path': name}
        outcome = (scanner(bytes(payload), path, source, check) if redact_values is None else
                   scanner(bytes(payload), path, source, check, redact_values=redact_values))
        parts.append({'part': path, 'bytes': len(payload), 'engines': outcome['engines'], 'complete': outcome['complete']})
        findings.extend(outcome['leaks'])
        if len(findings) > 256 or sum(len(f.get('locations', [])) for f in findings) > 2000:
            raise Incomplete('finding_bound')
        if outcome['complete'] is not True:
            raise PartialArchive([{'leaks': outcome['leaks']}] if outcome['leaks'] else [], 0, 0)
        requests.check_deadline()
        return [{'leaks': outcome['leaks']}] if outcome['leaks'] else []
    parser = scan_zip if target['artifact_path'].endswith('.zip') else scan_tar
    bounds = dict(parser.__globals__, _scan=visit, EXPANDED_LIMIT=MAX_EXPANDED,
                  MEMBER_LIMIT=MAX_MEMBERS, ZIP_LIMIT=MAX_BYTES, LAYER_LIMIT=MAX_BYTES)
    bounded = FunctionType(parser.__code__, bounds, parser.__name__, parser.__defaults__, parser.__closure__)
    try:
        if parser is scan_zip:
            refs, expanded, members = bounded(raw, _Deadline(check))
        else:
            refs, expanded, members = bounded(raw, 'application/vnd.oci.image.layer.v1.tar+gzip', _Deadline(check))
        if not parts: raise Incomplete('no_regular_text_members')
        return merge_leaks([leak for ref in refs for leak in ref['leaks']]), parts, True
    except PartialArchive as partial:
        return merge_leaks([leak for ref in partial.refs for leak in ref['leaks']]), parts, False


def _default_scanner(raw, path, source, check, *, redact_values=None):
    check()
    result = scan_with_source(scan_content, raw, path, source=source, timeout=15,
                              _redact_values=redact_values)
    check()
    return result


def inspect(target, source_get, service_get, proxy_get, *, scanner=_default_scanner,
            cancel=lambda: None, redact_values=None):
    ident = identity(target)
    marker = {'schema': SCHEMA, 'identity': ident, 'status': 'UNKNOWN', 'complete': False,
              'reason': 'unavailable', 'digest': target['artifact_digest'], 'revision': target['artifact_revision'],
              'native_before': None, 'native_after': None, 'service_before': None, 'service_after': None,
              'read': None, 'parts': [], 'leaks': []}
    deadline = time.monotonic() + MAX_SECONDS
    def check():
        cancel()
        if time.monotonic() >= deadline: raise Incomplete('deadline')
    bound = False
    try:
        before = _bind_source(target, source_get(target))
        service_before = _bind_service(target, service_get(target))
        marker['native_before'], marker['service_before'] = before, service_before
        check()
        raw = proxy_get(target)
        if type(raw) is not bytes or len(raw) != target['artifact_size'] or len(raw) > MAX_BYTES:
            raise Incomplete('artifact_truncated')
        if 'sha256:' + sha256(raw).hexdigest() != target['artifact_digest']:
            raise Incomplete('artifact_digest_mismatch')
        marker['read'] = {'method': 'GET', 'path': proxy_path(target), 'digest': target['artifact_digest'],
                          'size': len(raw), 'status': 'collected'}
        leaks, parts, complete = _scan(raw, target, check, scanner, redact_values)
        marker['leaks'], marker['parts'], marker['complete'] = leaks, parts, complete
        after_service = _bind_service(target, service_get(target))
        after = _bind_source(target, source_get(target))
        marker['native_after'], marker['service_after'] = after, after_service
        bound = after == before and after_service == service_before
        if not bound: raise Incomplete('flux_binding_changed')
        marker['status'] = 'FAIL' if leaks else 'PASS' if complete else 'UNKNOWN'
        marker['reason'] = 'complete' if complete else 'archive_incomplete'
    except Exception as exc:
        # Keep the reader's cancellation/deadline terminal, allowing collect()
        # to clear the redaction ledger and restore temporary path grants.
        if getattr(exc, 'code', None) in ('collection_cancelled', 'deadline_exceeded'):
            raise
        marker['reason'] = str(exc) if type(exc) is Incomplete else 'inspection_unavailable'
        marker['complete'] = False
        if marker['native_before'] is not None and marker['service_before'] is not None:
            try:
                after_service = _bind_service(target, service_get(target))
                after = _bind_source(target, source_get(target))
                marker['native_after'], marker['service_after'] = after, after_service
                bound = after == marker['native_before'] and after_service == marker['service_before']
            except Exception:
                bound = False
        if bound and marker['leaks'] and marker['read'] is not None:
            marker['status'] = 'FAIL'
    return marker


def _native_bytes(reader, api, cluster, target, state):
    """Bounded service-proxy binary GET on the existing authenticated transport."""
    from . import k8s_selected_log_sample_secret_indicators as native
    client, pool, host, headers, binding = native._context(api, cluster)
    if state.get('context') not in (None, binding): raise Incomplete('authentication_context_changed')
    state['context'] = binding
    headers.update({'Accept': 'application/gzip, application/octet-stream', 'Accept-Encoding': 'identity'})
    response = None
    try:
        def request():
            if state['calls'] >= MAX_CALLS: raise Incomplete('native_call_limit')
            state['calls'] += 1
            try:
                return pool.request('GET', host.rstrip('/') + proxy_path(target), headers=headers, fields={},
                    preload_content=False, decode_content=False,
                    timeout=max(.1, min(10, state['deadline'] - time.monotonic())))
            except Exception:
                raise Incomplete('native_transport_unavailable') from None
        response = reader.call(request)
        if response.status != 200:
            raise Incomplete('artifact_denied' if response.status in (401, 403) else 'artifact_redirect' if 300 <= response.status < 400 else 'artifact_unavailable')
        if response.headers.get('Content-Encoding', 'identity') != 'identity' or response.headers.get('Content-Range') is not None:
            raise Incomplete('artifact_framing')
        length = response.headers.get('Content-Length')
        if length is not None and (not isinstance(length, str) or not length.isdecimal()
                or int(length) != target['artifact_size']):
            raise Incomplete('artifact_framing')
        chunks, count = [], 0
        while True:
            reader.check_cancelled()
            if time.monotonic() >= state['deadline']: raise Incomplete('deadline')
            chunk = response.read(min(65536, target['artifact_size'] + 1 - count))
            if type(chunk) is not bytes: raise Incomplete('artifact_stream')
            if not chunk: break
            count += len(chunk)
            state['bytes'] += len(chunk)
            if count > target['artifact_size'] or state['bytes'] > MAX_BYTES + 4 * 1024 * 1024:
                raise Incomplete('artifact_byte_bound')
            chunks.append(chunk)
        if count != target['artifact_size']: raise Incomplete('artifact_truncated')
        return b''.join(chunks)
    finally:
        if response is not None:
            try: response.close()
            finally: response.release_conn()
        client.last_response = None


def collect(reader, api, options, scopes, cluster):
    named = options.get('_flux_artifact_named_checks', [])
    targets = selected_targets(options, scopes, named)
    if not enabled(options, named): return {}, set()
    from . import k8s_selected_log_sample_secret_indicators as native
    client, pool, _, _, _ = native._context(api, cluster)
    paths = {path for target in targets for path in (source_path(target), service_path(target), proxy_path(target))}
    old_paths = pool.literal_paths
    pool.literal_paths = frozenset(set(old_paths) | paths)
    metadata = {KIND + '_authorized': True, OPTION: deepcopy(targets)}
    grouped = {}
    matches = set()
    add_redactions = redaction_callback(matches)
    try:
        with native.private_native_logs():
            for target in targets:
                if target['cluster_id'] != cluster: continue
                if reader.budget.max_items is not None and reader.total + sum(len(v) for v in grouped.values()) + 1 > reader.budget.max_items:
                    raise Incomplete('resource_limit')
                state = {'deadline': time.monotonic() + MAX_SECONDS, 'calls': 0, 'bytes': 0, 'context': None}
                def source_get(_):
                    return native._read(reader, api, cluster, source_path(target), {}, state)[0]
                def service_get(_):
                    return native._read(reader, api, cluster, service_path(target), {}, state)[0]
                def proxy_get(_):
                    return _native_bytes(reader, api, cluster, target, state)
                marker = inspect(target, source_get, service_get, proxy_get,
                                 cancel=reader.check_cancelled, redact_values=add_redactions)
                item = {'id': identity(target), 'name': identity(target), 'SelectedFluxArtifact': marker}
                grouped.setdefault(target['namespace'], []).append(item)
        for scope, items in grouped.items():
            reader.collections.append({'type': KIND, 'scope': scope, 'service': 'kubernetes',
                'status': 'collected' if all(i['SelectedFluxArtifact']['complete'] for i in items) else 'partial',
                'items': items})
            reader.total += len(items)
    except Exception:
        if matches:
            matches.clear()
            raise RedactionOverflow('redaction_ledger_unavailable') from None
        raise
    except BaseException:
        matches.clear()
        raise
    finally:
        pool.literal_paths = old_paths
        client.last_response = None
    return metadata, matches
