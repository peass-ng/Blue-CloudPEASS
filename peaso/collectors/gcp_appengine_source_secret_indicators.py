"""Explicit App Engine deployment.files observation, never installed implicitly.

Dedicated uncached metadata reads discard sourceUrl/query before serialization.
Only fixed GCS endpoints are read; a native deployed SHA1 must match bytes before
running the existing bounded offline dual-detector reader primitives.
"""

from peaso.secret_evidence import scan_with_source, target_source
from copy import deepcopy
import hashlib
import http.client
import json
import logging
import re
import threading
import time
from urllib.parse import quote, urlsplit, unquote

from . import gcp_selected_object_secret_indicators as objects
from .gcp_cloudbuild_log_secret_indicators import _json_get, _project
from .gcp_composer_source_secret_indicators import _refs
from peaso.secret_scanning import scan_content, merge_leaks

KIND = 'appengine_deployment_source'
OPTION = 'selected_appengine_versions'
SCHEMA = 'gcp-appengine-deployment-source-secrets-v1'
MARKER = 'AppEngineSourceSecretIndicators'
MAX_VERSIONS = 4
MAX_FILES = 4
MAX_BYTES = 1048576  # Plus at most 20 * 16KiB metadata: below 2MiB total.
VERSION_FIELDS = 'name,id,env,deployment'
VERSION_NAME = re.compile(r'apps/([a-z][a-z0-9-]{0,62})/services/([a-z][a-z0-9-]{0,62})/versions/([a-z0-9][a-z0-9-]{0,62})\Z')
Incomplete = objects.Incomplete


def enabled(options):
    kinds = options.get('_content_secret_scan_kinds')
    return options.get('content_secret_scans') is True and isinstance(kinds, list) and KIND in kinds


def selected_versions(options, scopes):
    if not enabled(options):
        return []
    names = options.get(OPTION)
    if (not isinstance(scopes, list) or len(scopes) != 1 or not isinstance(scopes[0], str)
            or not objects._SCOPE.fullmatch(scopes[0]) or not isinstance(names, list)
            or not 1 <= len(names) <= MAX_VERSIONS):
        raise Incomplete('invalid_selection')
    seen, project_ids = set(), set()
    for name in names:
        m = VERSION_NAME.fullmatch(name) if isinstance(name, str) else None
        if (m is None or m[3] in ('default', 'latest') or m[3].startswith('ah-')
                or name in seen
                or not scopes[0].split('/')[1].isdigit() and m[1] != scopes[0].split('/')[1]):
            raise Incomplete('invalid_selection')
        seen.add(name)
        project_ids.add(m[1])
    if len(project_ids) != 1:
        raise Incomplete('invalid_selection')
    return list(names)


def selection_metadata(collector):
    return {'appengine_deployment_source_authorized': enabled(collector.options)}


def identity(name):
    return 'appengine-deployment-source:' + hashlib.sha256(name.encode()).hexdigest()


def source_target(info, scope):
    """Parse only the documented path-style endpoint; never retain query/URL."""
    if (not isinstance(info, dict) or set(info) - {'sourceUrl', 'sha1Sum', 'mimeType'}
            or not isinstance(info.get('sha1Sum'), str)
            or not re.fullmatch(r'[0-9a-fA-F]{40}', info['sha1Sum'])):
        raise Incomplete('deployed_hash_unavailable')
    url = info.get('sourceUrl')
    if not isinstance(url, str) or len(url.encode()) > 8192 or any(ord(c) < 32 or ord(c) == 127 for c in url):
        raise Incomplete('unsupported_source')
    parsed = urlsplit(url)
    if (parsed.scheme not in ('https', 'http') or parsed.netloc != 'storage.googleapis.com'
            or parsed.fragment or not parsed.path.startswith('/') or '\\' in parsed.path):
        raise Incomplete('unsupported_source')
    # Query may contain signed credentials; ignore it entirely, never follow it.
    parts = parsed.path[1:].split('/', 1)
    if len(parts) != 2:
        raise Incomplete('unsupported_source')
    bucket, encoded = parts
    if (not objects._BUCKET.fullmatch(bucket) or any(len(p) > 63 for p in bucket.split('.'))
            or re.search(r'%(?![0-9a-fA-F]{2})', encoded)):
        raise Incomplete('unsupported_source')
    try:
        name = unquote(encoded, errors='strict')
    except UnicodeError:
        raise Incomplete('unsupported_source') from None
    if (not name or len(name.encode()) > 1024 or '\\' in name
            or any(ord(c) < 32 or ord(c) == 127 for c in name)
            or any(p in ('', '.', '..') for p in name.split('/'))):
        raise Incomplete('unsupported_source')
    return {'project_scope': scope, 'bucket': bucket, 'object': name}, info['sha1Sum'].lower()


def _projection(transport, operation, resource, projection):
    """Attach only an allowlisted identity projection to its successful receipt."""
    with transport.lock:
        receipts = [r for r in transport.evidence if r.get('operation') == operation
                    and r.get('resource_id') == resource and r.get('status') == 'collected'
                    and r.get('http_status') == 200]
        if not receipts:
            raise Incomplete('source_receipt_unavailable')
        receipts[-1]['projection'] = deepcopy(projection)


def _source_identity(target):
    return {'bucket_sha256': hashlib.sha256(target['bucket'].encode()).hexdigest(),
            'object_sha256': hashlib.sha256(target['object'].encode()).hexdigest()}


def manifest(version, name, scope, project, app):
    m = VERSION_NAME.fullmatch(name)
    if (m is None or m[1] != project.get('projectId')
            or app != {'name': 'apps/' + m[1], 'id': m[1]}
            or not isinstance(version, dict) or set(version) - {'name', 'id', 'env', 'deployment'}
            or version.get('name') != name or version.get('id') != m[3]
            or version.get('env', 'standard') != 'standard'):
        raise Incomplete('app_version_identity_unavailable')
    deployment = version.get('deployment')
    if not isinstance(deployment, dict) or set(deployment) != {'files'}:
        raise Incomplete('unsupported_deployment')
    files = deployment['files']
    if not isinstance(files, dict) or not 1 <= len(files) <= MAX_FILES:
        raise Incomplete('manifest_limit_or_missing')
    targets, seen = [], set()
    for path, info in files.items():
        if not isinstance(path, str) or not path or len(path.encode()) > 1024:
            raise Incomplete('invalid_manifest')
        target, sha1 = source_target(info, scope)
        key = (target['bucket'], target['object'])
        if key in seen:
            raise Incomplete('ambiguous_manifest')
        seen.add(key)
        targets.append((target, sha1))
    return targets


def collect_sources(collector, scope):
    if not enabled(collector.options):
        return []
    try:
        names = selected_versions(collector.options, collector.scopes)
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
    results = []
    for name in names:
        ident = identity(name)
        marker = {'schema': SCHEMA, 'scope': scope, 'version_name': name, 'complete': False,
                  'verification': 'not_attempted', 'files': [], 'manifest_count': 0,
                  'native_requests': [], 'read_receipts': [], 'source_requests': [], 'reason': 'unavailable'}
        start = len(transport.evidence)
        owned = {ident}
        try:
            from urllib3.connection import HTTPSConnection
            if (http.client.HTTPConnection.debuglevel or http.client.HTTPSConnection.debuglevel
                    or HTTPSConnection.debuglevel
                    or logging.getLogger('urllib3.connectionpool').isEnabledFor(logging.DEBUG)):
                raise Incomplete('unsafe_http_diagnostics')
            with state['lock']:
                project, refs = _project(collector, scope)
                marker['native_requests'] = list(refs)
                if VERSION_NAME.fullmatch(name)[1] != project.get('projectId'):
                    raise Incomplete('project_binding_unavailable')
                app_name = 'apps/' + project['projectId']
                app = _json_get(transport, state, scope, 'https://appengine.googleapis.com/v1/' + app_name,
                    {'fields': 'name,id'}, 'appengine.apps.get.source', ident)
                version = _json_get(transport, state, scope, 'https://appengine.googleapis.com/v1/' + name,
                    {'view': 'FULL', 'fields': VERSION_FIELDS}, 'appengine.versions.get.source', ident)
                targets = manifest(version, name, scope, project, app)
                _projection(transport, 'appengine.apps.get.source', ident, app)
                _projection(transport, 'appengine.versions.get.source', ident,
                    {'name': name, 'files': [{**_source_identity(t), 'sha1': h} for t, h in targets]})
                del version, app  # Raw source URLs never enter transport.cache or persistent state.
                marker['manifest_count'] = len(targets)
                for target, sha1 in targets:
                    bucket = target['bucket']
                    objects._bound_bucket(collector, scope, bucket)
                    bucket_row = next(r for r in collector.collections[('bucket', scope)]['items'] if r.get('name') == bucket)
                    if set(bucket_row.get('_coverage', {})) & {'name', 'projectNumber', '*'}:
                        raise Incomplete('bucket_binding_unavailable')
                    marker['native_requests'] += _refs(collector, 'bucket', scope, bucket_row,
                        'https://storage.googleapis.com/storage/v1/b', {'project': scope.split('/')[1], 'projection': 'full'})
                    metadata = _json_get(transport, state, scope,
                        'https://storage.googleapis.com/storage/v1/b/' + quote(bucket, safe='') + '/o/' + quote(target['object'], safe=''),
                        {'fields': objects.FIELDS, 'projection': 'noAcl'}, 'storage.objects.get.appengine_generation', ident)
                    target['generation'] = metadata.get('generation')
                    objects.selected_targets({'content_secret_scans': True, '_content_secret_scan_kinds': [objects.KIND],
                                              objects.OPTION: [target]}, [scope])
                    if int(target['generation']) > 9223372036854775807:
                        raise Incomplete('generation_unavailable')
                    objects._metadata(json.dumps(metadata).encode(), target)
                    binding = {**_source_identity(target), 'generation': target['generation']}
                    _projection(transport, 'storage.objects.get.appengine_generation', ident, binding)
                    oid = objects.identity(target)
                    owned.add(oid)
                    observed = objects._metadata(objects._read(transport, state, target), target)
                    _projection(transport, 'storage.objects.get.metadata', oid, binding)
                    if state['bytes'] + observed['size'] > MAX_BYTES:
                        raise Incomplete('adapter_byte_limit')
                    payload = objects._read(transport, state, target, media=True, expected=observed)
                    _projection(transport, 'storage.objects.get.media', oid, binding)
                    if hashlib.sha1(payload).hexdigest() != sha1:
                        raise Incomplete('deployed_hash_mismatch')
                    objects._text(payload)
                    objects._check(transport, state)
                    outcome = scan_with_source(scan_content, payload, 'object.content', timeout=min(5, objects._remaining(transport, state) / 2), source=target_source(target, resource_id=ident, scope=scope))
                    del payload
                    objects._check(transport, state)
                    leaks = merge_leaks(outcome['leaks'])
                    if len(leaks) > objects.MAX_LEAKS or sum(len(x['locations']) for x in leaks) > objects.MAX_LOCATIONS:
                        raise Incomplete('finding_limit')
                    inner = {'schema': objects.SCHEMA, 'identity': oid, 'scope': scope,
                        'status': 'collected' if outcome['complete'] else 'incomplete', 'complete': outcome['complete'],
                        'bytes': observed['size'], 'engines': outcome['engines'], 'leaks': leaks,
                        'verification': 'not_attempted', 'reason': 'complete' if outcome['complete'] else 'detector_unavailable'}
                    marker['files'].append({**binding, 'sha1': sha1, 'hash_matches': True,
                        'object': {'name': oid, objects.MARKER: inner}})
                marker.update(complete=all(f['object'][objects.MARKER]['complete'] is True for f in marker['files']), reason='complete')
        except Incomplete as exc:
            marker['reason'] = str(exc)
        except Exception:
            marker['reason'] = 'source_unavailable'
        with transport.lock:
            marker['read_receipts'] = [{k: e[k] for k in ('id', 'scope', 'method', 'operation', 'resource_id', 'status', 'http_status', 'projection') if k in e}
                for e in transport.evidence[start:] if e.get('scope') == scope and e.get('resource_id') in owned]
        marker['native_requests'] = sorted(set(marker['native_requests']))
        marker['source_requests'] = sorted(set(marker['native_requests'] + [r['id'] for r in marker['read_receipts']]))
        results.append({'name': ident, MARKER: marker})
    return deepcopy(results)


def collection_pages(collector, scope):
    for row in collect_sources(collector, scope):
        refs = row[MARKER].get('source_requests', [])
        for ref in refs[:-1]:
            yield [], ref
        yield [row], refs[-1] if refs else 'local:appengine_source_unavailable'


def jobs(collector, scope):
    """Root schedules after native project+bucket jobs and explicitly installs check."""
    return [(KIND, scope, 'appengine', lambda: collection_pages(collector, scope))] if enabled(collector.options) else []
