"""Unregistered, default-off exact Release -> observed Skaffold source archive.

Only native GETs; source/config text is scanned offline and never cached. The
native URI has no historical generation guarantee. No rendering or execution.
"""
from copy import deepcopy
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
from . import gcp_selected_archive_secret_indicators as archives
from .gcp_cloudbuild_log_secret_indicators import _json_get, _project
from .gcp_composer_source_secret_indicators import _refs

KIND = 'clouddeploy_release_source'
OPTION = 'selected_clouddeploy_releases'
MARKER = 'CloudDeploySourceSecretIndicators'
SCHEMA = 'gcp-clouddeploy-release-source-secrets-v1'
MAX_RELEASES = 4
RELEASE_FIELDS = 'name,skaffoldConfigUri'
PART = r'[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?'
RELEASE_NAME = re.compile(r'projects/([a-z][a-z0-9-]{0,62}|[1-9][0-9]{0,19})/locations/' + PART + '/deliveryPipelines/' + PART + '/releases/' + PART + r'\Z')
Incomplete = objects.Incomplete


def enabled(options):
    kinds = options.get('_content_secret_scan_kinds')
    return options.get('content_secret_scans') is True and isinstance(kinds, list) and KIND in kinds


def selected_releases(options, scopes):
    if not enabled(options):
        return []
    rows = options.get(OPTION)
    if (not isinstance(scopes, list) or len(scopes) != 1 or not isinstance(scopes[0], str)
            or not objects._SCOPE.fullmatch(scopes[0]) or not isinstance(rows, list)
            or not 1 <= len(rows) <= MAX_RELEASES):
        raise Incomplete('invalid_selection')
    names = []
    for name in rows:
        match = RELEASE_NAME.fullmatch(name) if isinstance(name, str) else None
        if match is None or 'projects/' + match[1] != scopes[0] or name in names:
            raise Incomplete('invalid_selection')
        names.append(name)
    return names


def selection_metadata(collector):
    try:
        selected = selected_releases(collector.options, collector.scopes)
    except Incomplete:
        selected = []
    return {'clouddeploy_release_source_authorized': enabled(collector.options),
            'selected_clouddeploy_release_ids': [identity(n) for n in selected]}


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def identity(name):
    return 'clouddeploy-release-source:' + digest(name)


def release_binding(row, name, scope):
    if (not isinstance(row, dict) or set(row) != {'name', 'skaffoldConfigUri'}
            or row['name'] != name or not RELEASE_NAME.fullmatch(name)
            or '/'.join(name.split('/')[:2]) != scope):
        raise Incomplete('release_binding_unavailable')
    uri = row['skaffoldConfigUri']
    match = re.fullmatch(r'gs://([^/]+)/(.+\.tar\.gz)', uri) if isinstance(uri, str) and len(uri.encode()) <= 1250 else None
    if (match is None or not objects._BUCKET.fullmatch(match[1])
            or any(len(p) > 63 for p in match[1].split('.'))
            or any(c in match[2] for c in '%?#*[]\\')
            or any(ord(c) < 32 or ord(c) == 127 for c in match[2])
            or any(p in ('', '.', '..') for p in match[2].split('/'))
            or len(match[2].encode()) > 1024):
        raise Incomplete('unsupported_source_binding')
    return match[1], match[2]


def collect_sources(collector, scope):
    if not enabled(collector.options):
        return []
    try:
        names = selected_releases(collector.options, collector.scopes)
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
        marker = {'schema': SCHEMA, 'complete': False, 'scope': scope, 'release_name': name,
                  'binding': {}, 'archive': {}, 'native_requests': [], 'read_receipts': [],
                  'source_requests': [], 'reason': 'source_unavailable', 'verification': 'not_attempted'}
        start = len(transport.evidence)
        object_id = None
        try:
            from urllib3.connection import HTTPSConnection
            if (http.client.HTTPConnection.debuglevel or http.client.HTTPSConnection.debuglevel
                    or HTTPSConnection.debuglevel
                    or logging.getLogger('urllib3.connectionpool').isEnabledFor(logging.DEBUG)):
                raise Incomplete('unsafe_http_diagnostics')
            with state['lock']:
                _, refs = _project(collector, scope)
                marker['native_requests'] = refs
                release = _json_get(transport, state, scope, 'https://clouddeploy.googleapis.com/v1/' + name,
                    {'fields': RELEASE_FIELDS}, 'clouddeploy.releases.get.source', ident)
                bucket, object_name = release_binding(release, name, scope)
                objects._bound_bucket(collector, scope, bucket)
                bucket_row = next(r for r in collector.collections[('bucket', scope)]['items'] if r.get('name') == bucket)
                if set(bucket_row.get('_coverage', {})) & {'name', 'projectNumber', '*'}:
                    raise Incomplete('bucket_binding_unavailable')
                marker['native_requests'] += _refs(collector, 'bucket', scope, bucket_row,
                    'https://storage.googleapis.com/storage/v1/b', {'project': scope.split('/')[1], 'projection': 'full'})
                metadata = _json_get(transport, state, scope,
                    'https://storage.googleapis.com/storage/v1/b/' + quote(bucket, safe='') + '/o/' + quote(object_name, safe=''),
                    {'fields': objects.FIELDS, 'projection': 'noAcl'}, 'storage.objects.get.clouddeploy_source_generation', ident)
                target = {'project_scope': scope, 'bucket': bucket, 'object': object_name,
                          'generation': metadata.get('generation'), 'format': 'tar.gz'}
                archives.normalize_selection({'content_secret_scans': True, '_content_secret_scan_kinds': [archives.KIND],
                                              archives.OPTION: [target]}, [scope])
                archives._native_metadata(json.dumps(metadata).encode(), target)
                base = {k: v for k, v in target.items() if k != 'format'}
                object_id = objects.identity(base)
                binding = {'bucket_sha256': digest(bucket), 'object_sha256': digest(object_name),
                           'generation': target['generation'], 'object_id': object_id,
                           'archive_id': archives.identity(target), 'format': 'tar.gz',
                           'relationship': 'skaffoldConfigUri', 'coverage': 'observed_object_generation_only'}
                marker['binding'] = binding
                # Opaque binding retained on the authoritative uncached GET receipt;
                # consumer compares against the independent transport evidence.
                with transport.lock:
                    for receipt in transport.evidence[start:]:
                        if (receipt.get('operation') in ('clouddeploy.releases.get.source',
                                'storage.objects.get.clouddeploy_source_generation')
                                and receipt.get('resource_id') == ident):
                            receipt['binding'] = deepcopy(binding)
            facade = SimpleNamespace(options={'content_secret_scans': True,
                '_content_secret_scan_kinds': [archives.KIND], archives.OPTION: [target]},
                scopes=[scope], transport=transport, collections=collector.collections)
            selected, = archives.collect_selected_archives(facade, scope)
            marker['archive'] = selected
            marker['complete'] = selected[archives.MARKER]['complete'] is True
            marker['reason'] = 'complete' if marker['complete'] else 'archive_incomplete'
        except Incomplete as exc:
            marker['reason'] = str(exc)
        except Exception:
            marker['reason'] = 'source_unavailable'
        with transport.lock:
            receipts = [e for e in transport.evidence if e.get('scope') == scope
                        and (e.get('resource_id') == object_id or e in transport.evidence[start:]
                             and e.get('resource_id') == ident)]
            marker['read_receipts'] = [deepcopy(e) for e in receipts]
        marker['source_requests'] = sorted(set(marker['native_requests'] + [e['id'] for e in receipts]))
        result.append({'name': ident, MARKER: marker, '_coverage': {MARKER: {
            'status': 'collected' if marker['complete'] else 'unknown', 'source_requests': marker['source_requests']}}})
    return deepcopy(result)


def collection_pages(collector, scope):
    for row in collect_sources(collector, scope):
        refs = row[MARKER].get('source_requests', [])
        for ref in refs[:-1]:
            yield [], ref
        yield [row], refs[-1] if refs else 'local:clouddeploy_release_source_unavailable'


def jobs(collector, scope):
    """Integration: schedule only after native project and bucket jobs complete."""
    if enabled(collector.options):
        return [(KIND, scope, 'clouddeploy', lambda: collection_pages(collector, scope))]
    return []
