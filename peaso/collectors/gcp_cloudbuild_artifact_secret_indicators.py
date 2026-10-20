"""Default-off read-only produced GCS artifact observation; root owns hooks.

Manifest layout is newline-delimited ArtifactResult using snake_case Go JSON
fields, verified against Google's cloud-build-local/gsutil/gsutil.go. The
manifest is observed at a resolved generation; historical build linkage is
never asserted. Neither source archives nor configured globs are traversed.
"""
from copy import deepcopy
import base64
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
from . import gcp_cloudbuild_log_secret_indicators as logs
from .gcp_composer_source_secret_indicators import _refs, _pairs

KIND = 'cloudbuild_artifact_source'
OPTION = 'selected_cloudbuild_artifact_builds'
MARKER = 'CloudBuildArtifactSecretIndicators'
SCHEMA = 'gcp-cloudbuild-artifact-secrets-v1'
MAX_BUILDS = 2
MAX_ARTIFACTS = 4
MAX_MANIFEST_BYTES = 16384
BUILD_FIELDS = 'id,name,projectId,status,createTime,startTime,finishTime,results(artifactManifest)'
BUILD_NAME = logs.BUILD_NAME
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
    seen = set()
    for name in rows:
        m = BUILD_NAME.fullmatch(name) if isinstance(name, str) else None
        if m is None or 'projects/' + m[1] != scopes[0] or name in seen:
            raise Incomplete('invalid_selection')
        seen.add(name)
    return list(rows)


def identity(name):
    return 'cloudbuild-artifacts:' + hashlib.sha256(name.encode()).hexdigest()


def selection_metadata(collector):
    return {'cloudbuild_artifact_source_authorized': enabled(collector.options)}


def _uri(value, scope, *, pinned):
    if not isinstance(value, str) or len(value.encode()) > 1300:
        raise Incomplete('unsupported_gcs_uri')
    m = re.fullmatch(r'gs://([^/]+)/([^#]+)(?:#([1-9][0-9]{0,19}))?', value)
    if m is None or pinned and m[3] is None:
        raise Incomplete('unsupported_gcs_uri')
    bucket, name, generation = m.groups()
    if (not objects._BUCKET.fullmatch(bucket) or any(len(p) > 63 for p in bucket.split('.'))
            or len(name.encode()) > 1024 or any(c in name for c in '%?*[]\\')
            or any(ord(c) < 32 or ord(c) == 127 for c in name)
            or any(p in ('', '.', '..') for p in name.split('/'))
            or generation is not None and int(generation) > 9223372036854775807):
        raise Incomplete('unsupported_gcs_uri')
    target = {'project_scope': scope, 'bucket': bucket, 'object': name}
    if generation is not None:
        target['generation'] = generation
    return target


def build_binding(build, name, project):
    m = BUILD_NAME.fullmatch(name) if isinstance(name, str) else None
    if (m is None or not isinstance(build, dict)
            or set(build) - {'id', 'name', 'projectId', 'status', 'createTime', 'startTime', 'finishTime', 'results'}
            or build.get('name') != name or build.get('id') != m[3]
            or build.get('projectId') != project.get('projectId')
            or m[1] not in (project.get('projectId'), project.get('name', '').split('/')[-1])
            or build.get('status') not in logs.TERMINAL):
        raise Incomplete('build_identity_or_state_unavailable')
    created, finished = logs._time(build.get('createTime')), logs._time(build.get('finishTime'))
    if created > finished or 'startTime' in build and not created <= logs._time(build['startTime']) <= finished:
        raise Incomplete('build_time_unavailable')
    results = build.get('results')
    if not isinstance(results, dict) or set(results) != {'artifactManifest'}:
        raise Incomplete('manifest_unavailable')
    return _uri(results['artifactManifest'], 'projects/' + m[1], pinned=False)


def parse_manifest(payload, scope):
    """Exact documented record semantics; unknown layouts never imply coverage.

    Google's writer encodes each ArtifactResult separately, not a JSON array.
    Hash values are retained only long enough to validate the supported MD5
    shape, not used as a claim of immutable native Build provenance.
    """
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_MANIFEST_BYTES:
        raise Incomplete('manifest_limit_or_empty')
    try:
        lines = payload.decode('utf-8', errors='strict').splitlines()
        if not 1 <= len(lines) <= MAX_ARTIFACTS or any(not line.strip() for line in lines):
            raise ValueError('records')
        targets, seen = [], set()
        for line in lines:
            row = json.loads(line, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            if not isinstance(row, dict) or set(row) != {'location', 'file_hash'}:
                raise ValueError('record')
            hashes = row['file_hash']
            if (not isinstance(hashes, list) or len(hashes) != 1 or not isinstance(hashes[0], dict)
                    or set(hashes[0]) != {'file_hash'} or not isinstance(hashes[0]['file_hash'], list)
                    or len(hashes[0]['file_hash']) != 1):
                raise ValueError('hashes')
            h = hashes[0]['file_hash'][0]
            if not isinstance(h, dict) or set(h) != {'type', 'value'} or type(h['type']) is not int or h['type'] != 2:
                raise ValueError('hash type')
            decoded = base64.b64decode(h['value'], validate=True)
            if base64.b64encode(decoded).decode() != h['value']:
                raise ValueError('hash encoding')
            # Go's writer serializes the gsutil MD5 column bytes (itself base64).
            if len(decoded) != 16:
                md5 = base64.b64decode(decoded, validate=True)
                if len(md5) != 16 or base64.b64encode(md5) != decoded:
                    raise ValueError('hash size')
            target = _uri(row['location'], scope, pinned=True)
            key = (target['bucket'], target['object'])
            if key in seen:
                raise ValueError('duplicate artifact')
            seen.add(key)
            targets.append(target)
        return targets
    except Exception:
        raise Incomplete('unsupported_manifest') from None


def _bucket(collector, scope, target):
    objects._bound_bucket(collector, scope, target['bucket'])
    row, = [r for r in collector.collections[('bucket', scope)]['items'] if r.get('name') == target['bucket']]
    if set(row.get('_coverage', {})) & {'name', 'projectNumber', '*'}:
        raise Incomplete('bucket_binding_unavailable')
    refs = _refs(collector, 'bucket', scope, row, 'https://storage.googleapis.com/storage/v1/b',
                 {'project': scope.split('/')[1], 'projection': 'full'})
    if len(refs) != 1:
        raise Incomplete('ambiguous_bucket_provenance')
    return refs


def _descriptor(target):
    return {'identity': objects.identity(target), 'generation': target['generation'],
            'bucket_sha256': hashlib.sha256(target['bucket'].encode()).hexdigest()}


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
        marker = {'schema': SCHEMA, 'scope': scope, 'build_name': name, 'build': {},
            'manifest': {}, 'artifacts': [], 'complete': False, 'reason': 'source_unavailable',
            'native_requests': [], 'read_receipts': [], 'source_requests': [], 'verification': 'not_attempted',
            'coverage': 'observed_manifest_generations_only', 'historical_build_bytes': 'not_established'}
        start, resources, bindings = len(transport.evidence), {ident}, {}
        try:
            from urllib3.connection import HTTPSConnection
            if (http.client.HTTPConnection.debuglevel or http.client.HTTPSConnection.debuglevel
                    or HTTPSConnection.debuglevel or logging.getLogger('urllib3.connectionpool').isEnabledFor(logging.DEBUG)):
                raise Incomplete('unsafe_http_diagnostics')
            with state['lock']:
                project, refs = logs._project(collector, scope)
                if len(refs) != 1:
                    raise Incomplete('ambiguous_project_provenance')
                marker['native_requests'] = refs
                # Prove native CRM identity before the first source GET.
                pid, pnum = project.get('projectId'), project.get('name')
                if (not isinstance(pid, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', pid)
                        or not isinstance(pnum, str) or not re.fullmatch(r'projects/[1-9][0-9]{0,19}', pnum)
                        or scope not in ('projects/' + pid, pnum)
                        or 'projectNumber' in project and project['projectNumber'] != pnum[9:]):
                    raise Incomplete('project_binding_unavailable')
                build = logs._json_get(transport, state, scope, 'https://cloudbuild.googleapis.com/v1/' + name,
                    {'fields': BUILD_FIELDS}, 'cloudbuild.builds.get.artifact_source', ident)
                target = build_binding(build, name, project)
                target['project_scope'] = scope
                marker['native_requests'] += _bucket(collector, scope, target)
                metadata = logs._json_get(transport, state, scope,
                    'https://storage.googleapis.com/storage/v1/b/' + quote(target['bucket'], safe='') + '/o/' + quote(target['object'], safe=''),
                    {**({'generation': target['generation'], 'ifGenerationMatch': target['generation']} if 'generation' in target else {}),
                     'fields': objects.FIELDS, 'projection': 'noAcl'},
                    'storage.objects.get.cloudbuild_manifest_generation', ident)
                generation = metadata.get('generation')
                if (not isinstance(generation, str) or not objects._DECIMAL.fullmatch(generation)
                        or int(generation) > 9223372036854775807
                        or 'generation' in target and target['generation'] != generation):
                    raise Incomplete('generation_unavailable')
                target['generation'] = generation
                observed = objects._metadata(json.dumps(metadata).encode(), target)
                if not 0 < observed['size'] <= MAX_MANIFEST_BYTES:
                    raise Incomplete('manifest_limit_or_empty')
                if state['bytes'] + observed['size'] > objects.MAX_TOTAL_BYTES:
                    raise Incomplete('total_byte_limit')
                resources.add(objects.identity(target))
                bindings[objects.identity(target)] = _descriptor(target)
                payload = objects._read(transport, state, target, media=True, expected=observed)
                targets = parse_manifest(payload, scope)
                del payload
                marker['manifest'] = _descriptor(target)
                marker['build'] = {k: v for k, v in build.items() if k != 'results'}
                # Bind every destination before any artifact content reads.
                for artifact in targets:
                    marker['native_requests'] += _bucket(collector, scope, artifact)
                    if objects.identity(artifact) == objects.identity(target):
                        raise Incomplete('recursive_manifest')
            for artifact in targets:
                with state['lock']:
                    metadata = logs._json_get(transport, state, scope,
                        'https://storage.googleapis.com/storage/v1/b/' + quote(artifact['bucket'], safe='') + '/o/' + quote(artifact['object'], safe=''),
                        {'generation': artifact['generation'], 'ifGenerationMatch': artifact['generation'],
                         'fields': objects.FIELDS, 'projection': 'noAcl'},
                        'storage.objects.get.cloudbuild_artifact_type', objects.identity(artifact))
                    mime = metadata.get('contentType', '').split(';')[0].strip().lower()
                    fmt = next((f for f, types in archives.MIME_TYPES.items() if mime in types), None)
                    if fmt:
                        archives._native_metadata(json.dumps(metadata).encode(), {**artifact, 'format': fmt})
                    else:
                        objects._metadata(json.dumps(metadata).encode(), artifact)
                resources.add(objects.identity(artifact))
                reader = archives if fmt else objects
                selection = {**artifact, 'format': fmt} if fmt else artifact
                facade = SimpleNamespace(options={'content_secret_scans': True, '_content_secret_scan_kinds': [reader.KIND],
                    reader.OPTION: [selection]}, scopes=[scope], transport=transport, collections=collector.collections)
                selected, = (archives.collect_selected_archives(facade, scope) if fmt else objects.collect_selected_objects(facade, scope))
                bindings[objects.identity(artifact)] = {**_descriptor(artifact), 'reader_identity': selected['name']}
                marker['artifacts'].append({**_descriptor(artifact), 'format': fmt or 'utf8', 'reader_identity': selected['name'], 'selected': selected})
                if selected[reader.MARKER]['complete'] is not True:
                    raise Incomplete('artifact_incomplete')
            marker.update(complete=True, reason='complete')
        except Incomplete as exc:
            marker['reason'] = str(exc)
        except Exception:
            marker['reason'] = 'source_unavailable'
        with transport.lock:
            receipts = [e for e in transport.evidence[start:] if e.get('scope') == scope and e.get('resource_id') in resources]
            marker['read_receipts'] = []
            for e in receipts:
                receipt = {k: e[k] for k in ('id', 'scope', 'method', 'operation', 'resource_id', 'status', 'http_status') if k in e}
                if e.get('resource_id') in bindings:
                    receipt['binding'] = deepcopy(bindings[e['resource_id']])
                elif e.get('operation') == 'storage.objects.get.cloudbuild_manifest_generation' and marker['manifest']:
                    receipt['binding'] = deepcopy(marker['manifest'])
                marker['read_receipts'].append(receipt)
        marker['native_requests'] = sorted(set(marker['native_requests']))
        marker['source_requests'] = sorted(set(marker['native_requests'] + [e['id'] for e in receipts]))
        result.append({'name': ident, MARKER: marker, '_coverage': {MARKER: {
            'status': 'collected' if marker['complete'] else 'unknown', 'source_requests': marker['source_requests']}}})
    return deepcopy(result)


def collection_pages(collector, scope):
    for row in collect_sources(collector, scope):
        refs = row[MARKER].get('source_requests', [])
        for ref in refs[:-1]:
            yield [], ref
        yield [row], refs[-1] if refs else 'local:cloudbuild_artifact_source_unavailable'


def jobs(collector, scope):
    if enabled(collector.options):
        return [(KIND, scope, 'cloudbuild', lambda: collection_pages(collector, scope))]
    return []
