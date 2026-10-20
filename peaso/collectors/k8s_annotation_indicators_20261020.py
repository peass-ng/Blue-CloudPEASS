"""Bounded safe indicators from already-read native annotation maps.

This module performs no reads itself. The page wrapper receives only the
existing authenticated inventory iterator, never annotation bodies to export.
"""
from hashlib import sha256
from contextvars import ContextVar
import json
import re
import time
from urllib.parse import quote, urlsplit
from uuid import uuid4

MARKER = '_k8s_annotation_indicators_20261020'
CONTEXT = 'k8s_annotation_collection_context_20261020'
SCHEMA = 'k8s-native-annotation-indicators/v1'
MAX_ANNOTATIONS = 2048
MAX_ANNOTATION_BYTES = 262144
MAX_PAGE_BYTES = 16 * 1024 * 1024
MAX_NATIVE_PAGES = 32
FLAGS = ('snippet', 'alias', 'lua', 'apparmor_runtime_default', 'seccomp_runtime_default')
TYPES = {'ingress': ('networking.k8s.io/v1', 'Ingress'),
         'podsecuritypolicy': ('policy/v1beta1', 'PodSecurityPolicy')}
_TARGET_KIND = ContextVar('k8s_annotation_inventory_target', default=None)


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def identity(row):
    meta = row.get('metadata')
    if not isinstance(meta, dict):
        raise ValueError('native metadata missing')
    values = [row.get('apiVersion'), row.get('kind'), meta.get('namespace'), meta.get('name'),
              meta.get('uid'), meta.get('resourceVersion')]
    if any(not isinstance(v, str) or not v or len(v) > 253 for v in values[3:]):
        raise ValueError('native name, UID or resourceVersion missing')
    if any(v is not None and not isinstance(v, str) for v in values[:3]):
        raise ValueError('native type or namespace malformed')
    return values


def project(row):
    """Return derived booleans only, before the annotation map is filtered."""
    target = _TARGET_KIND.get()
    if (target not in TYPES or not isinstance(row, dict) or not isinstance(row.get('metadata'), dict)
            or 'spec' not in row or row.get('kind') not in (None, TYPES[target][1])):
        return None
    result = {'schema': SCHEMA, 'status': 'unavailable', 'reason': 'malformed_native_annotations'}
    try:
        values = identity(row)
        if (not isinstance(row['spec'], dict) or MARKER in row or '_coverage' in row
                or '_coverage' in row['metadata']):
            return result
        annotations = row['metadata'].get('annotations', {})
        if not isinstance(annotations, dict) or len(annotations) > MAX_ANNOTATIONS:
            return result
        total = 0
        flags = dict.fromkeys(FLAGS, False)
        for key, value in annotations.items():
            if not isinstance(key, str) or not key or len(key) > 317 or not isinstance(value, str):
                return result
            if len(value) > MAX_ANNOTATION_BYTES - total:
                return {**result, 'reason': 'annotation_budget_exceeded'}
            total += len(key.encode()) + len(value.encode())
            if total > MAX_ANNOTATION_BYTES:
                return {**result, 'reason': 'annotation_budget_exceeded'}
            # Preserve the old source's case-sensitive substring criteria,
            # including non-nginx keys containing literal "snippet".
            if 'snippet' in key:
                flags['snippet'] = True
                flags['alias'] |= 'alias' in value
                flags['lua'] |= re.search(r'(lua_|_lua|kubernetes\.io)', value) is not None
            if key == 'apparmor.security.beta.kubernetes.io/defaultProfileName':
                flags['apparmor_runtime_default'] = value == 'runtime/default'
            if key == 'seccomp.security.alpha.kubernetes.io/defaultProfileName':
                flags['seccomp_runtime_default'] = value in ('runtime/default', 'docker/default')
        return {'schema': SCHEMA, 'status': 'projected', 'identity_digest': digest(values),
                'flags': flags, 'annotation_count': len(annotations)}
    except (ValueError, TypeError, UnicodeError):
        return result


def collection_context(api, cluster):
    """Bind a collection session to the real SDK origin and configured auth.

    No credential value, credential fingerprint or claimed principal is saved.
    HTTP success establishes only that this context could read the objects.
    """
    cfg = getattr(getattr(api, 'api_client', None), 'configuration', None)
    origin = getattr(cfg, 'host', None)
    parsed = urlsplit(origin) if isinstance(origin, str) else None
    if (parsed is None or parsed.scheme != 'https' or not parsed.netloc or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        return None
    keys = getattr(cfg, 'api_key', {})
    bearer = isinstance(keys, dict) and isinstance(keys.get('authorization'), str) and bool(keys['authorization'])
    certificate = bool(getattr(cfg, 'cert_file', None) and getattr(cfg, 'key_file', None))
    if not bearer and not certificate:
        return None
    return {'schema': SCHEMA, 'provider': 'k8s', 'cluster_id': cluster,
            'origin_digest': digest(origin.rstrip('/')), 'session': uuid4().hex,
            'authentication': 'configured_bearer' if bearer else 'configured_client_certificate',
            'assurance': 'configured authenticated read session; principal identity unobserved'}


class _AnnotationInventoryApi:
    """The same existing inventory GET with strict representation/byte bounds."""
    def __init__(self, api, path, reader, expected):
        self.api_client, self.path, self.reader, self.expected = api.api_client, path, reader, expected
        self.has_next = False

    def get_json(self, path, params=None):
        if path != self.path:
            raise ValueError('annotation inventory path changed')
        deadline = time.monotonic() + 30
        response = self.api_client.call_api(path, 'GET', query_params=list((params or {}).items()),
            header_params={'Accept': 'application/json'}, auth_settings=['BearerToken'],
            _preload_content=False, _return_http_data_only=True, _request_timeout=30)
        try:
            content_type = response.headers.get('Content-Type', '').lower()
            if response.status != 200 or content_type.split(';', 1)[0].strip() != 'application/json' or 'as=' in content_type:
                raise ValueError('annotation inventory HTTP representation incomplete')
            chunks, total = [], 0
            while True:
                self.reader.check_cancelled()
                if time.monotonic() >= deadline:
                    raise TimeoutError('annotation inventory page deadline exceeded')
                chunk = response.read(16384)
                if not chunk:
                    break
                if not isinstance(chunk, bytes):
                    raise ValueError('annotation inventory body malformed')
                total += len(chunk)
                if total > MAX_PAGE_BYTES:
                    raise ValueError('annotation inventory page byte budget exceeded')
                chunks.append(chunk)
            def distinct(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError('duplicate annotation inventory JSON field')
                    result[key] = value
                return result
            document = json.loads(b''.join(chunks), object_pairs_hook=distinct)
            if not isinstance(document, dict):
                raise ValueError('annotation inventory document malformed')
            if (document.get('apiVersion', self.expected[0]) != self.expected[0]
                    or document.get('kind', self.expected[1] + 'List') != self.expected[1] + 'List'):
                raise ValueError('annotation inventory list type conflicts')
            self.has_next = bool(document.get('metadata', {}).get('continue'))
            return document
        finally:
            response.close(); response.release_conn()
            self.api_client.last_response = None


def pages(reader, api, path, kind, cluster, scope, namespaced, context, native_pages):
    """Bind safe projections after real endpoint reads; detect repeats pre-merge."""
    expected_version, expected_kind = TYPES[kind]
    expected_path = ('/apis/networking.k8s.io/v1/' +
        ('' if scope == '*' else 'namespaces/' + quote(scope, safe='') + '/') + 'ingresses'
        if kind == 'ingress' else '/apis/policy/v1beta1/podsecuritypolicies')
    if path != expected_path:
        raise ValueError('annotation source path mismatch')
    names, uids = set(), set()
    bounded_api = _AnnotationInventoryApi(api, path, reader, (expected_version, expected_kind))
    target_token = _TARGET_KIND.set(kind)
    try:
        for page_number, page in enumerate(native_pages(reader, bounded_api, path, kind, cluster, scope, namespaced), 1):
            for row in page:
                values = identity(row)
                version, typ, namespace, name, uid, rv = values
                if version not in (None, expected_version) or typ not in (None, expected_kind):
                    raise ValueError('annotation source native type mismatch')
                if namespaced and (not namespace or scope != '*' and namespace != scope):
                    raise ValueError('annotation source namespace mismatch')
                if not namespaced and namespace not in (None, ''):
                    raise ValueError('cluster annotation source has namespace')
                if (namespace, name) in names or uid in uids:
                    raise ValueError('duplicate annotation source identity')
                names.add((namespace, name)); uids.add(uid)
                marker = row.get(MARKER)
                if (not isinstance(marker, dict) or marker.get('status') != 'projected'
                        or marker.get('identity_digest') != digest(values) or context is None):
                    row[MARKER] = {'schema': SCHEMA, 'status': 'unavailable',
                                   'reason': marker.get('reason', 'unbound_annotation_projection') if isinstance(marker, dict) else 'unbound_annotation_projection'}
                    continue
                provenance = row.get('provenance', {})
                if (provenance.get('cluster_id') != cluster or provenance.get('evidence') != 'read-only list'
                        or provenance.get('uid') != uid or provenance.get('resourceVersion') != rv
                        or provenance.get('namespace') != (namespace if namespaced else '_cluster')
                        or provenance.get('apiVersion') != version):
                    raise ValueError('annotation source producer provenance mismatch')
                marker.update(status='bound', source={'method': 'GET', 'path': path,
                    'kind': kind, 'scope': scope, 'context_digest': digest(context),
                    'native_id': row['id'], 'native_type': expected_kind, 'native_api_version': expected_version})
            yield page
            if page_number >= MAX_NATIVE_PAGES and bounded_api.has_next:
                raise ValueError('annotation inventory page budget exceeded')
    finally:
        _TARGET_KIND.reset(target_token)
        sdk = getattr(api, 'api_client', None)
        if sdk is not None:
            sdk.last_response = None
