"""Optional read-only GKE workload bridge, independent of Kubernetes kubeconfig.

No credential refresh/helper, Secret read, token volume resolution, subresource,
mutation or generic response cache. Only proven native public IP + CA bindings
and existing Google access tokens are used; native GKE enforces auth and RBAC.
"""

from peaso.secret_evidence import scan_with_source
import base64
from datetime import datetime, timezone
import http.client
import ipaddress
import json
import re
import ssl
import time
from uuid import UUID

from peaso.secret_scanning import scan_content, merge_leaks, redact_matches

KIND = 'gke_workload_literal'
SCHEMA = 'gcp-gke-workload-literal-secrets-v1'
MARKER = 'GKEWorkloadLiteralSecretIndicators'
PROJECT = r'[a-z][a-z0-9-]{0,62}'
LOCATION = r'[a-z][a-z0-9-]{0,62}'
CLUSTER = r'[a-z](?:[a-z0-9-]{0,38}[a-z0-9])?'
SELECTION = re.compile(r'projects/(' + PROJECT + r')/locations/(' + LOCATION + r')/clusters/(' + CLUSTER + ')')
DNS_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')
DNS_NAME = re.compile(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*')
DATA_KEY = re.compile(r'[A-Za-z0-9._-]{1,253}')
ENV_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,127}')
EMAIL_SCOPE = 'https://www.googleapis.com/auth/userinfo.email'
CLOUD_SCOPE = 'https://www.googleapis.com/auth/cloud-platform'
MAX_CLUSTERS = 3
MAX_NAMESPACES = 5
MAX_RESOURCES = 100
MAX_PAGES = 3
PAGE_SIZE = 25
MAX_CALLS = 128
MAX_HTTP_BYTES = 1048576
MAX_READ_BYTES = 4194304
MAX_VALUE_BYTES = 65536
MAX_ROW_BYTES = 262144
MAX_SCAN_BYTES = 1048576
MAX_PAIRS = 128
MAX_CONTAINERS = 20
MAX_SECONDS = 60


def _failure(code='gke_literal_unavailable', status='unavailable'):
    from .gcp import ReadError
    return ReadError(status, code)


def enabled(options):
    return (options.get('content_secret_scans') is True and
            isinstance(options.get('_content_secret_scan_kinds'), list) and
            KIND in options['_content_secret_scan_kinds'])


def selection_metadata(collector):
    """Root includes the non-secret explicit selection contract in the snapshot."""
    try:
        values = collector.options.get('selected_gke_clusters')
        if not isinstance(values, list) or not values:
            raise ValueError('selection')
        scope = values[0].split('/locations/')[0]
        selected(collector, scope)
        from copy import deepcopy
        return {'gke_literal_selection': {'status': 'authorized', 'clusters': values[:],
            'namespaces': deepcopy(collector.options.get('selected_gke_namespaces'))}}
    except Exception:
        return {'gke_literal_selection': {'status': 'unavailable'}}


def auth_requested(collector):
    """Root-owned credential hook may request email scope for this named plan."""
    if KIND not in collector.needed:
        return False
    try:
        return any(selected(collector, scope)[0] for scope in collector.requested_scopes
                   if isinstance(scope, str) and re.fullmatch('projects/' + PROJECT, scope))
    except Exception:
        return False


def selected(collector, scope):
    options = collector.options
    values = options.get('selected_gke_clusters')
    if (not enabled(options) or scope not in collector.requested_scopes or
            not isinstance(values, list) or not 1 <= len(values) <= MAX_CLUSTERS or
            any(not isinstance(v, str) or not SELECTION.fullmatch(v) for v in values) or len(values) != len(set(values))):
        raise _failure('gke_literal_selection_required')
    if any(v.split('/locations/')[0] not in collector.requested_scopes for v in values):
        raise _failure('gke_literal_discovered_project_not_authorized')
    namespaces = options.get('selected_gke_namespaces')
    if namespaces is not None:
        if not isinstance(namespaces, dict) or set(namespaces) != set(values):
            raise _failure('gke_literal_namespace_selection_invalid')
        for names in namespaces.values():
            if (not isinstance(names, list) or not 1 <= len(names) <= MAX_NAMESPACES
                    or any(not isinstance(n, str) or not DNS_LABEL.fullmatch(n) for n in names)
                    or len(names) != len(set(names))):
                raise _failure('gke_literal_namespace_selection_invalid')
    if any(key in options for key in ('gke_endpoint', 'kubernetes_endpoint', 'gke_ca', 'gke_token', 'kubeconfig')):
        raise _failure('gke_literal_override_prohibited')
    return [v for v in values if v.startswith(scope + '/locations/')], namespaces


def cluster_binding(collector, scope, selection):
    """Bind actual short native names to source collection authority, IP and CA."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    source = collector.collections.get(('gke_cluster', scope))
    match = SELECTION.fullmatch(selection)
    if (not source or source.get('status') != 'collected' or source.get('coverage_status') != 'collected'
            or not isinstance(source.get('items'), list) or not match or 'projects/' + match[1] != scope):
        raise _failure('gke_cluster_inventory_unproved')
    candidates = [r for r in source['items'] if isinstance(r, dict) and r.get('name') == match[3] and r.get('location') == match[2]]
    if len(candidates) != 1:
        raise _failure('gke_cluster_subject_ambiguous')
    row = candidates[0]
    expected_links = {f'https://container.googleapis.com/v1/{scope}/{segment}/{match[2]}/clusters/{match[3]}' for segment in ('locations', 'zones')}
    provenance = row.get('_provenance', {})
    refs = provenance.get('source_requests')
    if (row.get('selfLink') not in expected_links or row.get('status') != 'RUNNING'
            or row.get('_coverage') or row.get('collection_status', 'collected') != 'collected'
            or provenance.get('scope') != scope or not isinstance(refs, list) or not refs):
        raise _failure('gke_cluster_subject_unproved')
    receipts = {e.get('id'): e for e in collector.transport.evidence if isinstance(e, dict)}
    if any(ref not in receipts or receipts[ref].get('scope') != scope
            or receipts[ref].get('method') != 'GET' or receipts[ref].get('status') != 'collected'
            or receipts[ref].get('http_status') != 200 or receipts[ref].get('query') != {}
            or receipts[ref].get('url') != f'https://container.googleapis.com/v1/{scope}/locations/-/clusters' for ref in refs):
        raise _failure('gke_cluster_source_receipt_unproved')
    endpoint = row.get('endpoint')
    try:
        address = ipaddress.ip_address(endpoint)
        if not address.is_global or address.is_multicast or address.is_reserved or str(address) != endpoint or address.version != 4:
            raise ValueError('public canonical IPv4 required')
        config = row.get('controlPlaneEndpointsConfig', {}).get('ipEndpointsConfig', {})
        if config.get('enabled') is False or config.get('publicEndpoint', endpoint) != endpoint:
            raise ValueError('IP endpoint not available')
        private = row.get('privateClusterConfig', {})
        if private.get('enablePrivateEndpoint') is True:
            raise ValueError('private endpoint unsupported')
        encoded = row['masterAuth']['clusterCaCertificate']
        if not isinstance(encoded, str) or len(encoded) > 24000:
            raise ValueError('CA size')
        pem = base64.b64decode(encoded, validate=True)
        if base64.b64encode(pem).decode() != encoded or len(pem) > 16384 or pem.count(b'-----BEGIN CERTIFICATE-----') != 1:
            raise ValueError('CA shape')
        cert = x509.load_pem_x509_certificate(pem)
        if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError('not a CA')
        if not cert.not_valid_before_utc <= datetime.now(timezone.utc) < cert.not_valid_after_utc:
            raise ValueError('expired CA')
        cert.verify_directly_issued_by(cert)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(cadata=pem.decode('ascii'))
    except Exception:
        raise _failure('gke_cluster_endpoint_or_ca_unproved') from None
    return {'selection': selection, 'endpoint': endpoint, 'ca_sha256': cert.fingerprint(hashes.SHA256()).hex(),
            'context': context, 'source_requests': refs[:]}


def validate_cluster_source(data, scope):
    """Proposed source-page hook before generic envelope identity coalescing.

    Run only for the optional bridge. Conflicting/duplicate native cluster rows
    must not be silently collapsed into an apparently complete authority fact.
    """
    if (not isinstance(data, dict) or set(data) - {'clusters', 'missingZones'}
            or not isinstance(data.get('clusters', []), list)):
        raise _failure('gke_cluster_source_shape')
    seen = set()
    for row in data.get('clusters', []):
        name, location = (row.get('name'), row.get('location')) if isinstance(row, dict) else (None, None)
        if (not isinstance(name, str) or not re.fullmatch(CLUSTER, name) or not isinstance(location, str)
                or not re.fullmatch(LOCATION, location) or (name, location) in seen
                or row.get('selfLink') not in {f'https://container.googleapis.com/v1/{scope}/{segment}/{location}/clusters/{name}'
                                               for segment in ('locations', 'zones')}):
            raise _failure('gke_cluster_source_subject_ambiguous')
        seen.add((name, location))


def existing_bearer(transport):
    """Reuse an existing token; native GKE authenticates and authorizes the read.

    Missing scope metadata is not evidence of missing grants. No refresh,
    gcloud invocation, token inspection endpoint or verification request occurs.
    """
    credentials = transport.credentials
    token = getattr(credentials, 'direct_token', None)
    if not token:
        gcloud = getattr(credentials, 'gcloud', None)
        if gcloud is not None:
            if getattr(gcloud, 'expires', 0) <= time.monotonic() + 5:
                raise _failure('gke_existing_google_token_unavailable')
            token = getattr(gcloud, 'token', None)
        else:
            from google.auth.credentials import Credentials as GoogleCredentials
            credential = getattr(credentials, 'credential', None)
            if not isinstance(credential, GoogleCredentials) or not credential.valid:
                raise _failure('gke_existing_google_token_unavailable')
            token = credential.token
    if not isinstance(token, str) or len(token) > 8192 or not re.fullmatch(r'[A-Za-z0-9._~+/-]+=*', token):
        raise _failure('gke_existing_google_token_unavailable')
    return token


def _string(value):
    if not isinstance(value, str) or len(value.encode()) > MAX_VALUE_BYTES:
        raise ValueError('literal bound')
    return value


def _map(value, binary=False):
    if not isinstance(value, dict) or len(value) > MAX_PAIRS:
        raise ValueError('literal map')
    result = {}
    for key, val in value.items():
        if not isinstance(key, str) or not DATA_KEY.fullmatch(key):
            raise ValueError('literal key')
        if binary:
            if not isinstance(val, str) or len(val) > 4 * ((MAX_VALUE_BYTES + 2) // 3):
                raise ValueError('encoded bound')
            decoded = base64.b64decode(val, validate=True)
            if len(decoded) > MAX_VALUE_BYTES or base64.b64encode(decoded).decode() != val:
                raise ValueError('base64')
            val = decoded.decode('utf-8', errors='strict')
        result[key] = _string(val)
    return json.dumps(result, ensure_ascii=False, separators=(',', ':')).encode()


def _reference(value, fields):
    if not isinstance(value, dict) or set(value) - set(fields):
        raise ValueError('reference shape')
    out = {}
    for key, val in value.items():
        if key == 'optional':
            if type(val) is not bool:
                raise ValueError('reference flag')
        elif not isinstance(val, str) or len(val) > 253 or not val:
            raise ValueError('reference field')
        out[key] = val
    return out


def pod_surfaces(spec):
    if not isinstance(spec, dict) or not isinstance(spec.get('containers'), list) or not spec['containers']:
        raise ValueError('missing containers')
    payloads, refs, names, seen = [], [], [], set()
    for field in ('containers', 'initContainers', 'ephemeralContainers'):
        rows = spec.get(field, [])
        if not isinstance(rows, list) or len(rows) > MAX_CONTAINERS:
            raise ValueError('containers bound')
        for ordinal, container in enumerate(rows, 1):
            if not isinstance(container, dict):
                raise ValueError('container')
            name = container.get('name')
            if not isinstance(name, str) or not DNS_LABEL.fullmatch(name) or name in seen:
                raise ValueError('container name')
            seen.add(name)
            path = f'{field}/{ordinal}'
            names.append({'path': path, 'name': name})
            env = container.get('env', [])
            if not isinstance(env, list) or len(env) > MAX_PAIRS:
                raise ValueError('env bound')
            literal, env_seen = {}, set()
            for entry in env:
                if (not isinstance(entry, dict) or set(entry) - {'name', 'value', 'valueFrom'}
                        or not isinstance(entry.get('name'), str) or not ENV_NAME.fullmatch(entry['name']) or entry['name'] in env_seen):
                    raise ValueError('env shape')
                env_seen.add(entry['name'])
                if 'valueFrom' not in entry:
                    literal[entry['name']] = _string(entry.get('value', ''))
                    continue
                if entry.get('value', '') != '':
                    raise ValueError('env union')
                source = entry['valueFrom']
                if not isinstance(source, dict) or len(source) != 1:
                    raise ValueError('env source')
                key = next(iter(source))
                fields = {'secretKeyRef': ('name', 'key', 'optional'), 'configMapKeyRef': ('name', 'key', 'optional'),
                          'fieldRef': ('apiVersion', 'fieldPath'), 'resourceFieldRef': ('containerName', 'resource', 'divisor')}
                if key not in fields:
                    raise ValueError('env source')
                ref = _reference(source[key], fields[key])
                required = {'name', 'key'} if key in ('secretKeyRef', 'configMapKeyRef') else ({'fieldPath'} if key == 'fieldRef' else {'resource'})
                if not required <= set(ref):
                    raise ValueError('env reference')
                if key in ('secretKeyRef', 'configMapKeyRef') and (not DNS_NAME.fullmatch(ref['name']) or not DATA_KEY.fullmatch(ref['key'])):
                    raise ValueError('reference name')
                refs.append({'path': path + '/env', 'envName': entry['name'], 'valueFrom': {key: ref}})
            sources = container.get('envFrom', [])
            if not isinstance(sources, list) or len(sources) > MAX_PAIRS:
                raise ValueError('envFrom')
            for source in sources:
                if not isinstance(source, dict) or set(source) - {'prefix', 'secretRef', 'configMapRef'}:
                    raise ValueError('envFrom shape')
                keys = set(source) & {'secretRef', 'configMapRef'}
                if len(keys) != 1:
                    raise ValueError('envFrom union')
                key = next(iter(keys))
                ref = _reference(source[key], ('name', 'optional'))
                if not isinstance(ref.get('name'), str) or not DNS_NAME.fullmatch(ref['name']):
                    raise ValueError('envFrom reference')
                prefix = source.get('prefix', '')
                if not isinstance(prefix, str) or len(prefix) > 128 or prefix and not ENV_NAME.fullmatch(prefix):
                    raise ValueError('envFrom prefix')
                refs.append({'path': path + '/envFrom', 'prefix': prefix, key: ref})
            payloads.append((path + '/env', json.dumps(literal, ensure_ascii=False, separators=(',', ':')).encode()))
            for surface in ('args', 'command'):
                values = container.get(surface, [])
                if not isinstance(values, list) or len(values) > MAX_PAIRS:
                    raise ValueError('command bound')
                payloads.append((path + '/' + surface, json.dumps([_string(v) for v in values], ensure_ascii=False, separators=(',', ':')).encode()))
    return payloads, refs, names


def project_resource(row, kind, namespace, binding, budget, cancelled):
    marker = {'schema': SCHEMA, 'complete': False, 'surfaces': [], 'leaks': [], 'verification': 'not_attempted'}
    if not isinstance(row, dict) or row.get('apiVersion') != 'v1' or row.get('kind') != kind:
        raise _failure('gke_workload_native_shape')
    meta = row.get('metadata')
    if not isinstance(meta, dict) or meta.get('namespace') != namespace or not isinstance(meta.get('name'), str) or not DNS_NAME.fullmatch(meta['name']):
        raise _failure('gke_workload_native_subject')
    try:
        uid = str(UUID(meta['uid']))
        if uid != meta['uid'] or not isinstance(meta.get('resourceVersion'), str) or not re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', meta['resourceVersion']):
            raise ValueError('version')
    except Exception:
        raise _failure('gke_workload_native_subject') from None
    identity = (binding['selection'], uid)
    seen_uids = budget.setdefault('seen_uids', set())
    if identity in seen_uids:
        raise _failure('gke_workload_uid_ambiguous')
    seen_uids.add(identity)
    name = binding['selection'] + '/namespaces/' + namespace + '/' + ('configmaps' if kind == 'ConfigMap' else 'pods') + '/' + meta['name']
    safe = {'name': name, 'cluster': binding['selection'], 'namespace': namespace, 'nativeKind': kind,
        'kubernetesName': meta['name'], 'uid': uid, 'resourceVersion': meta['resourceVersion'], 'clusterCaSha256': binding['ca_sha256'],
        'clusterEndpoint': binding['endpoint'], 'references': [], 'containerNames': [],
        'namespaceAuthorization': {'mode': binding['namespace_mode'], 'names': binding['namespace_names'][:],
            'source_requests': binding['namespace_requests'][:]}, MARKER: marker}
    redactions = set()
    try:
        if row.get('_coverage') or row.get('collection_status', 'collected') != 'collected':
            raise ValueError('partial')
        if kind == 'ConfigMap':
            data, binary = row.get('data', {}), row.get('binaryData', {})
            if not isinstance(data, dict) or not isinstance(binary, dict) or set(data) & set(binary):
                raise ValueError('config map key union')
            payloads = [('data', _map(data)), ('binaryData', _map(binary, True))]
        else:
            payloads, refs, names = pod_surfaces(row.get('spec'))
            safe['references'], safe['containerNames'] = refs, names
        total = sum(len(payload) for _, payload in payloads)
        if total > MAX_ROW_BYTES or total > budget['scan_bytes']:
            raise ValueError('scan byte bound')
        budget['scan_bytes'] -= total
        for path, payload in payloads:
            cancelled()
            remaining = budget['deadline'] - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('scan deadline')
            outcome = scan_with_source(scan_content, payload, path, timeout=min(10, remaining / 2), _redact_values=redactions.update, source={'resource_id': name, 'scope': binding['selection'], 'location_kind': 'configuration'}, native=row)
            marker['surfaces'].append({'path': path, 'bytes': len(payload), 'complete': outcome['complete'], 'engines': outcome['engines']})
            marker['leaks'] = merge_leaks(marker['leaks'] + outcome['leaks'])
            if len(marker['leaks']) > 256 or sum(len(x['locations']) for x in marker['leaks']) > 512:
                raise ValueError('redacted bound')
        cancelled()
        marker['complete'] = time.monotonic() < budget['deadline'] and all(s['complete'] is True for s in marker['surfaces'])
    except Exception:
        marker['complete'] = False
    return redact_matches(safe, redactions)


class Reader:
    """Fresh verified TLS connection per exact GET, no proxy/helper/cookie/cache."""
    def __init__(self, collector, binding, namespaces, budget):
        self.transport = collector.transport
        self.binding, self.namespaces, self.budget = binding, namespaces, budget

    def read(self, path, params):
        from urllib.parse import urlencode
        allowed = (path == '/api/v1/namespaces' and self.namespaces is None or
            any(path == f'/api/v1/namespaces/{n}/{resource}' for n in (self.namespaces or []) for resource in ('configmaps', 'pods')))
        if (not allowed or set(params) - {'limit', 'continue'} or params.get('limit') != PAGE_SIZE
                or type(params['limit']) is not int or 'continue' in params and
                (not isinstance(params['continue'], str) or not params['continue'] or len(params['continue'].encode()) > 4096)):
            raise _failure('gke_literal_path_prohibited')
        self.transport.check_cancelled()
        bearer = existing_bearer(self.transport)
        response, connection, rid = None, None, None
        failure_status = 'unavailable'
        try:
            with self.transport.lock:
                if (self.budget['calls'] >= MAX_CALLS or time.monotonic() >= self.budget['deadline']
                        or self.transport.max_calls is not None and self.transport.calls >= self.transport.max_calls):
                    raise ValueError('call budget')
                self.transport.calls += 1
                self.budget['calls'] += 1
                rid = 'request-' + str(len(self.transport.evidence) + 1)
                evidence = {'id': rid, 'scope': self.binding['selection'], 'method': 'GET',
                    'url': 'https://' + self.binding['endpoint'] + path, 'operation': 'gke-literal-list',
                    'query': {'limit': PAGE_SIZE}, 'status': 'incomplete'}
                self.transport.evidence.append(evidence)
            connection = http.client.HTTPSConnection(self.binding['endpoint'], port=443,
                context=self.binding['context'], timeout=max(.01, min(1, self.budget['deadline'] - time.monotonic())))
            connection.request('GET', path + '?' + urlencode(params), headers={
                'Authorization': 'Bearer ' + bearer, 'Accept': 'application/json', 'Accept-Encoding': 'identity'})
            del bearer
            response = connection.getresponse()
            evidence['http_status'] = response.status
            if response.status != 200:
                failure_status = 'denied' if response.status in (401, 403) else 'unavailable'
                evidence['status'] = failure_status
                raise ValueError('HTTP failure')
            encoding = response.getheader('Content-Encoding', 'identity')
            length, transfer = response.getheader('Content-Length'), response.getheader('Transfer-Encoding')
            if not isinstance(encoding, str) or encoding.strip().lower() != 'identity':
                raise ValueError('encoding')
            if length is not None:
                if transfer is not None or not isinstance(length, str) or not re.fullmatch(r'[0-9]{1,9}', length) or int(length) > MAX_HTTP_BYTES:
                    raise ValueError('framing')
                length = int(length)
            elif not isinstance(transfer, str) or transfer.strip().lower() != 'chunked' or response.chunked is not True:
                raise ValueError('framing')
            raw = bytearray()
            while True:
                self.transport.check_cancelled()
                if time.monotonic() >= self.budget['deadline']:
                    raise TimeoutError('read deadline')
                chunk = response.read(16384)
                if not chunk:
                    break
                self.budget['read_bytes'] -= len(chunk)
                if len(raw) + len(chunk) > MAX_HTTP_BYTES or self.budget['read_bytes'] < 0:
                    raise ValueError('read byte bound')
                raw.extend(chunk)
            if length is not None and len(raw) != length:
                raise ValueError('truncated')
            def pairs(values):
                out = {}
                for key, value in values:
                    if key in out:
                        raise ValueError('duplicate key')
                    out[key] = value
                return out
            data = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
            del raw
            # The raw body stays in this frame until immediate native projection.
            safe = self.project_list(data, path)
            del data
            self.transport.check_cancelled()
            if time.monotonic() >= self.budget['deadline']:
                raise TimeoutError('deadline')
            evidence['status'] = 'collected'
            return safe, rid
        except Exception:
            error = _failure('gke_literal_read_unavailable', failure_status)
            if rid is not None:
                error.request_id = rid
            raise error from None
        finally:
            for stream in (response, connection):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass

    def project_list(self, data, path):
        namespace_list = path == '/api/v1/namespaces'
        kind = 'Namespace' if namespace_list else ('ConfigMap' if path.endswith('/configmaps') else 'Pod')
        if (not isinstance(data, dict) or set(data) - {'apiVersion', 'kind', 'metadata', 'items'}
                or data.get('apiVersion') != 'v1' or data.get('kind') != kind + 'List'
                or not isinstance(data.get('items'), list) or len(data['items']) > PAGE_SIZE
                or not isinstance(data.get('metadata'), dict)):
            raise ValueError('native list shape')
        meta = data['metadata']
        rv, token = meta.get('resourceVersion'), meta.get('continue', '')
        if (not isinstance(rv, str) or not re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', rv)
                or not isinstance(token, str) or len(token.encode()) > 4096
                or 'remainingItemCount' in meta and (type(meta['remainingItemCount']) is not int
                    or meta['remainingItemCount'] < 0 or meta['remainingItemCount'] > 0 and not token)):
            raise ValueError('list continuity')
        safe = []
        if namespace_list:
            for row in data['items']:
                name = row.get('metadata', {}).get('name') if isinstance(row, dict) else None
                if not isinstance(row, dict) or row.get('apiVersion') != 'v1' or row.get('kind') != kind or not isinstance(name, str) or not DNS_LABEL.fullmatch(name):
                    raise ValueError('namespace')
                safe.append({'name': name})
        else:
            namespace = path.split('/')[4]
            for row in data['items']:
                self.budget['resources'] += 1
                if self.budget['resources'] > MAX_RESOURCES:
                    raise ValueError('resource bound')
                safe.append(project_resource(row, kind, namespace, self.binding, self.budget, self.transport.check_cancelled))
        return {'items': safe, 'continue': token, 'resourceVersion': rv}

    def pages(self, path):
        token, tokens, rv, seen = None, set(), None, set()
        for _ in range(MAX_PAGES):
            params = {'limit': PAGE_SIZE}
            if token is not None:
                params['continue'] = token
            data, rid = self.read(path, params)
            if rv is not None and data['resourceVersion'] != rv:
                raise _failure('gke_literal_list_version_changed')
            rv = data['resourceVersion']
            for row in data['items']:
                identities = [('name', row['name'])] + ([('uid', row['uid'])] if 'uid' in row else [])
                if any(identity in seen for identity in identities):
                    raise _failure('gke_literal_duplicate_resource')
                seen.update(identities)
            yield data['items'], rid
            token = data['continue']
            if not token:
                return
            if token in tokens:
                raise _failure('gke_literal_pagination_repeated')
            tokens.add(token)
        raise _failure('gke_literal_page_limit')


def dependent_jobs(collector):
    if KIND not in collector.needed:
        return []
    jobs = []
    for scope in collector.scopes:
        if not isinstance(scope, str) or not re.fullmatch('projects/' + PROJECT, scope):
            continue
        def fetch(scope=scope):
            selections, namespace_selection = selected(collector, scope)
            if not selections:
                raise _failure('gke_literal_selection_required')
            budget = {'deadline': time.monotonic() + MAX_SECONDS, 'calls': 0, 'read_bytes': MAX_READ_BYTES,
                      'scan_bytes': MAX_SCAN_BYTES, 'resources': 0}
            # Prove all endpoint/CA and existing token authority before any bridge call.
            collector.transport.check_cancelled()
            bindings = [cluster_binding(collector, scope, value) for value in selections]
            existing_bearer(collector.transport)
            for binding in bindings:
                namespaces = namespace_selection[binding['selection']][:] if namespace_selection is not None else None
                binding.update(namespace_mode='explicit' if namespaces is not None else 'discovered',
                               namespace_names=namespaces[:] if namespaces is not None else [], namespace_requests=[])
                reader = Reader(collector, binding, namespaces, budget)
                if namespaces is None:
                    namespaces = []
                    for rows, rid in reader.pages('/api/v1/namespaces'):
                        binding['namespace_requests'].append(rid)
                        yield [], rid
                        for row in rows:
                            if row['name'] in namespaces:
                                raise _failure('gke_literal_duplicate_namespace')
                            namespaces.append(row['name'])
                            if len(namespaces) > MAX_NAMESPACES:
                                raise _failure('gke_literal_namespace_limit')
                    reader.namespaces = namespaces
                    binding['namespace_names'] = namespaces[:]
                if not namespaces:
                    raise _failure('gke_literal_no_namespaces')
                for namespace in namespaces:
                    for resource in ('configmaps', 'pods'):
                        yield from reader.pages(f'/api/v1/namespaces/{namespace}/{resource}')
        jobs.append((KIND, scope, 'gke-kubernetes-readonly', fetch))
    return jobs
