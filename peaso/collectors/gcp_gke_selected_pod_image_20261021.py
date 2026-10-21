"""Exact selected GKE cluster and Pod image bridge; no implicit kube credentials."""
import base64
from copy import deepcopy
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re

from peaso import gcp_gke_image_selection_20261021 as selection
from . import k8s_selected_registry_image_20261021 as image

SECRET_KIND = 'gke_selected_pod_image_secrets'
VULN_KIND = 'gke_selected_pod_image_vulnerabilities'
SCHEMA = 'gcp-selected-gke-pod-image-v1'


def identity(target):
    return 'gke-selected-pod-image:' + hashlib.sha256(
        json.dumps(target, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _gcp_capture_scanner(target, scanner):
    """Keep private image matches bound to the selected GCP finding item."""
    resource_id = identity(target)
    scope = target['cluster_id'].split('/locations/', 1)[0]
    def scan(raw, path, source, check, leaks, parts, **kwargs):
        return scanner(raw, path, {**source, 'resource_id': resource_id, 'scope': scope},
                       check, leaks, parts, **kwargs)
    return scan


def cluster_binding(raw, target):
    """Bind canonical GKE GET fields and a public native TLS endpoint."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    match = selection.CLUSTER.fullmatch(target['cluster_id'])
    if not match or type(raw) is not dict:
        raise ValueError('gke_cluster_identity_unavailable')
    project, location, name = match.groups()
    links = {f'https://container.googleapis.com/v1/projects/{project}/{segment}/{location}/clusters/{name}'
             for segment in ('locations', 'zones')}
    if (raw.get('name') != name or raw.get('location') != location or raw.get('selfLink') not in links
            or raw.get('status') != 'RUNNING' or raw.get('_coverage')
            or type(raw.get('id')) is not str or not 1 <= len(raw['id']) <= 256):
        raise ValueError('gke_cluster_identity_unavailable')
    endpoint = raw.get('endpoint')
    try:
        address = ipaddress.ip_address(endpoint)
        if address.version != 4 or not address.is_global or str(address) != endpoint:
            raise ValueError('not public IPv4')
        control = raw.get('controlPlaneEndpointsConfig', {}).get('ipEndpointsConfig', {})
        private = raw.get('privateClusterConfig', {})
        if (type(control) is not dict or control.get('enabled') is False
                or control.get('publicEndpoint', endpoint) != endpoint
                or type(private) is not dict or private.get('enablePrivateEndpoint') is True):
            raise ValueError('private endpoint')
        encoded = raw['masterAuth']['clusterCaCertificate']
        if type(encoded) is not str or len(encoded) > 24000:
            raise ValueError('CA bound')
        pem = base64.b64decode(encoded, validate=True)
        if (base64.b64encode(pem).decode() != encoded or len(pem) > 16384
                or pem.count(b'-----BEGIN CERTIFICATE-----') != 1):
            raise ValueError('CA shape')
        certificate = x509.load_pem_x509_certificate(pem)
        if (not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                or not certificate.not_valid_before_utc <= datetime.now(timezone.utc) < certificate.not_valid_after_utc):
            raise ValueError('CA unavailable')
        certificate.verify_directly_issued_by(certificate)
    except Exception:
        raise ValueError('gke_endpoint_or_ca_unavailable') from None
    return {'name': target['cluster_id'], 'cluster_id': raw['id'], 'location': location,
            'endpoint': endpoint, 'ca_sha256': certificate.fingerprint(hashes.SHA256()).hex(),
            'ca_pem': pem.decode('ascii')}


def inspect_selected(target, *, gke_get, namespace_get, pod_get, context, allowed_hosts=(),
                     credentials=None, registry_factory=image.RegistryReader, scanner=image._scan,
                     cancel=lambda: None, redact_values=None, secret_enabled=True,
                     trivy_enabled=False, trivy_runner=None, trivy_db=None):
    """Read GKE, Namespace, Pod, OCI, Pod, Namespace, GKE in that order."""
    marker = {'schema': SCHEMA, 'identity': identity(target), 'complete': False,
              'reason': 'native_read_unavailable', 'gke_before': None, 'gke_after': None,
              'cluster_uid': None, 'image': None}
    try:
        cancel()
        before = cluster_binding(gke_get(target), target)
        marker['gke_before'] = {k: v for k, v in before.items() if k != 'ca_pem'}
        if type(context) is not dict or set(context) != {'cluster_id', 'server', 'ca_cert_data', 'token'}:
            raise ValueError('explicit_kubernetes_context_required')
        if (context['cluster_id'] != target['cluster_id']
                or context['server'] != 'https://' + before['endpoint']
                or context['ca_cert_data'] != before['ca_pem']):
            raise ValueError('gke_endpoint_or_ca_changed')
        def cluster_uid():
            row = namespace_get()
            meta = row.get('metadata', {}) if type(row) is dict else {}
            if (row.get('apiVersion') != 'v1' or row.get('kind') != 'Namespace'
                    or meta.get('name') != 'kube-system' or type(meta.get('uid')) is not str or not meta['uid']):
                raise ValueError('kubernetes_cluster_uid_unavailable')
            return meta['uid']
        uid = cluster_uid()
        marker['cluster_uid'] = hashlib.sha256(uid.encode()).hexdigest()
        native = image.inspect(target, pod_get, allowed_hosts=allowed_hosts,
            credentials=credentials, registry_factory=registry_factory,
            scanner=_gcp_capture_scanner(target, scanner),
            cancel=cancel, redact_values=redact_values, secret_enabled=secret_enabled,
            trivy_enabled=trivy_enabled, trivy_runner=trivy_runner, trivy_db=trivy_db)
        marker['image'] = native
        cancel()
        if cluster_uid() != uid:
            raise ValueError('kubernetes_cluster_uid_changed')
        after = cluster_binding(gke_get(target), target)
        marker['gke_after'] = {k: v for k, v in after.items() if k != 'ca_pem'}
        if before != after:
            raise ValueError('gke_cluster_changed')
        if native['native_before'] != native['native_after'] or native['status_image_id'] != target['image']:
            raise ValueError('pod_image_binding')
        marker['complete'] = ((secret_enabled and native['complete'] is True)
                              or (trivy_enabled and type(native.get('vulnerability')) is dict
                                  and native['vulnerability'].get('complete') is True))
        marker['reason'] = native['reason']
    except Exception as exc:
        marker['image'] = None
        marker['complete'] = False
        marker['reason'] = str(exc) if type(exc) is ValueError and str(exc) in {
            'gke_cluster_identity_unavailable', 'gke_endpoint_or_ca_unavailable',
            'explicit_kubernetes_context_required', 'gke_endpoint_or_ca_changed',
            'kubernetes_cluster_uid_unavailable', 'kubernetes_cluster_uid_changed',
            'gke_cluster_changed', 'pod_image_binding'} else 'native_read_unavailable'
    return marker


def collect(collector):
    options, auth = collector.options, collector.auth
    if any(key in options for key in ('trivy_db_cache', 'trivy_cli')):
        raise ValueError('trivy_runtime_configuration_is_not_a_request_option')
    named = options.get('_gke_image_named_checks', [])
    targets = selection.selected(options, collector.requested_scopes, named)
    secret_on = (SECRET_KIND in collector.needed and options.get('content_secret_scans') is True
                 and selection.SECRET_CHECK in named)
    vuln_on = (VULN_KIND in collector.needed and options.get('image_vulnerability_scans') is True
               and selection.VULN_CHECK in named)
    if not (secret_on or vuln_on):
        return
    contexts = selection.kubernetes_auth(auth, targets)
    credentials = image.registry_credentials(auth, targets, options[selection.HOSTS])
    if collector.max_items is not None and collector.total_items + len(targets) * (int(secret_on) + int(vuln_on)) > collector.max_items:
        raise ValueError('gke_image_item_limit')
    from . import k8s
    from . import k8s_selected_log_sample_secret_indicators as native
    rows_by_scope = {scope: [] for scope in collector.requested_scopes}
    reader_refs = {scope: [] for scope in collector.requested_scopes}
    redactions = set()
    from . import selected_image_trivy_database_20261021 as database
    lease_stack = ExitStack()
    try:
        db_cache = database.acquire(lease_stack, enabled=vuln_on, cancel=collector.transport.check_cancelled)
        for target in targets:
            cluster = target['cluster_id']; scope = cluster.split('/locations/')[0]
            context = contexts.get(cluster)
            path = '/api/v1/namespaces/' + target['namespace'] + '/pods/' + target['pod']
            state = {'api': None, 'pool': None, 'prior': None}
            refs = []
            def gke_get(_):
                url = 'https://container.googleapis.com/v1/' + cluster
                value, request_id = collector.read(url, scope, params={}, operation='gke-selected-image-cluster-get')
                refs.append(request_id)
                return value
            def api_get(request_path):
                if state['api'] is None:
                    state['api'] = k8s._new_api({'method': 'token', 'server': context['server'],
                        'ca_cert_data': context['ca_cert_data'], 'token': context['token'],
                        '_hosted': bool(options.get('hosted')), '_disable_proxy': True})
                    _, pool, _, _, _ = native._context(state['api'], cluster)
                    state['pool'] = pool; state['prior'] = pool.literal_paths
                    pool.literal_paths = frozenset(set(pool.literal_paths) | {path})
                collector.transport.check_cancelled()
                return state['api'].get_json(request_path, {})
            values = set()
            try:
                marker = inspect_selected(target, gke_get=gke_get,
                    namespace_get=lambda: api_get('/api/v1/namespaces/kube-system'),
                    pod_get=lambda _: api_get(path), context=context,
                    allowed_hosts=options[selection.HOSTS], credentials=credentials,
                    cancel=collector.transport.check_cancelled,
                    redact_values=image.redaction_callback(values) if secret_on else None,
                    secret_enabled=secret_on, trivy_enabled=vuln_on and db_cache is not None,
                    trivy_db=db_cache)
            finally:
                if state['pool'] is not None:
                    state['pool'].literal_paths = state['prior']
            if (len(redactions | values) > image.MAX_REDACTION_VALUES or
                    sum(len(value.encode('utf-8')) for value in redactions | values) > image.MAX_REDACTION_BYTES):
                redactions.clear(); values.clear()
                raise image.RedactionOverflow('gke_image_redaction_union_bound')
            redactions.update(values)
            marker['gke_source_requests'] = refs[:]
            reader_refs[scope].extend(refs)
            resource_id = identity(target)
            rows_by_scope[scope].append({'name': resource_id, 'id': resource_id,
                                         '_resource_id': resource_id, 'native_id': resource_id,
                                         '_provenance': {'scope': scope, 'source_requests': refs[:],
                                             'collected_at': getattr(collector, 'read_time', None)},
                                         'SelectedGkePodImage': marker})
    finally:
        lease_stack.close()
    collector.gke_selected_image_metadata = {selection.OPTION: deepcopy(targets),
        SECRET_KIND + '_authorized': secret_on, VULN_KIND + '_authorized': vuln_on}
    collector.gke_selected_image_redactions = redactions
    for scope, rows in rows_by_scope.items():
        if not rows:
            continue
        for kind, enabled in ((SECRET_KIND, secret_on), (VULN_KIND, vuln_on)):
            if not enabled:
                continue
            def complete(row):
                marker = row['SelectedGkePodImage']; native_marker = marker.get('image') or {}
                if marker.get('gke_before') != marker.get('gke_after'):
                    return False
                if kind == SECRET_KIND:
                    return native_marker.get('complete') is True
                return (native_marker.get('vulnerability') or {}).get('complete') is True
            envelope = {'type': kind, 'scope': scope, 'service': 'container',
                'status': 'collected' if all(complete(row) for row in rows) else 'partial',
                'coverage_status': 'collected' if all(complete(row) for row in rows) else 'partial',
                'items': deepcopy(rows), 'source_requests': reader_refs[scope][:]}
            collector.collections[(kind, scope)] = envelope
            collector.total_items += len(rows)
