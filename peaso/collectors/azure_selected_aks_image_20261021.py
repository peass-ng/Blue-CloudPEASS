"""Selected AKS Pod image bridge. Arc is an explicit unsupported capability."""
from copy import deepcopy
from contextlib import ExitStack
import hashlib
import json
import re
from urllib.parse import quote

from . import azure_aks_workloads_native as aks
from . import k8s_selected_registry_image_20261021 as image

KIND = 'azure_selected_aks_pod_image'
CHECK = 'azure.review.aks.selected_pod_image_secret_indicators'
VULN_KIND = 'azure_selected_aks_pod_image_vulnerabilities'
VULN_CHECK = 'azure.review.aks.selected_pod_image_high_vulnerabilities'
OPTION = 'selected_azure_aks_pod_images'
SCHEMA = 'azure-selected-aks-pod-image-v1'
MAX_TARGETS = 4
_ARC = re.compile(r'/subscriptions/' + aks._UUID +
                  r'/resourceGroups/[A-Za-z0-9_.()-]{1,90}/providers/Microsoft\.Kubernetes/connectedClusters/[A-Za-z0-9_-]{1,63}\Z', re.I)


def selected_targets(options, scopes, named=()):
    """Entire preflight is pure and runs before ARM, Kubernetes, or registry auth."""
    if (type(options) is not dict or
            any(key in options and type(options[key]) is not bool
                for key in ('content_secret_scans', 'image_vulnerability_scans'))):
        raise ValueError('invalid_aks_image_selection')
    if any(key in options for key in ('trivy_db_cache', 'trivy_cli')):
        raise ValueError('trivy_runtime_configuration_is_not_a_request_option')
    active = ((options.get('content_secret_scans') is True and CHECK in named)
              or (options.get('image_vulnerability_scans') is True and VULN_CHECK in named))
    if OPTION not in options and not active:
        return []
    rows = options.get(OPTION)
    if type(rows) is not list or not 1 <= len(rows) <= MAX_TARGETS or type(scopes) is not list:
        raise ValueError('invalid_aks_image_selection')
    scopes = {s.casefold() for s in scopes if type(s) is str}
    seen = set()
    for row in rows:
        if type(row) is not dict or set(row) != {'cluster_id', 'namespace', 'pod', 'uid', 'resource_version', 'container_type', 'container_name', 'image'}:
            raise ValueError('invalid_aks_image_selection')
        rid = row['cluster_id']
        if type(rid) is not str or not (aks._ARM.fullmatch(rid) or _ARC.fullmatch(rid)) or rid.casefold().split('/resourcegroups/')[0] not in scopes:
            raise ValueError('invalid_aks_image_selection')
        # Reuse the existing exact Pod/digest/host validator without enabling I/O.
        image.selected_targets({image.OPTION: [row], image.ALLOWLIST: options.get(image.ALLOWLIST, []),
                                'content_secret_scans': True}, [row['namespace']], [image.SECRET_CHECK])
        key = image.identity(row)
        if key in seen:
            raise ValueError('duplicate_aks_image_selection')
        seen.add(key)
    return deepcopy(rows)


def identity(target):
    return KIND + ':' + hashlib.sha256(json.dumps(target, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _arm_binding(raw, target, tenant):
    rid = target['cluster_id']
    if not isinstance(tenant, str) or not tenant:
        raise ValueError('aks_arm_tenant_changed')
    if (type(raw) is not dict or str(raw.get('id', '')).casefold() != rid.casefold()
            or str(raw.get('type', '')).casefold() != 'microsoft.containerservice/managedclusters'
            or str(raw.get('name', '')).casefold() != rid.rsplit('/', 1)[-1].casefold()):
        raise ValueError('aks_arm_identity_changed')
    properties = raw.get('properties')
    if type(properties) is not dict or properties.get('provisioningState') != 'Succeeded':
        raise ValueError('aks_arm_unavailable')
    resource_uid = properties.get('resourceUID')
    if type(resource_uid) is not str or not 1 <= len(resource_uid) <= 256:
        raise ValueError('aks_arm_identity_changed')
    hosts = {aks._host(properties[key]) for key in ('fqdn', 'privateFQDN') if properties.get(key)}
    if not hosts:
        raise ValueError('aks_endpoint_unavailable')
    # ARM does not authorize Pod reads; the explicit Kubernetes context does.
    owner = raw.get('identity', {})
    if type(owner) is dict and owner.get('tenantId') and str(owner['tenantId']).casefold() != tenant.casefold():
        raise ValueError('aks_arm_tenant_changed')
    return {'id': rid.casefold(), 'hosts': sorted(hosts), 'resource_uid': resource_uid,
            'provisioning_state': properties['provisioningState']}


def inspect_selected(target, *, arm_get, namespace_get, pod_get, context, tenant,
                     registry_factory=image.RegistryReader, scanner=image._scan,
                     credentials=None, allowed_hosts=(), cancel=lambda: None, redact_values=None,
                     secret_enabled=True, trivy_enabled=False, trivy_runner=None, trivy_db=None):
    """Bound one ARM owner, exact Kubernetes cluster UID, Pod and OCI digest."""
    marker = {'schema': SCHEMA, 'identity': identity(target), 'complete': False, 'reason': 'capability_unavailable',
              'arm_before': None, 'arm_after': None, 'cluster_uid': None, 'image': None}
    if _ARC.fullmatch(target['cluster_id']):
        marker['reason'] = 'arc_kubernetes_api_endpoint_unavailable'
        return marker
    try:
        cancel()
        before = _arm_binding(arm_get(target), target, tenant)
        marker['arm_before'] = before
        if type(context) is not dict or set(context) != {'cluster_id', 'server', 'ca_cert_data', 'token'}:
            raise ValueError('explicit_kubernetes_context_required')
        if context['cluster_id'].casefold() != target['cluster_id'].casefold() or aks._server(context['server']) not in before['hosts']:
            raise ValueError('aks_endpoint_binding_mismatch')
        def cluster_uid():
            namespace = namespace_get()
            meta = namespace.get('metadata', {}) if type(namespace) is dict else {}
            if (namespace.get('apiVersion') != 'v1' or namespace.get('kind') != 'Namespace'
                    or meta.get('name') != 'kube-system' or not isinstance(meta.get('uid'), str) or not meta['uid']):
                raise ValueError('kubernetes_cluster_uid_unavailable')
            return meta['uid']
        uid = cluster_uid()
        marker['cluster_uid'] = hashlib.sha256(uid.encode()).hexdigest()
        # The registry reader's public item is nested under this selected AKS
        # item. Keep its exact layer/path witness, but bind private matches to
        # the owner finding's resource and subscription scope.
        def bound_scanner(raw, path, source, check, leaks, parts, **kwargs):
            return scanner(raw, path, {**source, 'resource_id': identity(target),
                'scope': target['cluster_id'].casefold().split('/resourcegroups/', 1)[0]},
                check, leaks, parts, **kwargs)
        marker['image'] = image.inspect(target, pod_get, allowed_hosts=allowed_hosts,
            credentials=credentials, registry_factory=registry_factory, scanner=bound_scanner,
            cancel=cancel, redact_values=redact_values, secret_enabled=secret_enabled,
            trivy_enabled=trivy_enabled,
            trivy_runner=trivy_runner, trivy_db=trivy_db)
        cancel()
        if cluster_uid() != uid:
            raise ValueError('kubernetes_cluster_uid_changed')
        after = _arm_binding(arm_get(target), target, tenant)
        marker['arm_after'] = after
        if before != after:
            raise ValueError('aks_arm_identity_changed')
        native = marker['image']
        if native['native_before'] != native['native_after'] or native['status_image_id'] != target['image']:
            raise ValueError('pod_image_binding')
        marker['complete'] = ((secret_enabled and native['complete'] is True)
                              or (trivy_enabled and isinstance(native.get('vulnerability'), dict)
                                  and native['vulnerability'].get('complete') is True))
        marker['reason'] = native['reason']
    except Exception as exc:
        # A changed owner or cluster cannot authorize a previously found value.
        marker['image'] = None
        marker['complete'] = False
        marker['reason'] = str(exc) if type(exc) is ValueError and str(exc) in {
            'explicit_kubernetes_context_required', 'aks_endpoint_binding_mismatch',
            'kubernetes_cluster_uid_unavailable', 'kubernetes_cluster_uid_changed',
            'aks_arm_identity_changed', 'aks_arm_unavailable', 'aks_endpoint_unavailable',
            'aks_arm_tenant_changed', 'pod_image_binding'} else 'native_read_unavailable'
    return marker


def collect(reader, request, transport, scopes, wanted, options, auth):
    if KIND not in wanted and VULN_KIND not in wanted:
        return
    named = options.get('_azure_aks_image_named_checks', [])
    targets = selected_targets(options, scopes, named)
    secret_on = KIND in wanted and options.get('content_secret_scans') is True and CHECK in named
    vuln_on = VULN_KIND in wanted and options.get('image_vulnerability_scans') is True and VULN_CHECK in named
    if not (secret_on or vuln_on):
        return
    needed = len(targets) * (int(secret_on) + int(vuln_on))
    if reader.budget.max_items is not None and reader.total + needed > reader.budget.max_items:
        raise ValueError('aks_image_item_limit')
    _, contexts = aks.normalize(options, auth)
    image.registry_credentials(auth, targets, options.get(image.ALLOWLIST, []))
    from . import k8s
    from .azure import ARM
    from .azure_selected_secret_integration_20261020 import remember
    reader.azure_aks_image_redactions = set()
    collections = {scope.casefold(): [] for scope in scopes}
    from . import selected_image_trivy_database_20261021 as database
    lease_stack = ExitStack()
    try:
        db_cache = database.acquire(lease_stack, enabled=vuln_on, cancel=reader.check_cancelled)
        for target in targets:
            scope = target['cluster_id'].casefold().split('/resourcegroups/')[0]
            verified_tenant = getattr(transport, 'verified_tenant', None)
            subscriptions = [row for collection in reader.collections
                             if collection.get('type') == 'subscription' and collection.get('scope', '').casefold() == scope
                             and collection.get('status') in ('collected', 'empty') for row in collection.get('items', [])
                             if str(row.get('id', '')).casefold() == scope]
            if (not isinstance(verified_tenant, str) or len(subscriptions) != 1
                    or str(subscriptions[0].get('tenantId', '')).casefold() != verified_tenant.casefold()):
                raise ValueError('aks_subscription_tenant_unverified')
            context = contexts.get(target['cluster_id'].casefold())
            api = None
            pool = None
            if context is not None and not _ARC.fullmatch(target['cluster_id']):
                api = k8s._new_api({'method': 'token', 'server': context['server'], 'ca_cert_data': context['ca_cert_data'],
                                    'token': context['token'], '_hosted': bool(options.get('hosted')), '_disable_proxy': True})
            path = '/api/v1/namespaces/' + quote(target['namespace'], safe='') + '/pods/' + quote(target['pod'], safe='')
            if api is not None:
                from . import k8s_selected_log_sample_secret_indicators as native
                _, pool, _, _, _ = native._context(api, target['cluster_id'])
                previous_paths = pool.literal_paths
                pool.literal_paths = frozenset(set(previous_paths) | {path})
            def arm_get(_):
                return reader.call(request, ARM + target['cluster_id'] + '?api-version=2024-05-01')
            def namespace_get():
                return reader.call(api.get_json, '/api/v1/namespaces/kube-system', {})
            def pod_get(_):
                return reader.call(api.get_json, path, {})
            values = set()
            try:
                marker = inspect_selected(target, arm_get=arm_get, namespace_get=namespace_get, pod_get=pod_get,
                    context=context, tenant=verified_tenant,
                    credentials=image.registry_credentials(auth, [target], options.get(image.ALLOWLIST, [])),
                    allowed_hosts=options.get(image.ALLOWLIST, []), cancel=reader.check_cancelled,
                    redact_values=image.redaction_callback(values) if secret_on else None,
                    secret_enabled=secret_on, trivy_enabled=vuln_on and db_cache is not None,
                    trivy_db=db_cache)
            finally:
                if pool is not None:
                    pool.literal_paths = previous_paths
            if values:
                remember(reader, 'azure_aks_image_redactions', values)
            collections[scope].append({'id': identity(target), 'name': identity(target), 'SelectedAksImage': marker})
    finally:
        lease_stack.close()
    reader.azure_aks_image_metadata = {KIND + '_authorized': secret_on,
        VULN_KIND + '_authorized': vuln_on, OPTION: deepcopy(targets)}
    for scope, items in collections.items():
        if items:
            for kind, enabled in ((KIND, secret_on), (VULN_KIND, vuln_on)):
                if enabled:
                    def complete(row):
                        marker = row['SelectedAksImage']
                        native = marker.get('image') or {}
                        if kind == KIND:
                            return native.get('complete') is True and marker.get('arm_before') == marker.get('arm_after')
                        vuln = native.get('vulnerability') or {}
                        return vuln.get('complete') is True and marker.get('arm_before') == marker.get('arm_after')
                    reader.collections.append({'type': kind, 'scope': scope, 'service': 'Microsoft.ContainerService',
                        'status': 'collected' if all(complete(i) for i in items) else 'partial',
                        'items': deepcopy(items)})
                    reader.total += len(items)
