"""Explicit AKS data-plane reads, ARM-bound before transmitting a Kubernetes token."""
import copy
import hashlib
import json
import re
from urllib.parse import urlsplit, quote

OPTION = 'azure_aks_workloads'
IMAGES = 'azure.gap.kubernetes_cluster_container_use_allowed_images'
PORTS = 'azure.gap.kubernetes_cluster_service_listen_to_allowed_ports'
LIMITS = 'azure.gap.kubernetes_cluster_container_cpu_and_memory_resource_limit'
READ_ONLY_ROOT = 'azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb'
# The signed historical ID mentions RBAC; its frozen predicate checks root filesystems.
WORKLOADS = {
    'aks_pod': ('/api/v1/pods', 'Pod', 'v1', 'spec'),
    'aks_deployment': ('/apis/apps/v1/deployments', 'Deployment', 'apps/v1', 'spec.template.spec'),
    'aks_statefulset': ('/apis/apps/v1/statefulsets', 'StatefulSet', 'apps/v1', 'spec.template.spec'),
    'aks_daemonset': ('/apis/apps/v1/daemonsets', 'DaemonSet', 'apps/v1', 'spec.template.spec'),
    'aks_job': ('/apis/batch/v1/jobs', 'Job', 'batch/v1', 'spec.template.spec'),
    'aks_cronjob': ('/apis/batch/v1/cronjobs', 'CronJob', 'batch/v1', 'spec.jobTemplate.spec.template.spec'),
}
NATIVE_TYPES = ('kubernetes_scope', 'pod', 'service', 'limit_range', 'pod_runtime', 'aks_legacy_pod_inventory', *WORKLOADS)
_UUID = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
_SCOPE = re.compile(r'/subscriptions/' + _UUID, re.I)
_ARM = re.compile(r'(/subscriptions/' + _UUID + r')/resourceGroups/[A-Za-z0-9_.()-]{1,90}/providers/Microsoft.ContainerService/managedClusters/[A-Za-z0-9_-]{1,63}', re.I)
_HOST = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+')


def _scope(value):
    if not isinstance(value, str) or not _SCOPE.fullmatch(value):
        raise ValueError('AKS subscription identity invalid')
    return value.lower()


def _arm(value):
    if not isinstance(value, str) or not _ARM.fullmatch(value):
        raise ValueError('AKS ARM identity invalid')
    return value.lower()


def _host(value):
    if (not isinstance(value, str) or len(value) > 253 or value != value.lower()
            or not _HOST.fullmatch(value) or not any(c.isalpha() for c in value) or any(p.startswith('xn--') for p in value.split('.'))):
        raise ValueError('AKS DNS identity invalid')
    return value


def _server(value):
    if not isinstance(value, str):
        raise ValueError('AKS explicit HTTPS server required')
    p = urlsplit(value)
    if p.scheme != 'https' or p.netloc != p.hostname or p.path or p.query or p.fragment:
        raise ValueError('AKS server must be an exact HTTPS DNS origin')
    host=_host(p.hostname)
    if value!='https://'+host:raise ValueError('AKS noncanonical HTTPS server rejected')
    return host


def _strings(values, maximum=256):
    if (not isinstance(values, list) or not 0 < len(values) <= maximum
            or any(not isinstance(x, str) or not x or len(x) > 512 for x in values)
            or len(set(values)) != len(values)):
        raise ValueError('AKS owner string list invalid')
    return list(values)


def normalize(options, auth=None):
    """Validate pure normative policy and explicit credentials before any transport."""
    if not isinstance(options, dict) or auth is not None and not isinstance(auth, dict):
        raise ValueError('AKS options and credentials must be objects')
    parent = options.get('compliance_parameters', {})
    if not isinstance(parent, dict):
        raise ValueError('AKS policy parameters invalid')
    raw = parent.get(OPTION)
    output = {}
    if raw is not None:
        try:bounded=len(json.dumps(raw,allow_nan=False))<=50000
        except (TypeError,ValueError):bounded=False
        if not bounded:raise ValueError('AKS owner policy byte budget exceeded')
        if not isinstance(raw, dict) or set(raw) != {'subscriptions'} or not isinstance(raw['subscriptions'], list) or not 0 < len(raw['subscriptions']) <= 16:
            raise ValueError('AKS owner policy subscriptions invalid')
        for row in raw['subscriptions']:
            if not isinstance(row, dict) or not {'scope'} < set(row) or set(row) - {'scope', 'images', 'service_ports', 'limits'}:
                raise ValueError('AKS owner policy fields invalid')
            scope = _scope(row['scope'])
            if scope in output:
                raise ValueError('AKS duplicate owner subscription')
            cleaned = {'scope': scope}
            if 'images' in row:
                image = row['images']
                required = {'mode', 'allowed', 'immutableImages', 'containerKinds'}
                if (not isinstance(image, dict) or not required <= set(image)
                        or set(image) - required - {'allowedDigests'} or image['mode'] not in ('images', 'registries', 'digests')
                        or type(image['immutableImages']) is not bool):
                    raise ValueError('AKS image approval fields invalid')
                _strings(image['allowed']); kinds = _strings(image['containerKinds'], 3)
                if 'containers' not in kinds or set(kinds) - {'containers', 'initContainers', 'ephemeralContainers'}:
                    raise ValueError('AKS container applicability invalid')
                from peaso.checks.compliance_new_sw25_pods import _image
                if image['mode'] == 'images':
                    for value in image['allowed']:
                        try:_image(value)
                        except Exception:raise ValueError('AKS image reference invalid') from None
                if image['mode'] == 'registries' and any(not re.fullmatch(r'[a-z0-9][a-z0-9.-]*(?::[0-9]+)?', x) for x in image['allowed']):
                    raise ValueError('AKS registry approval invalid')
                if image['mode'] == 'digests' and any(not re.fullmatch(r'sha256:[a-f0-9]{64}', x) for x in image['allowed']):
                    raise ValueError('AKS digest approval invalid')
                if image['immutableImages'] or 'allowedDigests' in image:
                    if any(not re.fullmatch(r'sha256:[a-f0-9]{64}', x) for x in _strings(image.get('allowedDigests'))):
                        raise ValueError('AKS immutable digest approval invalid')
                cleaned['images'] = copy.deepcopy(image)
            if 'limits' in row:
                limits = row['limits']
                if not isinstance(limits, dict) or set(limits) != {'maxCpu', 'maxMemory', 'containerKinds'}:
                    raise ValueError('AKS limits approval fields invalid')
                from peaso.checks.compliance_new_sw25_pods import _quantity
                for resource in ('maxCpu', 'maxMemory'):
                    try:_quantity(limits[resource])
                    except Exception:raise ValueError('AKS maximum resource quantity invalid') from None
                kinds = _strings(limits['containerKinds'], 3)
                if 'containers' not in kinds or set(kinds) - {'containers', 'initContainers', 'ephemeralContainers'}:
                    raise ValueError('AKS limits container applicability invalid')
                cleaned['limits'] = copy.deepcopy(limits)
            if 'service_ports' in row:
                ports = row['service_ports']
                if not isinstance(ports, dict) or set(ports) != {'cluster_id', 'services', 'evidence_ref'} or _arm(ports['cluster_id']).split('/resourcegroups/')[0] != scope:
                    raise ValueError('AKS port policy identity invalid')
                if not isinstance(ports['evidence_ref'], str) or not 0 < len(ports['evidence_ref']) <= 512:
                    raise ValueError('AKS port approval reference required')
                services = ports['services']
                if not isinstance(services, list) or len(services) > 1000:
                    raise ValueError('AKS service approval bounds invalid')
                seen = set()
                for service in services:
                    if not isinstance(service, dict) or set(service) != {'namespace', 'name', 'allowed'}:
                        raise ValueError('AKS service approval fields invalid')
                    key = (service['namespace'], service['name'])
                    if any(not isinstance(v, str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', v) for v in key) or key in seen:
                        raise ValueError('AKS service approval identity invalid')
                    seen.add(key); pairs = service['allowed']
                    if not isinstance(pairs, list) or len(pairs) > 256:
                        raise ValueError('AKS service port bounds invalid')
                    unique = set()
                    for pair in pairs:
                        if not isinstance(pair, dict) or set(pair) != {'port', 'protocol'} or type(pair['port']) is not int or not 1 <= pair['port'] <= 65535 or pair['protocol'] not in ('TCP','UDP','SCTP') or (pair['port'],pair['protocol']) in unique:
                            raise ValueError('AKS service port approval invalid')
                        unique.add((pair['port'],pair['protocol']))
                cleaned['service_ports'] = copy.deepcopy(ports)
                cleaned['service_ports']['cluster_id'] = _arm(ports['cluster_id'])
            output[scope] = cleaned
    contexts = {}
    if auth is not None and 'aks_workloads' in auth:
        entries = auth['aks_workloads']
        try:bounded=len(json.dumps(entries,allow_nan=False))<=2000000
        except (TypeError,ValueError):bounded=False
        if not bounded:raise ValueError('AKS credential byte budget exceeded')
        if not isinstance(entries, list) or not 0 < len(entries) <= 16:
            raise ValueError('AKS explicit credential bounds invalid')
        from cryptography import x509
        endpoints=set()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {'cluster_id', 'server', 'ca_cert_data', 'token'}:
                raise ValueError('AKS explicit credential fields invalid')
            rid = _arm(entry['cluster_id']); _server(entry['server'])
            if entry['server'] in endpoints:raise ValueError('AKS endpoint bound to multiple resource identities')
            endpoints.add(entry['server'])
            if rid in contexts:
                raise ValueError('AKS duplicate credential binding')
            token, ca = entry['token'], entry['ca_cert_data']
            if not isinstance(token, str) or not 0 < len(token) <= 1000000 or not token.isascii() or any(c.isspace() or ord(c) < 33 or ord(c) > 126 for c in token):
                raise ValueError('AKS explicit bearer token invalid')
            if not isinstance(ca, str) or not 0 < len(ca) <= 100000 or 'PRIVATE KEY' in ca:
                raise ValueError('AKS inline CA certificate invalid')
            try:
                certs=x509.load_pem_x509_certificates(ca.encode())
                if not certs or any(not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca for cert in certs):
                    raise ValueError('AKS trust anchor must be a CA')
            except Exception:raise ValueError('AKS inline CA certificate invalid') from None
            contexts[rid] = copy.deepcopy(entry)
    return output, contexts


def bind_scopes(options, auth, scopes):
    policies,contexts=normalize(options,auth)
    selected={s.lower() for s in scopes}
    if set(policies)-selected or any(rid.split('/resourcegroups/')[0] not in selected for rid in contexts):
        raise ValueError('AKS explicit context or policy outside selected subscription')


def required_types(wanted):
    needed = {'aks_cluster', 'arc_kubernetes_cluster', 'subscription'} if set(wanted).intersection(NATIVE_TYPES) else set()
    if 'pod_runtime' in wanted:needed.add('pod')
    if 'aks_legacy_pod_inventory' in wanted:needed.update(('pod','kubernetes_scope'))
    return needed


def _identity(item, kind, api_version='v1'):
    meta = item.get('metadata', {})
    if (item.get('apiVersion') != api_version or item.get('kind') != kind
            or not isinstance(meta, dict) or not isinstance(meta.get('uid'), str) or not meta['uid']
            or not isinstance(meta.get('resourceVersion'), str) or not meta['resourceVersion']):
        raise ValueError('AKS Kubernetes object identity unavailable')
    return meta


def _root_filesystem_projection(item, kind):
    """Project admitted manifest fields, never env/command/secret references."""
    _, native_kind, api_version, path = WORKLOADS[kind]
    meta = _identity(item, native_kind, api_version)
    current = item
    for component in path.split('.'):
        current = current.get(component) if isinstance(current, dict) else None
        if not isinstance(current, dict):
            raise ValueError('AKS workload PodSpec missing or malformed')
    projected, absent, names = {}, [], set()
    fields = ('containers', 'initContainers', 'ephemeralContainers') if kind == 'aks_pod' else ('containers', 'initContainers')
    for field in fields:
        if field not in current:
            if field == 'containers':raise ValueError('AKS required containers missing')
            # Native complete JSON uses omitempty for absent optional container lists.
            values = []; absent.append(path + '.' + field)
        else:
            values = current[field]
            if not isinstance(values, list):raise ValueError('AKS container list malformed')
        if field == 'containers' and not values:raise ValueError('AKS workload has no containers')
        entries = []
        for container in values:
            if not isinstance(container, dict):raise ValueError('AKS container malformed')
            name = container.get('name')
            if not isinstance(name, str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', name) or name in names:
                raise ValueError('AKS container identity malformed or duplicate')
            names.add(name)
            security = container.get('securityContext', {})
            if not isinstance(security, dict):raise ValueError('AKS security context malformed')
            flags = {}
            if 'readOnlyRootFilesystem' in security:
                if type(security['readOnlyRootFilesystem']) is not bool:
                    raise ValueError('AKS read-only root flag must be a native boolean')
                flags['readOnlyRootFilesystem'] = security['readOnlyRootFilesystem']
            entries.append({'name': name, 'securityContext': flags})
        projected[field] = entries
    result = {'id': item['id'], 'apiVersion': api_version, 'kind': native_kind,
              'metadata': {key: meta[key] for key in ('name','namespace','uid','resourceVersion')}}
    nested = result
    for component in path.split('.')[:-1]:nested = nested.setdefault(component, {})
    nested[path.split('.')[-1]] = projected
    result['_native_optional_absent_arrays'] = absent
    return result


def _cluster(reader, transport, request, listed, scope, context, wanted, hosted):
    from . import k8s
    from .azure import ARM, AzureReadError
    rid = _arm(listed.get('id'))
    if str(listed.get('name','')).lower()!=rid.rsplit('/',1)[-1]:raise ValueError('AKS listed name mismatch')
    if str(listed.get('type','')).lower() != 'microsoft.containerservice/managedclusters' or rid.split('/resourcegroups/')[0] != scope:
        raise ValueError('AKS foreign listed cluster')
    current = reader.call(request, ARM + listed['id'] + '?api-version=2024-05-01')
    if _arm(current.get('id')) != rid or str(current.get('type','')).lower() != 'microsoft.containerservice/managedclusters':
        raise ValueError('AKS GET identity mismatch')
    if str(current.get('name','')).lower()!=rid.rsplit('/',1)[-1]:raise ValueError('AKS GET name mismatch')
    props = current.get('properties', {})
    if not isinstance(props, dict) or props.get('provisioningState') != 'Succeeded':
        raise AzureReadError('aks_cluster_not_ready')
    host = _server(context['server'])
    hosts = {_host(props[k]) for k in ('fqdn','privateFQDN') if props.get(k)}
    if host not in hosts:
        raise AzureReadError('aks_endpoint_binding_mismatch')
    api = k8s._new_api({'method':'token','server':context['server'],'ca_cert_data':context['ca_cert_data'],
                        'token':context['token'], '_hosted':hosted, '_disable_proxy':True})
    observed = False
    try:
        def uid():
            raw = reader.call(api.get_json, '/api/v1/namespaces/kube-system', {})
            meta = _identity(raw, 'Namespace')
            if meta.get('name') != 'kube-system' or meta.get('namespace'):
                raise ValueError('AKS cluster namespace identity invalid')
            return meta['uid']
        before = uid()
        observed = True
        legacy_pages = {}
        capture_legacy_pages = True
        class Lists:
            def get_json(self,path,params):
                payload=api.get_json(path,params)
                kinds={'/api/v1/namespaces':('v1','NamespaceList'),'/api/v1/pods':('v1','PodList'),'/api/v1/services':('v1','ServiceList'),'/api/v1/limitranges':('v1','LimitRangeList')}
                kinds.update({endpoint:(version,kind+'List') for endpoint,kind,version,_ in WORKLOADS.values()})
                schema=kinds.get(path)
                if not isinstance(payload,dict) or schema is None or payload.get('apiVersion')!=schema[0] or payload.get('kind')!=schema[1]:
                    raise ValueError('AKS native list generation unavailable')
                meta=payload.get('metadata',{})
                if not isinstance(meta,dict) or not isinstance(meta.get('resourceVersion'),str) or not meta['resourceVersion']:
                    raise ValueError('AKS native list snapshot version unavailable')
                if 'continue' in meta and (not isinstance(meta['continue'],str) or len(meta['continue'])>4096):
                    raise ValueError('AKS native list continuation invalid')
                # Native typed LIST items may omit TypeMeta. Its authority is the
                # exact endpoint and validated List generation above, not input
                # supplied by an owner. Explicit conflicting/null fields survive
                # and are rejected by _identity below.
                items = payload.get('items')
                if not isinstance(items,list) or any(not isinstance(item,dict) for item in items):
                    raise ValueError('AKS native list items malformed')
                if 'aks_legacy_pod_inventory' in wanted and capture_legacy_pages:
                    from .azure_aks_legacy_projection_review_20261020 import record_page
                    record_page(legacy_pages,path,params,payload)
                payload = {**payload, 'items': [
                    {'apiVersion':schema[0], 'kind':schema[1][:-4], **item}
                    for item in items]}
                return payload
        lists=Lists()
        namespaces = []
        for page in k8s._pages(reader, lists, '/api/v1/namespaces', 'namespace', rid, '*', False):
            namespaces.extend(page)
            if reader.budget.max_items is not None and reader.total+len(namespaces)>reader.budget.max_items:
                raise AzureReadError('resource_limit')
        names = set(); namespace_uids = set()
        for row in namespaces:
            meta = _identity(row, 'Namespace')
            if meta['name'] in names or meta['uid'] in namespace_uids:
                raise ValueError('AKS ambiguous namespace inventory')
            names.add(meta['name']); namespace_uids.add(meta['uid'])
        if 'kube-system' not in names or not any(x['metadata']['name']=='kube-system' and x['metadata']['uid']==before for x in namespaces):
            raise ValueError('AKS namespace inventory cluster identity mismatch')
        rows = {}
        endpoints=[('pod','/api/v1/pods','Pod','v1'),('service','/api/v1/services','Service','v1'),('limit_range','/api/v1/limitranges','LimitRange','v1')]
        endpoints.extend((kind,path,native,version) for kind,(path,native,version,_) in WORKLOADS.items())
        for kind, path, native_kind, api_version in endpoints:
            if kind not in wanted:continue
            capture_legacy_pages = kind == 'pod'
            output = []; seen = set()
            for page in k8s._pages(reader, lists, path, 'limitrange' if kind=='limit_range' else kind, rid, '*', True):
                for row in page:
                    meta = _identity(row, native_kind, api_version)
                    if meta.get('namespace') not in names or meta['uid'] in seen:
                        raise ValueError('AKS foreign or duplicate workload identity')
                    seen.add(meta['uid'])
                    # The signed root-filesystem check only needs these narrow admitted fields.
                    if kind in WORKLOADS:row = _root_filesystem_projection(row, kind)
                    # The original native sanitizer redacts literals. Never call this an unredacted payload.
                    row['_provenance'] = {'cluster_id':rid, 'source_operation':path+':LIST' if kind in WORKLOADS else 'list_pods' if kind=='pod' else 'core/v1/services:LIST' if kind=='service' else 'core/v1/limitranges:LIST',
                        'representation':'full', 'read_only':True, 'api_version':api_version, 'cluster_uid':before,
                        'projection':'native identity and root-filesystem flags only' if kind in WORKLOADS else 'native admitted fields with workload literals redacted'}
                    if kind in WORKLOADS:row['_provenance']['optional_absent_arrays']=row.pop('_native_optional_absent_arrays')
                    output.append(row)
                    if reader.budget.max_items is not None and reader.total + sum(map(len,rows.values())) + len(output) > reader.budget.max_items:
                        raise AzureReadError('resource_limit')
            rows[kind] = output
        if 'pod_runtime' in wanted:
            from .azure_aks_admitted_limits_native import project
            rows['pod_runtime'] = [project(pod, rid, before) for pod in rows.get('pod', [])]
            if reader.budget.max_items is not None and reader.total + sum(map(len, rows.values())) > reader.budget.max_items:
                raise AzureReadError('resource_limit')
        after = uid()
        if after != before:
            raise AzureReadError('aks_cluster_uid_changed')
        proof = {'id':rid, 'kind':'AKS', 'namespaces':sorted(names), '_coverage':{
            'namespaces':{'status':'collected'},'pods':{'status':'collected' if 'pod' in rows else 'not_collected'}},
            '_provenance':{'cluster_uid':before,'ARM_api_version':'2024-05-01','server':context['server'],
                'ca_sha256':hashlib.sha256(context['ca_cert_data'].encode()).hexdigest(),'read_only':True}}
        if 'aks_legacy_pod_inventory' in wanted:
            from .azure_aks_legacy_projection_review_20261020 import KIND,project
            proof['native_namespace_uids']={row['metadata']['name']:row['metadata']['uid'] for row in namespaces}
            proof['native_ARM_get']={key:current[key] for key in ('id','name','type')}
            proof['native_ARM_get']['properties']={key:props[key] for key in ('fqdn','privateFQDN','provisioningState') if key in props}
            proof['_provenance'].update(native_list_pages=legacy_pages,cluster_uid_before=before,cluster_uid_after=after)
            rows[KIND]=[project(rid,rows['pod'],proof)]
        return rows, proof
    except Exception as exc:
        if observed:exc.aks_capture_partial = True
        raise
    finally:
        api.close()


def collect(reader, request, transport, scopes, wanted, options, auth):
    active = set(wanted).intersection(NATIVE_TYPES)
    if not active:return
    policies, contexts = normalize(options, auth)
    if any(rid.split('/resourcegroups/')[0] not in {s.lower() for s in scopes} for rid in contexts):
        raise ValueError('AKS credential outside selected subscriptions')
    metadata = {}
    from .azure import AzureReadError, _safe_error
    verified = getattr(transport, 'verified_tenant', None)
    for scope in scopes:
        scope = scope.lower(); by_type = {k:[] for k in active}; clusters=[]; status='collected';error=None; service_error=None
        try:
            if not verified:raise AzureReadError('aks_ARM_tenant_unverified')
            subscriptions=[row for c in reader.collections if c['type']=='subscription' and c['status'] in ('collected','empty') for row in c['items'] if str(row.get('id','')).lower()==scope]
            if len(subscriptions)!=1 or subscriptions[0].get('tenantId')!=verified:
                raise AzureReadError('aks_subscription_tenant_unverified')
            arcs=[c for c in reader.collections if c['type']=='arc_kubernetes_cluster' and c['scope'].lower()==scope]
            if len(arcs)!=1 or arcs[0]['status'] not in ('collected','empty') or arcs[0]['items']:
                raise AzureReadError('aks_Arc_workload_universe_unresolved')
            parents=[c for c in reader.collections if c['type']=='aks_cluster' and c['scope'].lower()==scope]
            if len(parents)!=1 or parents[0]['status'] not in ('collected','empty'):
                raise AzureReadError('aks_cluster_inventory_incomplete')
            ids=set()
            for listed in parents[0]['items']:
                rid=_arm(listed.get('id'))
                if rid in ids:raise ValueError('AKS duplicate parent identity')
                ids.add(rid)
            if set(contexts).intersection({r for r in contexts if r.startswith(scope+'/')})!=ids:
                raise AzureReadError('aks_cluster_credentials_incomplete_or_foreign')
            for listed in parents[0]['items']:
                rid=_arm(listed.get('id'))
                rows,proof=_cluster(reader,transport,request,listed,scope,contexts[rid],active,bool(options.get('hosted')))
                for kind,values in rows.items():by_type[kind].extend(values)
                if reader.budget.max_items is not None and reader.total+sum(map(len,by_type.values()))>reader.budget.max_items:
                    raise AzureReadError('resource_limit')
                if any(p['_provenance']['cluster_uid']==proof['_provenance']['cluster_uid'] for p in clusters):
                    raise AzureReadError('aks_cluster_uid_bound_to_multiple_ARM_resources')
                clusters.append(proof)
            if 'kubernetes_scope' in active:
                by_type['kubernetes_scope']=[{'id':scope+'/aks-workloads', 'clusters':clusters}]
            if len(clusters)==1:
                metadata['cluster_id']=clusters[0]['id']
            elif 'service' in active:
                service_error={'code':'aks_service_policy_multicluster_unsupported'}
        except Exception as exc:
            status,error=_safe_error(exc)
            if getattr(exc,'aks_capture_partial',False):status='partial'
            if status in ('collected','empty'):status='unknown'
            # Never publish a truncated universe as complete, including failed UID postchecks.
            by_type={k:[] for k in active}
        for kind,items in sorted(by_type.items()):
            envelope={'type':kind,'scope':scope,'service':'Kubernetes.core/v1' if kind=='service' else 'kubernetes','status':status if error else 'collected' if items else 'empty','items':items}
            if error:envelope['error']=error
            elif kind=='service' and service_error:
                envelope.update(status='not_collected',items=[],error=service_error)
            reader.collections.append(envelope);reader.total+=len(envelope['items']);reader.progress(scope=scope,settled=envelope)
    for scope,policy in policies.items():
        if scope not in {s.lower() for s in scopes}:raise ValueError('AKS policy outside selected subscription')
        if 'limits' in policy:metadata.setdefault('sw25_policy',{})[LIMITS]={'scope':scope,**policy['limits']}
        if 'images' in policy:metadata.setdefault('sw25_policy',{})[IMAGES]={'scope':scope,**policy['images']}
        if 'service_ports' in policy and metadata.get('cluster_id')==policy['service_ports']['cluster_id']:
            metadata.setdefault('sw22',{})['approved_service_ports']={'status':'collected','scope':scope,**policy['service_ports']}
    reader.native_aks_workloads_metadata=metadata
