"""Unregistered bounded ConfigMap declaration criteria, never node state."""
import re
from urllib.parse import quote

from peaso.collectors.k8s_kubelet_configmap_indicators_20261020 import (
    KIND, MARKER, SCHEMA, PREFIX, FIELDS, CONTEXT, CONTEXT_SCHEMA, digest, identity)

PREFIX_ID = 'k8s.review.kubelet_configmap.'
SPECS = {
    'authorization_webhook':('authorization_mode','Explicit kubelet declaration uses Webhook authorization',
        'The ConfigMap explicitly declares Webhook authorization.', 'The ConfigMap explicitly declares AlwaysAllow authorization.'),
    'client_ca_configured':('client_ca_configured','Explicit kubelet declaration configures a client CA path',
        'The ConfigMap explicitly declares a nonempty client CA path.', 'The ConfigMap explicitly declares an empty client CA path.'),
    'anonymous_disabled':('anonymous_disabled','Explicit kubelet declaration disables anonymous authentication',
        'The ConfigMap explicitly disables anonymous authentication.', 'The ConfigMap explicitly enables anonymous authentication.'),
    'readonly_disabled':('readonly_disabled','Explicit kubelet declaration disables the read-only port',
        'The ConfigMap explicitly disables the unauthenticated read-only port.', 'The ConfigMap explicitly declares a nonzero unauthenticated read-only port.'),
    'client_certificate_rotation':('client_rotation','Explicit kubelet declaration enables client certificate rotation',
        'The ConfigMap explicitly enables client certificate rotation requests.', 'The ConfigMap explicitly disables client certificate rotation requests.'),
    'explicit_cipher_allowlist':('cipher_allowlist','Explicit kubelet cipher declaration matches the reviewed allowlist',
        'The explicit cipher list matches the fixed reviewed allowlist.', 'The explicit cipher list includes a recognized cipher outside the fixed reviewed allowlist.'),
    'tls_file_pair_configured':('tls_files_configured','Explicit kubelet declaration configures certificate and key paths',
        'The ConfigMap explicitly declares nonempty certificate and key paths.', 'The ConfigMap explicitly declares an empty certificate or key path.'),
    'event_qps_bounded':('event_qps_bounded','Explicit kubelet declaration limits event creation rate',
        'The ConfigMap explicitly declares a positive eventRecordQPS limit.', 'The ConfigMap explicitly declares eventRecordQPS as zero, which means unlimited event creation.'),
}
IDS = tuple(PREFIX_ID+suffix for suffix in SPECS)
LIMIT = 'This named ConfigMap is a declaration source; node adoption, overrides and runtime behavior were not verified.'


def _indicator(item, index, field):
    context=index['context'];scope=context['scope'];metadata=context['metadata'];cluster=metadata['cluster_id']
    auth=metadata[CONTEXT]
    if (context['provider']!='k8s' or not isinstance(cluster,str) or not cluster
            or auth['schema']!=CONTEXT_SCHEMA or auth['provider']!='k8s' or auth['cluster_id']!=cluster
            or auth['authentication'] not in ('configured_bearer','configured_client_certificate')
            or re.fullmatch('[0-9a-f]{64}',auth['origin_digest']) is None
            or re.fullmatch('[0-9a-f]{32}',auth['session']) is None):raise ValueError('configmap_authenticated_context')
    own, = [r for r in index['collections'][KIND] if r.get('scope')==scope]
    if (own['type']!=KIND or own['service']!='kubernetes' or own['status']!='collected'
            or own.get('error') or sum(r==item for r in own['items'])!=1):raise ValueError('configmap_inventory_incomplete')
    values=identity(item);version,typ,ns,name,uid,rv=values
    if (not name.startswith(PREFIX) or scope!='*' and ns!=scope or item.get('apiVersion')!=version
            or item.get('kind')!=typ or any(k in item for k in ('data','binaryData','stringData'))):raise ValueError('configmap_native_identity')
    expected_path='/api/v1/'+('' if scope=='*' else 'namespaces/'+quote(scope,safe='')+'/')+'configmaps'
    native_id='k8s://'+'/'.join(quote(str(v),safe='') for v in (cluster,KIND,ns,uid))
    marker=item[MARKER]
    if (set(marker)!={'schema','identity_digest','indicators','source'} or marker['schema']!=SCHEMA
            or marker['identity_digest']!=digest(values) or set(marker['indicators'])!=set(FIELDS)
            or item['id']!=native_id):raise ValueError('configmap_projection_schema')
    source=marker['source'];list_version=source['list_resource_version']
    if (not isinstance(list_version,str) or re.fullmatch('[A-Za-z0-9._~:+/=-]{1,128}',list_version) is None
            or source!={'method':'GET','path':'/api/v1/namespaces/'+quote(ns,safe='')+'/configmaps/'+quote(name,safe=''),
                       'scope':scope,'context_digest':digest(auth),'native_id':native_id,'list_resource_version':list_version,
                       'discovery_path':expected_path,'discovery_type':'meta.k8s.io/v1/PartialObjectMetadataList'}):raise ValueError('configmap_native_request_binding')
    provenance=item['provenance']
    if (provenance.get('cluster_id')!=cluster or provenance.get('namespace')!=ns or provenance.get('uid')!=uid
            or provenance.get('apiVersion')!=version or provenance.get('resourceVersion')!=rv
            or provenance.get('evidence')!='read-only GET after metadata list' or provenance.get('representation') is not None):raise ValueError('configmap_native_provenance')
    indicator=marker['indicators'][field]
    if set(indicator)!={'status','value'} or indicator['status']!='observed':raise ValueError('configmap_deciding_field_missing')
    value=indicator['value']
    if field=='authorization_mode':
        if type(value) is not str or value not in ('Webhook','AlwaysAllow'):raise ValueError('configmap_mode_enum')
        return value=='Webhook'
    if type(value) is not bool:raise ValueError('configmap_indicator_type')
    return value


def evaluate(check_id, item, index):
    try:
        if check_id not in IDS:raise ValueError('unreviewed_configmap_criterion')
        field,title,positive,negative=SPECS[check_id[len(PREFIX_ID):]]
        good=_indicator(item,index,field)
        return ('PASS' if good else 'FAIL'),{'observed':(positive if good else negative)+' '+LIMIT,
            'scope':'native_named_configmap_declaration_only','field':field,'raw_content_retained':False}
    except (KeyError,TypeError,ValueError,AttributeError,IndexError):
        return 'UNKNOWN',{'observed':'The explicit field, bounded YAML projection, native identity or complete authenticated inventory could not be bound. '+LIMIT,
                          'scope':'native_named_configmap_declaration_only','raw_content_retained':False}


def evaluate_empty(context, collection):
    return 'UNKNOWN',{'observed':'No matching kubelet-config ConfigMap declaration was collected in this scope. Node configuration was not assessed.'}


def evaluate_for(check_id):
    if check_id not in IDS:raise ValueError('unreviewed_configmap_criterion')
    def evaluate_selected(item,index):return evaluate(check_id,item,index)
    evaluate_selected.evaluate_empty_inventory=evaluate_empty
    return evaluate_selected


DECLARATIONS=[{'id':cid,'provider':'k8s','category':'hardening','kind':KIND,'severity':'medium',
    'title':SPECS[cid[len(PREFIX_ID):]][1],'dependencies':[KIND],'registered':False,
    'framework_mappings':[],'control':'','existing_ui_group':('Permissions & IAM' if cid.endswith('authorization_webhook') else
        'Authentication' if cid.endswith(('client_ca_configured','anonymous_disabled')) else
        'Network & exposure' if cid.endswith('readonly_disabled') else
        'Keys & certificates' if cid.endswith(('client_certificate_rotation','tls_file_pair_configured')) else
        'Encryption' if cid.endswith('explicit_cipher_allowlist') else 'Logging'),
    'description':'Inspects an explicit whitelisted field in a native kubelet-config ConfigMap declaration. '+LIMIT,
    'remediation':'Review the intended kubelet configuration and node deployment process; this check does not establish which nodes consume the ConfigMap.'}for cid in IDS]
