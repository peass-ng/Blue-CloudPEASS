"""Cache-only candidate: accepted high-risk DaemonSet template, no runtime claim."""
from __future__ import annotations
from collections.abc import Mapping
import re
from urllib.parse import parse_qsl, urlsplit
from peaso.attack_detection.kubernetes_pod_next import _host_root_mount, _time, _SYSTEM_NAMESPACES
from peaso.attack_detection.gke_scope import project_scope, successful_status


_DNS_LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z")


def _from_gke(row):
    payload, resource = row.get('protoPayload'), row.get('resource')
    labels = resource.get('labels') if isinstance(resource, Mapping) else None
    scope = project_scope(row.get('logName'), labels)
    if (not isinstance(payload, Mapping) or payload.get('@type') != 'type.googleapis.com/google.cloud.audit.AuditLog'
            or payload.get('serviceName') != 'k8s.io'
            or payload.get('methodName') != 'io.k8s.apps.v1.daemonsets.create'
            or not isinstance(resource, Mapping) or resource.get('type') != 'k8s_cluster'
            or scope is None or not successful_status(payload)
            or ('labels' in row and not isinstance(row['labels'], Mapping))
            or isinstance(row.get('labels'), Mapping) and 'command.gke.io/dryRun' in row['labels']):
        return None
    request = payload.get('request')
    if not isinstance(request, Mapping):
        return None
    if 'dryRun' in request:
        return None
    response, auth = payload.get('response'), payload.get('authenticationInfo')
    if (not isinstance(response, Mapping) or not isinstance(auth, Mapping)
            or not isinstance(labels, Mapping)
            or not isinstance(labels.get('location'), str) or not _DNS_LABEL.fullmatch(labels['location'])
            or not isinstance(labels.get('cluster_name'), str) or not _DNS_LABEL.fullmatch(labels['cluster_name'])):
        return None
    meta = response.get('metadata')
    meta = meta if isinstance(meta, Mapping) else {}
    request_meta = request.get('metadata') if isinstance(request, Mapping) else None
    if request_meta is not None and (not isinstance(request_meta, Mapping)
            or request_meta.get('name') not in (None, meta.get('name'))
            or request_meta.get('namespace') not in (None, meta.get('namespace'))):
        return None
    cluster = scope + '/locations/' + labels['location'] + '/clusters/' + labels['cluster_name']
    return {'apiVersion':'audit.k8s.io/v1', 'kind':'Event', 'stage':'ResponseComplete',
            'verb':'create', 'auditID':row.get('insertId'), 'stageTimestamp':row.get('timestamp'),
            'cluster_id':cluster, 'user':{'username':auth.get('principalEmail')},
            'objectRef':{'apiGroup':'apps','resource':'daemonsets','name':meta.get('name'),'namespace':meta.get('namespace')},
            'responseStatus':{'code':201,'status':'Success'}, 'responseObject':response}


def normalize_kubernetes_privileged_daemonset(row):
    if not isinstance(row, Mapping):
        return None
    from_gke = 'protoPayload' in row
    if from_gke:
        row = _from_gke(row)
        if row is None:
            return None
    if (row.get('apiVersion') != 'audit.k8s.io/v1' or row.get('kind') != 'Event'
            or row.get('stage') != 'ResponseComplete' or row.get('verb') != 'create'):
        return None
    uri = row.get('requestURI')
    if not from_gke and (not isinstance(uri, str) or not uri):
        return None
    try:
        parsed_uri = urlsplit(uri) if isinstance(uri, str) else None
    except ValueError:
        return None
    if parsed_uri is not None and any(k.lower() == 'dryrun' for k,_ in parse_qsl(parsed_uri.query, keep_blank_values=True)):
        return None
    ref, status, response, user = [row.get(k) for k in ('objectRef','responseStatus','responseObject','user')]
    if (not isinstance(ref, Mapping) or ref.get('apiGroup') != 'apps' or ref.get('resource') != 'daemonsets'
            or ref.get('subresource') not in (None,'')
            or not isinstance(status, Mapping) or type(status.get('code')) is not int or status['code'] != 201
            or status.get('status') != 'Success' or not isinstance(response, Mapping)
            or response.get('apiVersion') != 'apps/v1' or response.get('kind') != 'DaemonSet'
            or not isinstance(user, Mapping)):
        return None
    actor, eid, cluster, when = user.get('username'), row.get('auditID'), row.get('cluster_id'), row.get('stageTimestamp')
    if (not isinstance(actor, str) or not actor or actor.startswith('system:')
            or not isinstance(eid, str) or not eid or not isinstance(cluster, str) or not cluster or _time(when) is None):
        return None
    meta, spec = response.get('metadata'), response.get('spec')
    if not isinstance(meta, Mapping) or not isinstance(spec, Mapping):
        return None
    name, namespace, uid = meta.get('name'), meta.get('namespace'), meta.get('uid')
    if (not isinstance(name, str) or not name or not isinstance(namespace, str) or not namespace
            or namespace in _SYSTEM_NAMESPACES or not isinstance(uid, str) or not uid
            or ref.get('name') not in (None,name) or ref.get('namespace') != namespace):
        return None
    if parsed_uri is not None and parsed_uri.path != f'/apis/apps/v1/namespaces/{namespace}/daemonsets':
        return None
    selector, template = spec.get('selector'), spec.get('template')
    if not isinstance(selector, Mapping) or not isinstance(template, Mapping):
        return None
    match_labels = selector.get('matchLabels')
    match_expressions = selector.get('matchExpressions')
    template_meta, template_spec = template.get('metadata'), template.get('spec')
    if (not isinstance(match_labels, Mapping) or not match_labels
            or match_expressions not in (None, [])
            or any(not isinstance(k, str) or not k or not isinstance(v, str) or not v
                   for k, v in match_labels.items())
            or not isinstance(template_meta, Mapping) or not isinstance(template_meta.get('labels'), Mapping)
            or template_meta.get('namespace') not in (None, namespace)
            or any(template_meta['labels'].get(k) != v for k,v in match_labels.items())
            or not isinstance(template_spec, Mapping) or template_spec.get('hostPID') is not True):
        return None
    os = template_spec.get('os')
    if isinstance(os, Mapping) and os.get('name') == 'windows':
        return None
    mount = _host_root_mount(template_spec)
    if mount is None:
        return None
    container, path = mount
    return {'cloud.provider':'kubernetes','event.source':'kubernetes.audit','event.name':'create',
            'event.outcome':'success','event.id':eid,'event.time':when,'account.id':cluster,
            'actor.id':actor,'target.id':f'{namespace}/{name}','target.namespace':namespace,
            'target.container':container,'target.host_mount_path':path,
            'daemonset.privileged_host_root_spec_accepted':True,'daemonset.change_effect':'admitted_spec'}
