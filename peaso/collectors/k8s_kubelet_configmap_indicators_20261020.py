"""Bounded kubelet ConfigMap declarations; no node or file access.

Unregistered proposal. Only native metadata discovery followed by exact ConfigMap GETs may call pages;
raw data, annotations and paths never leave this projection.
"""
import json
import re
import time
from urllib.parse import quote

import yaml

from .k8s_annotation_indicators_20261020 import digest, CONTEXT, SCHEMA as CONTEXT_SCHEMA

KIND = 'kubelet_configmap_declaration'
MARKER = '_kubelet_configmap_declaration_20261020'
SCHEMA = 'k8s-kubelet-configmap-declaration/v1'
PREFIX = 'kubelet-config'
MAX_YAML_BYTES = 65536
MAX_TOKENS = 4096
MAX_DEPTH = 12
MAX_PAGE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_PAGES = 8
MAX_TARGETS = 16
MAX_SECONDS = 30
FIELDS = ('authorization_mode', 'client_ca_configured', 'anonymous_disabled', 'readonly_disabled',
          'client_rotation', 'cipher_allowlist', 'tls_files_configured', 'event_qps_bounded')
CIPHERS = frozenset(('TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    'TLS_RSA_WITH_AES_256_GCM_SHA384', 'TLS_RSA_WITH_AES_128_GCM_SHA256'))
KNOWN_OTHER_CIPHERS = frozenset(('TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_RC4_128_SHA',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
    'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA'))


class _DistinctLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if type(key) is not str or key in result:
                raise ValueError('kubelet_yaml_duplicate_or_nonstr_key')
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def parse_yaml(text):
    """Three bounded parser passes, no aliases, tags, directives or recursion."""
    if not isinstance(text, str) or not text or len(text.encode()) > MAX_YAML_BYTES:
        raise ValueError('kubelet_yaml_size_or_missing')
    for number, token in enumerate(yaml.scan(text), 1):
        if number > MAX_TOKENS or isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken,
                yaml.tokens.TagToken, yaml.tokens.DirectiveToken)):
            raise ValueError('kubelet_yaml_token_budget_or_reference')
    depth = documents = 0
    for event in yaml.parse(text):
        if isinstance(event, yaml.events.DocumentStartEvent):
            documents += 1
            if documents > 1: raise ValueError('kubelet_yaml_multiple_documents')
        if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
            depth += 1
            if depth > MAX_DEPTH: raise ValueError('kubelet_yaml_depth')
        if isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)): depth -= 1
        if getattr(event, 'tag', None) is not None:
            raise ValueError('kubelet_yaml_custom_type')
    result = yaml.load(text, Loader=_DistinctLoader)
    if not isinstance(result, dict) or result.get('apiVersion') != 'kubelet.config.k8s.io/v1beta1' or result.get('kind') != 'KubeletConfiguration':
        raise ValueError('kubelet_yaml_schema')
    # Implicit timestamp/binary/set objects are never accepted as YAML facts.
    def types_ok(value):
        if isinstance(value, dict):return all(type(k) is str and types_ok(v) for k,v in value.items())
        if isinstance(value, list):return all(types_ok(v) for v in value)
        return value is None or type(value) in (str, bool, int, float)
    if not types_ok(result):raise ValueError('kubelet_yaml_unknown_type')
    return result


def _path(config, *keys):
    value = config
    for key in keys:
        if not isinstance(value, dict):raise ValueError('kubelet_field_type')
        if key not in value:raise KeyError(key)
        value = value[key]
    return value


def _bool(value):
    if type(value) is not bool:raise ValueError('kubelet_boolean_required')
    return value


def _file(value):
    # Test only explicit nonempty path declaration, never retain or read it.
    if type(value) is not str or len(value) > 4096 or any(ord(c) < 32 for c in value):
        raise ValueError('kubelet_path_type')
    return bool(value.strip())


def project(data):
    """Whitelisted safe indicators only; omitted fields never get defaults."""
    missing = {name:{'status':'missing'} for name in FIELDS}
    try:
        if not isinstance(data, dict) or 'kubelet' not in data:return missing
        config = parse_yaml(data['kubelet'])
    except (ValueError, TypeError, UnicodeError, yaml.YAMLError, RecursionError):
        return {name:{'status':'unavailable'} for name in FIELDS}
    def indicator(name, reader):
        try: missing[name] = {'status':'observed', 'value':reader()}
        except KeyError:pass
        except (TypeError, ValueError):missing[name] = {'status':'unavailable'}
    def mode():
        value = _path(config, 'authorization', 'mode')
        if value not in ('Webhook', 'AlwaysAllow') or type(value) is not str:raise ValueError('kubelet_authorization_enum')
        return value
    def port():
        value = _path(config, 'readOnlyPort')
        if type(value) is not int or not 0 <= value <= 65535:raise ValueError('kubelet_port_type')
        return value == 0
    def qps():
        value = _path(config, 'eventRecordQPS')
        if type(value) is not int or not 0 <= value <= 2147483647:raise ValueError('kubelet_qps_type')
        return value > 0
    def ciphers():
        value = _path(config, 'tlsCipherSuites')
        if (not isinstance(value, list) or not 1 <= len(value) <= 64 or any(type(v) is not str for v in value)
                or len(set(value)) != len(value) or not set(value) <= CIPHERS | KNOWN_OTHER_CIPHERS | {'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256','TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'}):
            raise ValueError('kubelet_cipher_list_or_enum')
        aliases = {'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256':'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305',
                   'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256':'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305'}
        return {aliases.get(v,v) for v in value} <= CIPHERS
    indicator('authorization_mode', mode)
    indicator('client_ca_configured', lambda:_file(_path(config, 'authentication', 'x509', 'clientCAFile')))
    indicator('anonymous_disabled', lambda:not _bool(_path(config, 'authentication', 'anonymous', 'enabled')))
    indicator('readonly_disabled', port)
    indicator('client_rotation', lambda:_bool(_path(config, 'rotateCertificates')))
    indicator('cipher_allowlist', ciphers)
    def files():
        # Both reads must occur, even if the first explicitly declares empty.
        cert, key = _file(_path(config, 'tlsCertFile')), _file(_path(config, 'tlsPrivateKeyFile'))
        return cert and key
    indicator('tls_files_configured', files)
    indicator('event_qps_bounded', qps)
    return missing


def identity(row):
    meta = row.get('metadata')
    if not isinstance(meta, dict):raise ValueError('configmap_identity_missing')
    ns, name, uid, rv = [meta.get(k) for k in ('namespace','name','uid','resourceVersion')]
    dns = r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?'
    if (not isinstance(ns, str) or len(ns)>63 or re.fullmatch(dns, ns) is None
            or not isinstance(name, str) or len(name)>253 or any(len(label)>63 or re.fullmatch(dns,label) is None for label in name.split('.'))
            or not isinstance(uid, str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', uid) is None
            or not isinstance(rv, str) or re.fullmatch(r'[A-Za-z0-9._~:+/=-]{1,128}', rv) is None):
        raise ValueError('configmap_identity_malformed')
    if row.get('apiVersion','v1') != 'v1' or row.get('kind','ConfigMap') != 'ConfigMap':
        raise ValueError('configmap_type_conflict')
    return ['v1','ConfigMap',ns,name,uid,rv]


def _reject_json_constant(value):
    raise ValueError('configmap_nonfinite_json')


def _json_pairs(pairs):
    result = {}
    for key,value in pairs:
        if key in result:raise ValueError('configmap_duplicate_json_field')
        result[key]=value
    return result


def pages(reader, api, path, kind, cluster, scope, namespaced, context, native):
    """Metadata-only discovery, then bounded exact native GETs for the prefix."""
    from .k8s import K8sReadError
    expected = '/api/v1/' + ('' if scope == '*' else 'namespaces/'+quote(scope,safe='')+'/') + 'configmaps'
    if kind != KIND or not namespaced or path != expected:raise ValueError('configmap_request_scope_conflict')
    deadline = time.monotonic()+MAX_SECONDS
    seen_names, seen_uids, tokens = set(), set(), set()
    continuation = None; resource_version = None; total = targets = 0
    def read(target, params, metadata_only):
        nonlocal total
        reader.check_cancelled()
        if time.monotonic() >= deadline:raise K8sReadError('configmap_deadline')
        accept = 'application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1' if metadata_only else 'application/json'
        response = api.api_client.call_api(target, 'GET', query_params=list(params.items()),
            header_params={'Accept':accept}, auth_settings=['BearerToken'],
            _preload_content=False, _return_http_data_only=True, _request_timeout=min(30,max(.001,deadline-time.monotonic())))
        try:
            content_type=response.headers.get('Content-Type','').lower()
            if (response.status != 200 or content_type.split(';',1)[0].strip() != 'application/json'
                    or not metadata_only and 'as=' in content_type):
                raise ValueError('configmap_http_representation_incomplete')
            chunks=[]; size=0
            while True:
                reader.check_cancelled()
                if time.monotonic() >= deadline:raise K8sReadError('configmap_deadline')
                chunk=response.read(16384)
                if not chunk:break
                if not isinstance(chunk,bytes):raise ValueError('configmap_http_body_type')
                size+=len(chunk)
                if size > MAX_PAGE_BYTES or total+size > MAX_TOTAL_BYTES:raise K8sReadError('configmap_byte_budget')
                chunks.append(chunk)
            total+=size
            return json.loads(b''.join(chunks), object_pairs_hook=_json_pairs, parse_constant=_reject_json_constant)
        finally:
            response.close();response.release_conn();api.api_client.last_response=None
    for page_number in range(MAX_PAGES):
        params = {'limit':reader.page_size}
        if continuation:params['continue']=continuation
        document = reader.call(read,path,params,True)
        if (not isinstance(document,dict) or document.get('apiVersion')!='meta.k8s.io/v1'
                or document.get('kind')!='PartialObjectMetadataList' or not isinstance(document.get('items'),list)
                or not isinstance(document.get('metadata'),dict)):
            raise ValueError('configmap_metadata_list_type_or_shape')
        meta=document['metadata'];rv=meta.get('resourceVersion')
        if not isinstance(rv,str) or re.fullmatch('[A-Za-z0-9._~:+/=-]{1,128}',rv) is None or resource_version is not None and resource_version!=rv:
            raise ValueError('configmap_list_version_conflict')
        resource_version=rv
        for discovered in document['items']:
            if (not isinstance(discovered,dict) or discovered.get('apiVersion','meta.k8s.io/v1')!='meta.k8s.io/v1'
                    or discovered.get('kind','PartialObjectMetadata')!='PartialObjectMetadata'
                    or any(k in discovered for k in ('data','binaryData','spec'))):raise ValueError('configmap_metadata_representation')
            values=identity({**discovered,'apiVersion':'v1','kind':'ConfigMap'});version,typ,ns,name,uid,rv=values
            if scope!='*' and ns!=scope:raise ValueError('configmap_foreign_namespace')
            if (ns,name) in seen_names or uid in seen_uids:raise ValueError('configmap_duplicate_identity')
            seen_names.add((ns,name));seen_uids.add(uid)
            if not name.startswith(PREFIX):continue
            targets+=1
            if targets>MAX_TARGETS:raise K8sReadError('configmap_target_budget')
            detail_path='/api/v1/namespaces/'+quote(ns,safe='')+'/configmaps/'+quote(name,safe='')
            row=reader.call(read,detail_path,{},False)
            if (not isinstance(row,dict) or row.get('apiVersion')!='v1' or row.get('kind')!='ConfigMap'
                    or identity(row)!=values):raise ValueError('configmap_detail_identity_conflict')
            if any(k in row for k in (MARKER,'id','provenance','_coverage')):raise ValueError('configmap_reserved_provider_field')
            safe={'apiVersion':version,'kind':typ,'metadata':dict(zip(('namespace','name','uid','resourceVersion'),values[2:]))}
            result=native(safe,kind,cluster,scope,True)
            result['provenance']['evidence']='read-only GET after metadata list'
            result[MARKER]={'schema':SCHEMA,'identity_digest':digest(values),'indicators':project(row.get('data')),
                'source':{'method':'GET','path':detail_path,'scope':scope,'context_digest':digest(context),
                    'native_id':result['id'],'discovery_path':path,'list_resource_version':resource_version,
                    'discovery_type':'meta.k8s.io/v1/PartialObjectMetadataList'}}
            yield [result]
        continuation=meta.get('continue')
        if continuation in (None,''):return
        if not isinstance(continuation,str) or len(continuation)>4096 or continuation in tokens:raise ValueError('configmap_continuation_conflict')
        tokens.add(continuation)
        if reader.budget.max_pages is not None and page_number+1>=reader.budget.max_pages:raise K8sReadError('page_limit')
    raise K8sReadError('configmap_page_budget')
