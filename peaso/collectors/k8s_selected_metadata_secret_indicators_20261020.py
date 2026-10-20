"""Unregistered selected metadata reader; reuse immutable bounded native GETs.

Each copied function has private globals. The installed literal reader, its
authorization namespace and its extraction behavior are never modified.
"""
from copy import deepcopy
import re
from types import FunctionType
from . import k8s_literal_secret_indicators as predecessor
from .k8s_selected_log_sample_secret_indicators import private_native_logs, _wire_debug_enabled

KIND='k8s_selected_metadata'
CHECK='k8s.review.selected_metadata.secret_indicators'
OPTION='selected_k8s_metadata_resources'
MARKER='SelectedKubernetesMetadataSecretIndicators'
SCHEMA='k8s-selected-metadata-secrets-v1'
NATIVE_KINDS=deepcopy(predecessor.NATIVE_KINDS)
Incomplete=predecessor.Incomplete
MAX_CONTENT=predecessor.MAX_CONTENT
MAX_VALUE=predecessor.MAX_VALUE
MAX_LITERALS=predecessor.MAX_LITERALS
_NAME=re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?\Z')
_DNS=re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')


def _key(value):
    if not isinstance(value,str)or value.count('/')>1:return False
    pieces=value.split('/')
    if not _NAME.fullmatch(pieces[-1]):return False
    return len(pieces)==1 or(len(pieces[0])<=253 and all(_DNS.fullmatch(x)for x in pieces[0].split('.')))


def _extract(document,target):
    meta=document.get('metadata')
    if(document.get('apiVersion')!=NATIVE_KINDS[target['kind']][0]or document.get('kind')!=target['kind']
            or any(k in document for k in('continue','nextLink','items','partial','_partial','hasMore','continuationToken','remainingItemCount','_coverage'))
            or not isinstance(meta,dict)or any(k in meta for k in('continue','remainingItemCount','_partial','_coverage'))
            or meta.get('name')!=target['name']or meta.get('namespace')!=target['namespace']or meta.get('deletionTimestamp')is not None
            or any(not isinstance(meta.get(k),str)or not 1<=len(meta[k])<=253
                or any(ord(c)<33 or ord(c)>126 for c in meta[k])for k in('uid','resourceVersion'))):
        raise Incomplete('native_identity_unresolved')
    values=[target['cluster_id'],meta['namespace'],meta['name'],meta['uid'],meta['resourceVersion']]
    count=0
    for field in('labels','annotations'):
        mapping=meta.get(field,{})
        if not isinstance(mapping,dict):raise Incomplete('malformed_metadata_map')
        for key,value in sorted(mapping.items(),key=lambda entry:str(entry[0])):
            if(not _key(key)or not isinstance(value,str)or '\x00'in value
                    or len(value.encode('utf-8'))>MAX_VALUE
                    or(field=='labels'and value!=''and not _NAME.fullmatch(value))):
                raise Incomplete('unsupported_metadata_literal')
            count+=1
            if count>MAX_LITERALS:raise Incomplete('metadata_count_limit')
            values.extend((key,value))
    if not count:raise Incomplete('no_selected_metadata_entries')
    payload='\n'.join(values).encode('utf-8')
    if len(payload)>MAX_CONTENT:raise Incomplete('metadata_byte_limit')
    return payload,meta['uid'],meta['resourceVersion'],count,0


_GLOBALS={**vars(predecessor),'__name__':__name__,'KIND':KIND,'CHECK':CHECK,'OPTION':OPTION,
          'MARKER':MARKER,'SCHEMA':SCHEMA,'NATIVE_KINDS':NATIVE_KINDS,'_extract':_extract}
_REUSED=('enabled','selected_targets','identity','_path','_remaining','_pairs','_read','collect')
for _name in _REUSED:
    _original=getattr(predecessor,_name)
    _GLOBALS[_name]=FunctionType(_original.__code__,_GLOBALS,_name,_original.__defaults__,_original.__closure__)
_NATIVE_READ=_GLOBALS['_read']


def _read(reader,api,target,state):
    client=getattr(getattr(api,'api',api),'api_client',None)
    pool=getattr(getattr(client,'rest_client',None),'pool_manager',None)
    # Log filters cannot intercept http.client's direct wire-debug printing.
    # Inspect the already-configured manager before each credentialed read.
    if _wire_debug_enabled(getattr(pool,'pool',None)):
        raise Incomplete('native_wire_debug_enabled')
    return _NATIVE_READ(reader,api,target,state)


_GLOBALS['_read']=_read
enabled=_GLOBALS['enabled']
selected_targets=_GLOBALS['selected_targets']
identity=_GLOBALS['identity']
_path=_GLOBALS['_path']


def collect(reader,api,options,scopes,cluster):
    """Sensitive reads only in the new namespace; no installed hooks or auth discovery."""
    if enabled(options):
        with private_native_logs():return _GLOBALS['collect'](reader,api,options,scopes,cluster)
    return _GLOBALS['collect'](reader,api,options,scopes,cluster)


def redact_output(scopes,collections,metadata,matches):
    return predecessor.redact_output(scopes,collections,metadata,matches)
