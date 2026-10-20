"""Pure unregistered declaration: exact versioned Azure stored-source literals."""
from copy import deepcopy
import re
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors.azure_selected_storage_secret_indicators import (
    KIND,CHECK,MARKER,SCHEMA,SCOPE,GUID,ARM_VERSION,SUB_VERSION,DATA_VERSION,MAX_TARGETS,MAX_CALLS,
    MAX_ARM,MAX_OBJECT,MAX_MEMBER,MAX_EXPANDED,MAX_MEMBERS,MAX_LEAKS,MAX_LOCATIONS)

DECLARATIONS=[{'id':CHECK,'provider':'azure','category':'exposure','kind':KIND,'finding_type':'secrets','severity':'high',
 'requirements':[],'dependencies':[KIND],'allow_incomplete_failure':True,'ui_group':'Secrets',
 'title':'Selected Azure stored source objects have no detected secrets',
 'remediation':'Remove exposed literals from the selected stored source and rotate confirmed exposed credentials. Use managed identities or supported secret references.',
 'scope':'Exact selected coherent current Blob/File objects or optional native Blob versions/File share snapshots. No SCM downloads, deployment/runtime identity, execution, credential validation or referenced-content proof.'}]


def evaluate(item,index):
    try:
        ctx=index['context'];scope=ctx['scope'];meta=ctx['metadata']
        if ctx['provider']!='azure' or not SCOPE.fullmatch(scope) or meta[KIND+'_authorized'] is not True or meta['context_binding']!='scan_local':raise ValueError()
        selected=meta[KIND+'_selection'][scope];capture=meta[KIND+'_capture']
        if (not isinstance(selected,list) or not 1<=len(selected)<=MAX_TARGETS or len(set(selected))!=len(selected)
                or any(not isinstance(i,str) or not re.fullmatch(KIND+':[0-9a-f]{64}',i) for i in selected)
                or not isinstance(capture,str) or not re.fullmatch('storage-source-capture:[0-9a-f]{32}',capture)):raise ValueError()
        own,=[c for c in index['collections'][KIND] if c.get('scope')==scope]
        ids=[r['id'] for r in own['items']]
        if (own['status'] not in ('collected','partial') or own.get('service')!='Microsoft.Storage' or len(set(ids))!=len(ids)
                or any(i not in selected for i in ids) or sum(r==item for r in own['items'])!=1):raise ValueError()
        for obj in (item,own):
            if any(not isinstance(meta.get(k),str) or not meta[k] or obj['_provenance'].get(k)!=meta[k]
                   for k in ('credential_context_id','customer_context_id')):raise ValueError()
        ident=item['id'];m=item[MARKER]
        if meta[KIND+'_targets'][ident]!={k:m[k] for k in ('service','format','selection_mode')}:raise ValueError()
        if (set(m)!={'schema','identity','scope','capture','service','format','selection_mode','tenant','principal','native_complete','complete','reason','verification',
                     'object_bytes','expanded_bytes','members','parts','leaks','source_requests','version_locator','etag_locator','file_locator'}
                or m['schema']!=SCHEMA or m['identity']!=ident or ident not in selected or m['scope'].casefold()!=scope.casefold()
                or m['capture']!=capture or m['service'] not in ('blob','file') or m['format'] not in ('text','zip','tar','tar.gz') or m['selection_mode'] not in ('current','versioned')
                or m['native_complete'] is not True or type(m['complete']) is not bool or m['reason'] not in ('complete','incomplete')
                or m['verification']!='not_attempted' or item['_provenance']['scope'].casefold()!=scope.casefold() or item['_provenance']['capture']!=capture
                or not isinstance(m['tenant'],str) or not re.fullmatch(GUID,m['tenant'],re.I) or str(meta.get('tenant_id','')).casefold()!=m['tenant'].casefold()
                or meta.get('tenant_verified') is not True or not isinstance(m['principal'],str) or not re.fullmatch('storage-source-principal:[0-9a-f]{64}',m['principal'])):raise ValueError()
        for key,label in [('version_locator','version'),('etag_locator','etag')]:
            if not isinstance(m[key],str) or not re.fullmatch('storage-source-'+label+':[0-9a-f]{64}',m[key]):raise ValueError()
        if m['service']=='blob':
            if m['file_locator'] is not None:raise ValueError()
        elif not isinstance(m['file_locator'],str) or not re.fullmatch('storage-source-file:[0-9a-f]{64}',m['file_locator']):raise ValueError()
        if (type(m['object_bytes']) is not int or not 1<=m['object_bytes']<=MAX_OBJECT
                or type(m['expanded_bytes']) is not int or not 0<=m['expanded_bytes']<=MAX_EXPANDED
                or type(m['members']) is not int or not 0<=m['members']<=MAX_MEMBERS):raise ValueError()
        refs=m['source_requests'];ledger=meta[KIND+'_receipts']
        operations=('subscription','account','properties_before','content','properties_after')
        if (not isinstance(refs,list) or len(refs)!=5 or len(set(refs))!=5 or item['_provenance']['source_requests']!=refs
                or not isinstance(ledger,list) or not 5<=len(ledger)<=MAX_CALLS or len({r['id'] for r in ledger})!=len(ledger)):raise ValueError()
        for ref,operation in zip(refs,operations):
            r,=[r for r in ledger if r.get('id')==ref]
            if (set(r)!={'id','identity','scope','capture','operation','method','origin','request','status','http_status','bytes','tenant','principal','bound','native_request','version'}
                    or not re.fullmatch('storage-source-read:[0-9a-f]{32}',ref) or r['identity']!=ident or r['scope'].casefold()!=scope.casefold()
                    or r['capture']!=capture or r['operation']!=operation or r['method']!=('HEAD' if operation.startswith('properties_') else 'GET')
                    or r['origin']!=('arm' if operation in ('subscription','account') else m['service'])
                    or r['version']!=(SUB_VERSION if operation=='subscription' else ARM_VERSION if operation=='account' else DATA_VERSION)
                    or not re.fullmatch('storage-source-request:[0-9a-f]{64}',r['request'])
                    or not isinstance(r['native_request'],str) or not re.fullmatch('storage-source-response:[0-9a-f]{64}',r['native_request'])
                    or r['status']!='collected' or type(r['http_status']) is not int or r['http_status']!=200 or r['bound'] is not True
                    or r['tenant']!=m['tenant'] or r['principal']!=m['principal'] or type(r['bytes']) is not int
                    or (r['bytes']!=0 if operation.startswith('properties_') else not 1<=r['bytes']<=(MAX_ARM if r['origin']=='arm' else MAX_OBJECT))):raise ValueError()
        parts=m['parts'];versions={'kingfisher':KINGFISHER_VERSION,'trufflehog':TRUFFLEHOG_VERSION};by_path={}
        if not isinstance(parts,list) or not 1<=len(parts)<=MAX_MEMBERS:raise ValueError()
        for number,part in enumerate(parts,1):
            if (set(part)!={'path','bytes','complete','engines','leaks'} or part['path']!=ident+'.file-'+str(number) or type(part['bytes']) is not int
                    or not 1<=part['bytes']<=MAX_MEMBER or type(part['complete']) is not bool):raise ValueError()
            engines=part['engines']
            if (not isinstance(engines,list) or len(engines)!=2 or {e['engine'] for e in engines}!=set(versions)
                    or any(set(e)!={'engine','version','status'} or e['version']!=versions[e['engine']] or e['status'] not in ('complete','unavailable') for e in engines)
                    or part['complete']!=all(e['status']=='complete' for e in engines)):raise ValueError()
            by_path[part['path']]={e['engine'] for e in engines if e['status']=='complete'}
            if (not isinstance(part['leaks'],list) or merge_leaks(part['leaks'])!=part['leaks'] or
                    any(not leak['detectors'] or not leak['locations'] or any(d['engine'] not in by_path[part['path']] for d in leak['detectors'])
                        or any(loc!={'path':part['path']} for loc in leak['locations']) for leak in part['leaks'])):raise ValueError()
        leaks=m['leaks']
        if (not isinstance(leaks,list) or merge_leaks(leaks)!=leaks or len(leaks)>MAX_LEAKS or sum(len(l['locations']) for l in leaks)>MAX_LOCATIONS
                or merge_leaks([leak for part in parts for leak in part['leaks']])!=leaks):raise ValueError()
        complete=(m['complete'] is True and m['reason']=='complete' and all(p['complete'] for p in parts)
                  and own['status']=='collected' and set(ids)==set(selected) and meta[KIND+'_redaction_complete'] is True
                  and type(m['expanded_bytes']) is int and 1<=m['expanded_bytes']<=MAX_EXPANDED
                  and type(m['members']) is int and len(parts)<=m['members']<=MAX_MEMBERS)
        if m['format']=='text' and (len(parts)!=1 or m['object_bytes']!=parts[0]['bytes']):raise ValueError()
        if not leaks and not complete:raise ValueError()
        observed=('A likely secret was detected in the selected stored source. Its value is hidden; offline detection did not validate it.' if leaks else
                  'Both offline detectors completed without detecting a supported secret in the selected stored source object. Coverage is limited to the captured supported text files.')
        if not complete:observed+=' Coverage is incomplete.'
        return ('FAIL' if leaks else 'PASS'),{'observed':observed,'secret_leaks':deepcopy(leaks),'complete':bool(complete),'credential_validation':'not_attempted',
            'coverage':'selected_captured_stored_source_only' if complete else 'incomplete_selected_stored_source','service':m['service'],'format':m['format'],'selection_mode':m['selection_mode'],'parts':deepcopy(parts)}
    except (KeyError,TypeError,ValueError,AttributeError,IndexError):
        return 'UNKNOWN',{'complete':False,'observed':'Selected stored source content was unavailable, unbound, unsupported or incompletely inspected. A clean result cannot be established.'}


def install(register):
    """Explicit only; importing this module changes no registry or historical cases."""
    from . import CHECKS
    if any(c.id==CHECK for c in CHECKS):return
    d=DECLARATIONS[0]
    register(CHECK,'azure','exposure',KIND,d['title'],'high','security_configuration',d['remediation'],dependencies=[KIND],allow_incomplete_failure=True)(evaluate)
