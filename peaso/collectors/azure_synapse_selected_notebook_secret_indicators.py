"""Bounded, exact selected Synapse published notebook source reads."""
from peaso.secret_evidence import scan_with_source, target_source
from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint
from .azure_selected_declaration_secret_indicators import GUID, SCOPE, SEG, ARM, _pairs, _bound
from .azure_selected_secret_integration_20261020 import remember
from copy import deepcopy
import base64, hashlib, http.client, json, re, time
from uuid import uuid4

KIND='azure_synapse_selected_notebook_source'
CHECK='azure.review.synapse.selected_notebook_source_secret_indicators'
OPTION='selected_azure_synapse_notebooks'
SERVICE='Microsoft.Synapse'
MARKER='SelectedSynapseNotebookSecretIndicators'
SCHEMA='azure-selected-synapse-notebook-source-v1'
ARM_API='2021-06-01'; DATA_API='2020-12-01'; SYNAPSE='https://dev.azuresynapse.net'
MAX_TARGETS=4;MAX_CALLS=20;MAX_WIRE=2*1024*1024;MAX_TOTAL=8*1024*1024;MAX_CONTENT=1024*1024;MAX_SECONDS=120;MAX_CELLS=128;MAX_LEAKS=256;MAX_LOCATIONS=512
WORKSPACE=re.compile(r'(/subscriptions/'+GUID+r')/resourceGroups/'+SEG+r'/providers/Microsoft\.Synapse/workspaces/([A-Za-z0-9][A-Za-z0-9-]{0,49})\Z',re.I)
NAME=re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z')

def enabled(options):
    return options.get('content_secret_scans')is True and isinstance(options.get('_content_secret_scan_kinds'),list)and KIND in options['_content_secret_scan_kinds']

def parse(target):
    if not isinstance(target,dict)or set(target)!={'workspace_resource_id','notebook_name'}:raise ValueError('invalid_selection')
    rid=target['workspace_resource_id'];name=target['notebook_name']
    m=WORKSPACE.fullmatch(rid)if isinstance(rid,str)and len(rid)<=1024 else None
    if not m or any(x in('.','..')for x in rid.split('/'))or not isinstance(name,str)or not NAME.fullmatch(name)or name in('.','..'):raise ValueError('invalid_selection')
    return m[1],rid,m[2],name

def identity(target):
    _,rid,_,name=parse(target)
    # Stable non-secret selected resource identifier; HMAC is reserved for private evidence.
    return KIND+':'+hashlib.sha256((rid.casefold()+'\n'+name).encode()).hexdigest()

def selected_targets(options,scopes):
    if not isinstance(options,dict)or 'content_secret_scans'in options and type(options['content_secret_scans'])is not bool:raise ValueError('invalid_selection')
    if OPTION not in options and not enabled(options):return []
    targets=options.get(OPTION)
    if (not isinstance(scopes,list)or not 1<=len(scopes)<=8 or any(not isinstance(s,str)or not SCOPE.fullmatch(s)for s in scopes)
            or len({s.casefold()for s in scopes})!=len(scopes)or not isinstance(targets,list)or not 1<=len(targets)<=MAX_TARGETS):raise ValueError('invalid_selection')
    seen=set()
    for target in targets:
        scope,_,_,_=parse(target);ident=identity(target)
        if scope.casefold()not in{s.casefold()for s in scopes}or ident in seen:raise ValueError('invalid_selection')
        seen.add(ident)
    return deepcopy(targets)

def remaining(reader,state):
    reader.check_cancelled();left=state['deadline']-time.monotonic()
    if left<=0:raise ValueError('deadline')
    return min(10,left)

def principal(token,audience,transport,state):
    if not isinstance(token,str)or not 16<=len(token)<=32768 or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',token):raise ValueError('credential_unbound')
    claims=json.loads(base64.urlsafe_b64decode(token.split('.')[1]+'='*(-len(token.split('.')[1])%4)),object_pairs_hook=_pairs)
    tenant=claims.get('tid');oid=claims.get('oid');client=claims.get('appid',claims.get('azp'));expiry=claims.get('exp')
    expected={ARM,ARM+'/','https://management.core.windows.net/'}if audience==ARM else{SYNAPSE,SYNAPSE+'/'}
    if (claims.get('aud')not in expected or not all(isinstance(v,str)and re.fullmatch(GUID,v,re.I)for v in(tenant,oid,client))
            or type(expiry)is not int or expiry<=time.time()+30 or expiry>time.time()+172800
            or str(transport.tenant).casefold()!=tenant.casefold()or str(transport.verified_tenant).casefold()!=tenant.casefold()):raise ValueError('credential_unbound')
    configured=getattr(transport,'auth',{})
    if configured.get('client_id')and str(configured['client_id']).casefold()!=client.casefold():raise ValueError('client_unbound')
    value=(tenant.casefold(),oid.casefold(),client.casefold())
    if state.get('principal')not in(None,value):raise ValueError('principal_changed')
    state['principal']=value
    return tenant,_fingerprint(json.dumps(value))

def _read(reader,transport,state,ledger,ident,scope,operation,host,path,audience):
    remaining(reader,state)
    if (state['calls']>=MAX_CALLS or state['routes'].get(operation)!=(host,path,audience)
            or audience==ARM and host!='management.azure.com'
            or audience==SYNAPSE and host!=state.get('dev_host')):raise ValueError('untrusted_route')
    state['calls']+=1
    receipt={'id':'synapse-notebook-read-'+str(len(ledger)+1),'identity':ident,'scope':scope,'capture':state['capture'],'operation':operation,
        'method':'GET','host_class':'arm'if audience==ARM else'synapse','host_binding':_fingerprint(host),'audience':audience,
        'request_digest':_fingerprint(path),'status':'unavailable','bytes':0,'tenant_id':None,'principal_binding':None,'identity_bound':False,'object_binding':None}
    ledger.append(receipt);connection=response=None
    try:
        token=transport.token(audience);tenant,binding=principal(token,audience,transport,state);receipt.update(tenant_id=tenant,principal_binding=binding)
        connection=http.client.HTTPSConnection(host,timeout=remaining(reader,state));connection.set_debuglevel(0)
        connection.request('GET',path,body=None,headers={'Authorization':'Bearer '+token,'Accept':'application/json','Accept-Encoding':'identity','Content-Length':'0'});del token
        response=connection.getresponse()
        if (response.status!=200 or response.getheader('Location')or response.getheader('Link')or response.getheader('Content-Range')
                or response.getheader('Transfer-Encoding')or response.getheader('Content-Encoding')not in(None,'','identity')):raise ValueError('unavailable')
        if (response.getheader('Content-Type')or'').split(';')[0].strip().lower()!='application/json':raise ValueError('content_type')
        length=response.getheader('Content-Length')
        if not isinstance(length,str)or not re.fullmatch('[0-9]{1,8}',length)or not 0<int(length)<=MAX_WIRE:raise ValueError('wire_bound')
        native=response.getheader('x-ms-request-id')
        if not isinstance(native,str)or not re.fullmatch('[A-Za-z0-9-]{1,128}',native):raise ValueError('provenance')
        raw=bytearray()
        while True:
            timeout=remaining(reader,state)
            if getattr(connection,'sock',None)is not None:connection.sock.settimeout(timeout)
            chunk=response.read(min(16384,MAX_WIRE+1-len(raw)))
            if not isinstance(chunk,bytes):raise ValueError('wire_type')
            if not chunk:break
            raw.extend(chunk);state['bytes']+=len(chunk);receipt['bytes']=len(raw)
            if len(raw)>MAX_WIRE or state['bytes']>MAX_TOTAL:raise ValueError('wire_bound')
        if len(raw)!=int(length):raise ValueError('truncated')
        data=json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs,parse_constant=lambda _:(_ for _ in()).throw(ValueError('nonfinite')))
        if not isinstance(data,dict)or any(k in data for k in('error','nextLink','partial','_partial','_coverage')):raise ValueError('partial')
        header_etag=response.getheader('ETag')
        if operation.startswith('notebook_')and header_etag is not None and header_etag.strip('"')!=data.get('etag'):raise ValueError('etag_mismatch')
        receipt['status']='collected';return data
    finally:
        if response is not None:response.close()
        if connection is not None:connection.close()

def workspace(data,rid,name,tenant):
    props=_bound(data,rid,SERVICE+'/workspaces')
    ident=data.get('identity')
    endpoint=props.get('connectivityEndpoints',{}).get('dev')if isinstance(props.get('connectivityEndpoints'),dict)else None
    host=name.lower()+'.dev.azuresynapse.net'
    if (data.get('name')!=name or props.get('provisioningState')!='Succeeded' or not isinstance(ident,dict)
            or str(ident.get('tenantId','')).casefold()!=tenant.casefold()or endpoint!='https://'+host):raise ValueError('workspace_unbound')
    return host,_fingerprint(json.dumps([rid.casefold(),name,tenant.casefold(),endpoint]))

def notebook(data,rid,name):
    if (data.get('id')!=rid+'/notebooks/'+name or data.get('name')!=name
            or data.get('type')!='Microsoft.Synapse/workspaces/Notebooks'):raise ValueError('notebook_owner')
    etag=data.get('etag')
    if not isinstance(etag,str)or not re.fullmatch('[A-Za-z0-9-]{1,128}',etag):raise ValueError('etag_unbound')
    props=data.get('properties');cells=props.get('cells')if isinstance(props,dict)else None
    if isinstance(props,dict)and any(k in props for k in('partial','truncated','nextLink','continuationToken')):raise ValueError('cells_partial')
    if not isinstance(cells,list)or not 1<=len(cells)<=MAX_CELLS:raise ValueError('cells_unavailable')
    parts=[]
    for cell in cells:
        if not isinstance(cell,dict)or cell.get('cell_type')not in('code','markdown','raw')or not isinstance(cell.get('source'),list):raise ValueError('cell_unavailable')
        lines=cell['source']
        if not lines or any(not isinstance(line,str)for line in lines):raise ValueError('cell_unavailable')
        part=''.join(lines)
        if len(part.encode('utf-8'))>MAX_CONTENT:raise ValueError('content_bound')
        parts.append(part)
    raw=('\n'.join(parts)).encode('utf-8')
    if not raw.strip()or len(raw)>MAX_CONTENT or b'\0'in raw:raise ValueError('content_bound')
    return etag,hashlib.sha256(raw).hexdigest(),raw

def _one(reader,transport,state,ledger,target,scope):
    ident=identity(target);_,rid,name,notebook_name=parse(target);start=len(ledger)
    marker={'schema':SCHEMA,'identity':ident,'scope':scope,'capture':state['capture'],'complete':False,'native_complete':False,
        'workspace_binding':None,'notebook_binding':None,'parts':[],'leaks':[],'source_requests':[],'verification':'not_attempted'}
    try:
        state['routes']={'subscription':('management.azure.com',scope+'?api-version=2022-12-01',ARM),
            'workspace_before':('management.azure.com',rid+'?api-version='+ARM_API,ARM),
            'workspace_after':('management.azure.com',rid+'?api-version='+ARM_API,ARM)}
        def read(op):
            host,path,audience=state['routes'][op]
            return reader.call(_read,reader,transport,state,ledger,ident,scope,op,host,path,audience)
        sub=read('subscription')
        if (str(sub.get('id','')).casefold()!=scope.casefold()or str(sub.get('subscriptionId','')).casefold()!=scope.rsplit('/',1)[1].casefold()
                or str(sub.get('tenantId','')).casefold()!=str(transport.verified_tenant).casefold()or sub.get('state')!='Enabled'):raise ValueError('subscription_unbound')
        ledger[-1]['identity_bound']=True;del sub
        host,binding=workspace(read('workspace_before'),rid,name,transport.verified_tenant);ledger[-1]['identity_bound']=True
        marker['workspace_binding']=binding;state['dev_host']=host
        path='/notebooks/'+notebook_name+'?api-version='+DATA_API
        state['routes'].update(notebook_before=(host,path,SYNAPSE),notebook_after=(host,path,SYNAPSE))
        first=read('notebook_before');etag,digest,raw=notebook(first,rid,notebook_name);del first
        object_binding=_fingerprint(json.dumps([etag,digest]));marker['notebook_binding']=object_binding
        ledger[-1].update(identity_bound=True,object_binding=object_binding)
        second=read('notebook_after');after_etag,after_digest,_=notebook(second,rid,notebook_name);del second
        if (after_etag,after_digest)!=(etag,digest):raise ValueError('notebook_changed')
        ledger[-1].update(identity_bound=True,object_binding=object_binding)
        after_host,after_binding=workspace(read('workspace_after'),rid,name,transport.verified_tenant)
        if (after_host,after_binding)!=(host,binding):raise ValueError('workspace_changed')
        ledger[-1]['identity_bound']=True
        marker['native_complete']=True;size=len(raw)
        result=scan_with_source(scan_content,raw,ident+'.notebook_source',timeout=remaining(reader,state)/2,
            _redact_values=lambda values:remember(reader,'configuration_secret_redactions',values),source=target_source(target,resource_id=ident,scope=scope));del raw
        marker['parts']=[{'bytes':size,'engines':deepcopy(result['engines']),'complete':result['complete']}]
        leaks=merge_leaks(result['leaks'])
        if len(leaks)>MAX_LEAKS or sum(len(x['locations'])for x in leaks)>MAX_LOCATIONS:raise ValueError('leak_bound')
        marker['leaks']=leaks;remaining(reader,state);marker['complete']=result['complete']is True
    except Exception:marker['complete']=False
    marker['source_requests']=[r['id']for r in ledger[start:]]
    return {'id':ident,MARKER:marker,'_provenance':{'scope':scope,'capture':state['capture'],'source_requests':marker['source_requests'][:]}}

def collect(reader,transport,scopes,wanted,options):
    targets=selected_targets(options,scopes);reader.synapse_notebook_secret_metadata={}
    if not hasattr(reader,'configuration_secret_redactions'):reader.configuration_secret_redactions=set()
    if KIND not in wanted:return
    state={'capture':'synapse-notebook-capture:'+uuid4().hex,'deadline':time.monotonic()+MAX_SECONDS,'calls':0,'bytes':0,'principal':None};ledger=[]
    reader.synapse_notebook_secret_metadata={KIND+'_authorized':enabled(options),KIND+'_capture':state['capture'],KIND+'_receipts':ledger,
        KIND+'_selection':{s:[identity(t)for t in targets if parse(t)[0].casefold()==s.casefold()]for s in scopes}}
    if not enabled(options):return
    for scope in scopes:
        selected=[t for t in targets if parse(t)[0].casefold()==scope.casefold()]
        if selected:
            def fetch(selected=selected,scope=scope):yield[_one(reader,transport,state,ledger,t,scope)for t in selected]
            reader.run([(KIND,scope,SERVICE,fetch)])
