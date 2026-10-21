"""Unregistered bounded notebook SOURCE exports; existing workspace principals only."""

from peaso.secret_evidence import scan_with_source, target_source
from copy import deepcopy
import base64
import http.client
import json
import re
import time
from urllib.parse import quote
from uuid import uuid4
from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint
from .azure_selected_declaration_secret_indicators import GUID, SCOPE, SEG, ARM, _pairs, _bound, remaining
from .azure_selected_secret_integration_20261020 import remember

KIND='azure_databricks_selected_notebook'
CHECK='azure.review.databricks.selected_notebook_source_secret_indicators'
OPTION='selected_azure_databricks_notebooks'
SERVICE='Microsoft.Databricks'
API='2026-01-01'
DATABRICKS='2ff814a6-3304-4ab8-85cb-cd0e6f879c1d'
MARKER='SelectedDatabricksNotebookSecretIndicators'
SCHEMA='azure-selected-databricks-notebook-source-v1'
MAX_TARGETS=4
MAX_CALLS=20
MAX_WIRE=2*1024*1024
MAX_TOTAL=8*1024*1024
MAX_CONTENT=1024*1024
MAX_SECONDS=120
MAX_LEAKS=256
MAX_LOCATIONS=512
LANGUAGES={'PYTHON':'py','SCALA':'scala','SQL':'sql','R':'r'}


def enabled(options):
    return options.get('content_secret_scans')is True and isinstance(options.get('_content_secret_scan_kinds'),list)and KIND in options['_content_secret_scan_kinds']


def parse(target):
    if not isinstance(target,dict)or set(target)!={'workspace_resource_id','path'}:raise ValueError('invalid_selection')
    rid=target['workspace_resource_id'];path=target['path']
    match=re.fullmatch(r'(/subscriptions/'+GUID+r')/resourceGroups/'+SEG+r'/providers/Microsoft\.Databricks/workspaces/([A-Za-z0-9_][A-Za-z0-9_.()-]{2,63})',rid,re.I)if isinstance(rid,str)and len(rid)<=1024 else None
    if (not match or any(p in('.','..')for p in rid.split('/'))or not isinstance(path,str)or not 2<=len(path.encode())<=1024
            or not re.fullmatch(r'/[A-Za-z0-9_@+ =()./-]+',path)or len(path.split('/'))>32
            or any(p in('','.','..')or p.endswith(' ')for p in path.split('/')[1:])
            or path.casefold().startswith(('/repos/','/workspace/repos/','/volumes/','/dbfs/'))
            or path.casefold()in('/repos','/workspace/repos','/volumes','/dbfs')):raise ValueError('invalid_selection')
    return match[1],rid,path


def identity(target):
    _,rid,path=parse(target)
    return KIND+':'+_fingerprint(rid.casefold()+'\n'+path)


def selected_targets(options,scopes):
    if not isinstance(options,dict)or 'content_secret_scans'in options and type(options['content_secret_scans'])is not bool:raise ValueError('invalid_selection')
    if OPTION not in options and not enabled(options):return[]
    targets=options.get(OPTION)
    if (not isinstance(scopes,list)or not 1<=len(scopes)<=8 or any(not isinstance(s,str)or not SCOPE.fullmatch(s)for s in scopes)
            or len({s.casefold()for s in scopes})!=len(scopes)or not isinstance(targets,list)or not 1<=len(targets)<=MAX_TARGETS):raise ValueError('invalid_selection')
    seen=set()
    for target in targets:
        scope,_,_=parse(target);ident=identity(target)
        if scope.casefold()not in{s.casefold()for s in scopes}or ident in seen:raise ValueError('invalid_selection')
        seen.add(ident)
    return deepcopy(targets)


def _principal(token,audience,transport,state):
    # SDK acquisition is trusted; these are defensive coherence checks, not JWT signature validation.
    if not isinstance(token,str)or not 1<=len(token)<=32768 or any(c in token for c in '\r\n'):raise ValueError('credential_unbound')
    parts=token.split('.')
    if len(parts)!=3:raise ValueError('credential_unbound')
    claims=json.loads(base64.urlsafe_b64decode(parts[1]+'='*(-len(parts[1])%4)),object_pairs_hook=_pairs)
    tenant=claims.get('tid');oid=claims.get('oid');client=claims.get('appid',claims.get('azp'));expiry=claims.get('exp')
    if (not all(isinstance(v,str)and re.fullmatch(GUID,v,re.I)for v in(tenant,oid,client))
            or claims.get('aud')not in({ARM,ARM+'/', 'https://management.core.windows.net/'}if audience==ARM else{DATABRICKS,DATABRICKS+'/'})
            or type(expiry)is not int or expiry<=time.time()+30 or str(transport.tenant).casefold()!=tenant.casefold()
            or str(transport.verified_tenant).casefold()!=tenant.casefold()):raise ValueError('credential_unbound')
    configured=getattr(transport,'auth',{})
    if configured.get('method')in('client-secret','client-cert','certificate','workload-identity','managed-identity','device-code')and configured.get('client_id')and str(configured['client_id']).casefold()!=client.casefold():raise ValueError('client_unbound')
    if 'appid'in claims and 'azp'in claims and str(claims['appid']).casefold()!=str(claims['azp']).casefold():raise ValueError('client_unbound')
    principal=(tenant.casefold(),oid.casefold(),client.casefold())
    if state.get('principal')not in(None,principal):raise ValueError('principal_changed')
    state['principal']=principal
    return tenant,_fingerprint(json.dumps(principal))


def _read(reader,transport,state,receipts,ident,scope,operation,host,path,audience):
    remaining(reader,state)
    if state['calls']>=MAX_CALLS:raise ValueError('call_limit')
    if (audience not in(ARM,DATABRICKS)or operation not in state['routes']or state['routes'][operation]!=(host,path,audience)
            or audience==ARM and host!='management.azure.com'
            or audience==DATABRICKS and not re.fullmatch(r'adb-[1-9][0-9]{0,18}\.[0-9]{1,20}\.azuredatabricks\.net',host)):raise ValueError('untrusted_route')
    state['calls']+=1
    receipt={'id':'notebook-read-'+str(len(receipts)+1),'identity':ident,'scope':scope,'capture':state['capture'],'operation':operation,'method':'GET',
        'host_class':'arm'if audience==ARM else'databricks','host_binding':_fingerprint(host),'audience':audience,'request_digest':_fingerprint(path),
        'status':'unavailable','bytes':0,'tenant_id':None,'principal_binding':None,'identity_bound':False,'object_binding':None}
    receipts.append(receipt);connection=response=None
    try:
        token=transport.token(audience);tenant,principal=_principal(token,audience,transport,state)
        receipt.update(tenant_id=tenant,principal_binding=principal)
        connection=http.client.HTTPSConnection(host,timeout=remaining(reader,state));connection.set_debuglevel(0)
        # No management token / workspace-onboarding header, challenge or alternate auth path.
        connection.request('GET',path,body=None,headers={'Authorization':'Bearer '+token,'Accept':'application/json','Accept-Encoding':'identity','Content-Length':'0'});del token
        response=connection.getresponse()
        if(response.status!=200 or response.getheader('Content-Encoding')not in(None,'','identity')or response.getheader('Location')or response.getheader('Link')):raise ValueError('unavailable')
        if(response.getheader('Content-Type')or'').split(';')[0].strip().lower()!='application/json':raise ValueError('encoding')
        length=response.getheader('Content-Length')
        if length is not None and(not re.fullmatch('[0-9]{1,8}',length)or not 0<int(length)<=MAX_WIRE):raise ValueError('wire_limit')
        chunks=[];count=0
        while True:
            timeout=remaining(reader,state)
            if getattr(connection,'sock',None)is not None:connection.sock.settimeout(timeout)
            chunk=response.read(16384)
            if not chunk:break
            count+=len(chunk);state['bytes']+=len(chunk);receipt['bytes']=count
            if count>MAX_WIRE or state['bytes']>MAX_TOTAL:raise ValueError('wire_limit')
            chunks.append(chunk)
        if not count or length is not None and count!=int(length):raise ValueError('incomplete')
        data=json.loads(b''.join(chunks).decode('utf-8'),object_pairs_hook=_pairs,parse_constant=lambda _:(_ for _ in()).throw(ValueError('nonfinite')))
        if not isinstance(data,dict)or any(k in data for k in('error','error_code','nextLink','next_page_token','partial','_partial','_coverage')):raise ValueError('incomplete')
        receipt['status']='collected';return data
    except Exception:raise ValueError('notebook_read_unavailable')from None
    finally:
        if response is not None:response.close()
        if connection is not None:connection.close()


def notebook(data,path):
    object_id=data.get('object_id');language=data.get('language')
    if(not {'path','object_type','object_id','language'}<=set(data)<={'path','object_type','object_id','language','resource_id'}or data.get('object_type')!='NOTEBOOK'or data.get('path')!=path or type(object_id)is not int or not 1<=object_id<=2**63-1 or language not in LANGUAGES):raise ValueError('notebook_unbound')
    resource=data.get('resource_id')
    if resource is not None and(not isinstance(resource,str)or not 1<=len(resource)<=256 or any(ord(c)<32 or ord(c)>126 for c in resource)):raise ValueError('notebook_unbound')
    return object_id,language,resource


def source_bytes(data,language):
    if not {'content'}<=set(data)<={'content','file_type'}or 'file_type'in data and data['file_type']!=LANGUAGES[language]:raise ValueError('unsupported_export')
    encoded=data['content']
    if not isinstance(encoded,str)or not 1<=len(encoded)<=4*((MAX_CONTENT+2)//3):raise ValueError('source_limit')
    raw=base64.b64decode(encoded.encode('ascii'),validate=True)
    if base64.b64encode(raw).decode()!=encoded or not 0<len(raw)<=MAX_CONTENT or b'\0'in raw or not raw.decode('utf-8').strip():raise ValueError('unsupported_source')
    return raw


def _scan(reader,transport,target,scope,state,receipts):
    ident=identity(target);_,rid,path=parse(target);start=len(receipts)
    marker={'schema':SCHEMA,'identity':ident,'scope':scope,'capture':state['capture'],'complete':False,'format':'SOURCE',
        'consistency':'point_in_time_export_only','workspace_binding':None,'object_binding':None,'language':None,'parts':[],'leaks':[],'source_requests':[],'verification':'not_attempted'}
    try:
        state['routes']={'subscription':('management.azure.com',scope+'?api-version=2022-12-01',ARM),'workspace':('management.azure.com',rid+'?api-version='+API,ARM)}
        def read(op):
            host,route,audience=state['routes'][op]
            return reader.call(_read,reader,transport,state,receipts,ident,scope,op,host,route,audience)
        sub=read('subscription')
        if(str(sub.get('id','')).casefold()!=scope.casefold()or str(sub.get('subscriptionId','')).casefold()!=scope.rsplit('/',1)[1].casefold()
                or str(sub.get('tenantId','')).casefold()!=str(transport.verified_tenant).casefold()or sub.get('state')!='Enabled'):raise ValueError('scope_unbound')
        receipts[-1]['identity_bound']=True;del sub
        workspace=read('workspace');props=_bound(workspace,rid,SERVICE+'/workspaces');wid=props.get('workspaceId');host=props.get('workspaceUrl')
        match=re.fullmatch(r'adb-([1-9][0-9]{0,18})\.([0-9]{1,20})\.azuredatabricks\.net',host)if isinstance(host,str)else None
        if(not isinstance(wid,str)or not match or wid!=match[1]or int(wid)>2**63-1 or props.get('provisioningState')!='Succeeded'):raise ValueError('workspace_unbound')
        marker['workspace_binding']=_fingerprint(wid);receipts[-1]['identity_bound']=True;del workspace,props,wid
        query='?path='+quote(path,safe='')
        state['routes'].update(status_before=(host,'/api/2.0/workspace/get-status'+query,DATABRICKS),
            export=(host,'/api/2.0/workspace/export'+query+'&format=SOURCE&direct_download=false',DATABRICKS),
            status_after=(host,'/api/2.0/workspace/get-status'+query,DATABRICKS))
        status=read('status_before');object_id,language,resource=notebook(status,path);binding=_fingerprint(json.dumps([object_id,resource]));del status
        marker.update(object_binding=binding,language=language);receipts[-1].update(identity_bound=True,object_binding=binding)
        data=read('export');raw=source_bytes(data,language);del data
        receipts[-1].update(identity_bound=True,object_binding=binding)
        after=read('status_after')
        if notebook(after,path)!=(object_id,language,resource):raise ValueError('object_changed')
        receipts[-1].update(identity_bound=True,object_binding=binding);del after,object_id
        count=len(raw);result=scan_with_source(scan_content, raw,ident+'.notebook_source',timeout=remaining(reader,state)/2,
            _redact_values=lambda values:remember(reader,'configuration_secret_redactions',values), source=target_source(target, resource_id=ident, scope=scope));del raw
        marker['parts']=[{'bytes':count,'engines':deepcopy(result['engines']),'complete':result['complete']}]
        leaks=merge_leaks(result['leaks']);bounded=[];locations=0
        for leak in leaks:
            if len(bounded)>=MAX_LEAKS or locations+len(leak['locations'])>MAX_LOCATIONS:break
            bounded.append(leak);locations+=len(leak['locations'])
        marker['leaks']=bounded;remaining(reader,state);marker['complete']=result['complete']is True and len(bounded)==len(leaks)
    except Exception:marker['complete']=False
    marker['source_requests']=[r['id']for r in receipts[start:]]
    return{'id':ident,MARKER:marker,'_provenance':{'scope':scope,'capture':state['capture'],'source_requests':marker['source_requests'][:]}}


def collect(reader,transport,scopes,wanted,options):
    targets=selected_targets(options,scopes)
    if not hasattr(reader,'configuration_secret_redactions'):reader.configuration_secret_redactions=set()
    reader.databricks_notebook_secret_metadata={}
    if KIND not in wanted:return
    state={'capture':'notebook-capture:'+uuid4().hex,'deadline':time.monotonic()+MAX_SECONDS,'calls':0,'bytes':0};receipts=[]
    reader.databricks_notebook_secret_metadata={KIND+'_authorized':enabled(options),KIND+'_capture':state['capture'],KIND+'_receipts':receipts,
        KIND+'_selection':{s:[identity(t)for t in targets if parse(t)[0].casefold()==s.casefold()]for s in scopes}}
    if not enabled(options):return
    for scope in scopes:
        selected=[t for t in targets if parse(t)[0].casefold()==scope.casefold()]
        if selected:
            def fetch(selected=selected,scope=scope):yield[_scan(reader,transport,t,scope,state,receipts)for t in selected]
            reader.run([(KIND,scope,SERVICE,fetch)])


def final_snapshot(reader,snapshot):
    snapshot.setdefault('metadata',{}).update(getattr(reader,'databricks_notebook_secret_metadata',{}))
    from .azure_ml_selected_job_secret_indicators import final_snapshot as existing
    return existing(reader,snapshot)
