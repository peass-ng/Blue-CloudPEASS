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
FILE_OPTION='selected_azure_databricks_files'
RUN_OPTION='selected_azure_databricks_task_outputs'
SERVICE='Microsoft.Databricks'
API='2026-01-01'
DATABRICKS='2ff814a6-3304-4ab8-85cb-cd0e6f879c1d'
MARKER='SelectedDatabricksNotebookSecretIndicators'
SCHEMA='azure-selected-databricks-notebook-source-v1'
MAX_TARGETS=4
MAX_CALLS=32
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
    if not isinstance(target,dict)or set(target) not in ({'workspace_resource_id','path'},{'workspace_resource_id','path','object_type'}) or target.get('object_type','NOTEBOOK') not in ('NOTEBOOK','FILE'):raise ValueError('invalid_selection')
    rid=target['workspace_resource_id'];path=target['path']
    match=re.fullmatch(r'(/subscriptions/'+GUID+r')/resourceGroups/'+SEG+r'/providers/Microsoft\.Databricks/workspaces/([A-Za-z0-9_][A-Za-z0-9_.()-]{2,63})',rid,re.I)if isinstance(rid,str)and len(rid)<=1024 else None
    if (not match or any(p in('.','..')for p in rid.split('/'))or not isinstance(path,str)or not 2<=len(path.encode())<=1024
            or not re.fullmatch(r'/[A-Za-z0-9_@+ =()./-]+',path)or len(path.split('/'))>32
            or any(p in('','.','..')or p.endswith(' ')for p in path.split('/')[1:])
            or path.casefold().startswith(('/repos/','/workspace/repos/','/volumes/','/dbfs/'))
            or path.casefold()in('/repos','/workspace/repos','/volumes','/dbfs')):raise ValueError('invalid_selection')
    return match[1],rid,path


def identity(target):
    if 'task_run_id' in target:
        _,rid,job,parent,task,key,content=parse_job(target)
        return KIND+':'+_fingerprint(json.dumps([rid.casefold(),job,parent,task,key,content]))
    _,rid,path=parse(target)
    return KIND+':'+_fingerprint(rid.casefold()+'\n'+path+('\nFILE' if target.get('object_type')=='FILE' else ''))


def parse_job(target):
    if not isinstance(target,dict) or set(target)!={'workspace_resource_id','job_id','parent_run_id','task_run_id','task_key','content'}:
        raise ValueError('invalid_selection')
    rid=target['workspace_resource_id']
    match=re.fullmatch(r'(/subscriptions/'+GUID+r')/resourceGroups/'+SEG+r'/providers/Microsoft\.Databricks/workspaces/([A-Za-z0-9_][A-Za-z0-9_.()-]{2,63})',rid,re.I) if isinstance(rid,str) and len(rid)<=1024 else None
    values=[target[k] for k in ('job_id','parent_run_id','task_run_id')]
    key=target['task_key'];content=target['content']
    if (not match or any(p in ('.','..') for p in rid.split('/'))
            or any(type(v)is not int or not 1<=v<=2**63-1 for v in values)
            or values[1]==values[2] or not isinstance(key,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',key)
            or content not in ('notebook_result','task_logs')):raise ValueError('invalid_selection')
    return match[1],rid,*values,key,content


def target_scope(target):
    return parse_job(target)[0] if 'task_run_id' in target else parse(target)[0]


def selected_targets(options,scopes):
    if not isinstance(options,dict)or 'content_secret_scans'in options and type(options['content_secret_scans'])is not bool:raise ValueError('invalid_selection')
    if OPTION not in options and FILE_OPTION not in options and RUN_OPTION not in options and not enabled(options):return[]
    notebooks=options.get(OPTION,[]);files=options.get(FILE_OPTION,[]);runs=options.get(RUN_OPTION,[])
    if (OPTION in options and (not isinstance(notebooks,list) or not notebooks)
            or FILE_OPTION in options and (not isinstance(files,list) or not files)
            or RUN_OPTION in options and (not isinstance(runs,list) or not runs)
            or any(not isinstance(t,dict) or set(t)!={'workspace_resource_id','path'} for t in notebooks)
            or any(not isinstance(t,dict) or set(t)!={'workspace_resource_id','path','object_type'} or t['object_type']!='FILE' for t in files)
            or any(not isinstance(t,dict) for t in runs)):
        raise ValueError('invalid_selection')
    targets=notebooks+files+runs
    if (not isinstance(scopes,list)or not 1<=len(scopes)<=8 or any(not isinstance(s,str)or not SCOPE.fullmatch(s)for s in scopes)
            or len({s.casefold()for s in scopes})!=len(scopes)or not isinstance(targets,list)or not 1<=len(targets)<=MAX_TARGETS):raise ValueError('invalid_selection')
    seen=set()
    for target in targets:
        scope=target_scope(target);ident=identity(target)
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


def workspace_file(data,path):
    """Only stable native FILE metadata may bind one selected RAW export."""
    allowed={'path','object_type','object_id','resource_id','created_at','modified_at','size','directory_info'}
    if (not isinstance(data,dict) or not {'path','object_type','object_id','modified_at','size'}<=set(data)<=allowed
            or data['path']!=path or data['object_type']!='FILE'
            or type(data['object_id']) is not int or not 1<=data['object_id']<=2**63-1
            or type(data['modified_at']) is not int or not 1<=data['modified_at']<=2**63-1
            or type(data['size']) is not int or not 1<=data['size']<=MAX_CONTENT):
        raise ValueError('file_unbound')
    resource=data.get('resource_id')
    if resource is not None and (not isinstance(resource,str) or not 1<=len(resource)<=256 or any(ord(c)<32 or ord(c)>126 for c in resource)):
        raise ValueError('file_unbound')
    if 'created_at' in data and (type(data['created_at']) is not int or not 1<=data['created_at']<=data['modified_at']):
        raise ValueError('file_unbound')
    if 'directory_info' in data:raise ValueError('file_unbound')
    return data['object_id'],resource,data['modified_at'],data['size']


def source_bytes(data,language):
    if not {'content'}<=set(data)<={'content','file_type'}or 'file_type'in data and data['file_type']!=LANGUAGES[language]:raise ValueError('unsupported_export')
    encoded=data['content']
    if not isinstance(encoded,str)or not 1<=len(encoded)<=4*((MAX_CONTENT+2)//3):raise ValueError('source_limit')
    raw=base64.b64decode(encoded.encode('ascii'),validate=True)
    if base64.b64encode(raw).decode()!=encoded or not 0<len(raw)<=MAX_CONTENT or b'\0'in raw or not raw.decode('utf-8').strip():raise ValueError('unsupported_source')
    return raw


def file_bytes(data,size):
    if not isinstance(data,dict) or not {'content'}<=set(data)<={'content','file_type'}:raise ValueError('unsupported_export')
    if 'file_type' in data and (not isinstance(data['file_type'],str) or not re.fullmatch('[A-Za-z0-9_.-]{1,32}',data['file_type'])):raise ValueError('unsupported_export')
    encoded=data['content']
    if not isinstance(encoded,str) or not 1<=len(encoded)<=4*((MAX_CONTENT+2)//3):raise ValueError('file_limit')
    raw=base64.b64decode(encoded.encode('ascii'),validate=True)
    if (base64.b64encode(raw).decode()!=encoded or len(raw)!=size or b'\0' in raw
            or not raw.decode('utf-8').strip()):raise ValueError('unsupported_file')
    return raw


def _scan(reader,transport,target,scope,state,receipts):
    ident=identity(target);_,rid,path=parse(target);start=len(receipts);is_file=target.get('object_type')=='FILE'
    marker={'schema':SCHEMA,'identity':ident,'scope':scope,'capture':state['capture'],'complete':False,'format':'RAW' if is_file else 'SOURCE',
        'consistency':'status_bound_file_export_only' if is_file else 'point_in_time_export_only','workspace_binding':None,'object_binding':None,'language':None,'parts':[],'leaks':[],'source_requests':[],'verification':'not_attempted'}
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
            export=(host,'/api/2.0/workspace/export'+query+'&format='+('RAW' if is_file else 'SOURCE')+'&direct_download=false',DATABRICKS),
            status_after=(host,'/api/2.0/workspace/get-status'+query,DATABRICKS))
        status=read('status_before');native=workspace_file(status,path) if is_file else notebook(status,path)
        binding=_fingerprint(json.dumps(native));del status
        marker.update(object_binding=binding,language='TEXT' if is_file else native[1]);receipts[-1].update(identity_bound=True,object_binding=binding)
        data=read('export');raw=file_bytes(data,native[3]) if is_file else source_bytes(data,native[1]);del data
        receipts[-1].update(identity_bound=True,object_binding=binding)
        after=read('status_after')
        if (workspace_file(after,path) if is_file else notebook(after,path))!=native:raise ValueError('object_changed')
        receipts[-1].update(identity_bound=True,object_binding=binding);del after,native
        count=len(raw);result=scan_with_source(scan_content, raw,ident+('.workspace_file' if is_file else '.notebook_source'),timeout=remaining(reader,state)/2,
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


def _run_state(data):
    current=data.get('status')
    if isinstance(current,dict) and current.get('state')=='TERMINATED':
        return ('TERMINATED',str(current.get('termination_details',{}).get('code','')))
    current=data.get('state')
    if isinstance(current,dict) and current.get('life_cycle_state')=='TERMINATED':
        return ('TERMINATED',str(current.get('result_state','')))
    raise ValueError('run_not_terminal')


def _run_identity(data,run_id,job_id,task_key=None,content=None):
    if (not isinstance(data,dict) or data.get('run_id')!=run_id or type(data.get('run_id'))is not int
            or data.get('job_id')!=job_id or type(data.get('job_id'))is not int
            or type(data.get('start_time'))is not int or data['start_time']<=0
            or type(data.get('end_time'))is not int or data['end_time']<data['start_time']):
        raise ValueError('run_unbound')
    state=_run_state(data)
    if task_key is not None:
        field='notebook_task' if content=='notebook_result' else None
        other=('spark_jar_task','spark_python_task','python_wheel_task')
        if (data.get('task_key')!=task_key or
                (field not in data or any(k in data for k in other) if field else sum(k in data for k in other)!=1 or 'notebook_task'in data)):
            raise ValueError('task_unbound')
    attempt=data.get('attempt_number',0);original=data.get('original_attempt_run_id',run_id)
    if (type(attempt)is not int or attempt<0 or type(original)is not int or original<=0):raise ValueError('run_unbound')
    return (run_id,job_id,data['start_time'],data['end_time'],state,attempt,original)


def _parent_identity(data,job_id,parent_id,task_id,key,content):
    if not isinstance(data,dict) or data.get('next_page_token') or not isinstance(data.get('tasks'),list) or not 1<=len(data['tasks'])<=100:
        raise ValueError('parent_incomplete')
    parent=_run_identity(data,parent_id,job_id)
    matches=[t for t in data['tasks'] if isinstance(t,dict) and t.get('run_id')==task_id and t.get('task_key')==key]
    if len(matches)!=1:raise ValueError('task_not_owned')
    task=matches[0]
    if (content=='notebook_result' and ('notebook_task' not in task or any(k in task for k in ('spark_jar_task','spark_python_task','python_wheel_task')))
            or content=='task_logs' and (sum(k in task for k in ('spark_jar_task','spark_python_task','python_wheel_task'))!=1 or 'notebook_task'in task)):
        raise ValueError('task_type_unbound')
    return (parent,task_id,key,content)


def _workspace_identity(data,rid):
    props=_bound(data,rid,SERVICE+'/workspaces');wid=props.get('workspaceId');host=props.get('workspaceUrl')
    match=re.fullmatch(r'adb-([1-9][0-9]{0,18})\.([0-9]{1,20})\.azuredatabricks\.net',host) if isinstance(host,str) else None
    if not isinstance(wid,str) or not match or wid!=match[1] or int(wid)>2**63-1 or props.get('provisioningState')!='Succeeded':
        raise ValueError('workspace_unbound')
    return wid,host


def _scan_job(reader,transport,target,scope,state,receipts):
    ident=identity(target);_,rid,job_id,parent_id,task_id,key,content=parse_job(target);start=len(receipts)
    fmt='NOTEBOOK_RESULT' if content=='notebook_result' else'TASK_LOGS'
    marker={'schema':SCHEMA,'identity':ident,'scope':scope,'capture':state['capture'],'complete':False,'format':fmt,
        'consistency':'selected_terminal_task_output_only','workspace_binding':None,'object_binding':None,'language':'TEXT',
        'parts':[],'leaks':[],'source_requests':[],'verification':'not_attempted'}
    try:
        state['routes']={'subscription':('management.azure.com',scope+'?api-version=2022-12-01',ARM),
            'workspace_before':('management.azure.com',rid+'?api-version='+API,ARM)}
        def read(op):
            host,path,audience=state['routes'][op]
            return reader.call(_read,reader,transport,state,receipts,ident,scope,op,host,path,audience)
        sub=read('subscription')
        if (str(sub.get('id','')).casefold()!=scope.casefold() or str(sub.get('subscriptionId','')).casefold()!=scope.rsplit('/',1)[1].casefold()
                or str(sub.get('tenantId','')).casefold()!=str(transport.verified_tenant).casefold() or sub.get('state')!='Enabled'):
            raise ValueError('scope_unbound')
        receipts[-1]['identity_bound']=True;del sub
        workspace=read('workspace_before');wid,host=_workspace_identity(workspace,rid);del workspace
        marker['workspace_binding']=_fingerprint(wid);receipts[-1]['identity_bound']=True
        parent_path='/api/2.2/jobs/runs/get?run_id='+str(parent_id)
        task_path='/api/2.2/jobs/runs/get?run_id='+str(task_id)
        state['routes'].update(parent_before=(host,parent_path,DATABRICKS),task_before=(host,task_path,DATABRICKS),
            output=(host,'/api/2.2/jobs/runs/get-output?run_id='+str(task_id),DATABRICKS),
            task_after=(host,task_path,DATABRICKS),parent_after=(host,parent_path,DATABRICKS),
            workspace_after=('management.azure.com',rid+'?api-version='+API,ARM))
        parent=_parent_identity(read('parent_before'),job_id,parent_id,task_id,key,content)
        task=_run_identity(read('task_before'),task_id,job_id,key,content)
        binding=_fingerprint(json.dumps([parent,task],sort_keys=True))
        marker['object_binding']=binding
        receipts[-2].update(identity_bound=True,object_binding=binding)
        receipts[-1].update(identity_bound=True,object_binding=binding)
        output=read('output');metadata=output.get('metadata')
        if _run_identity(metadata,task_id,job_id,key,content)!=task:raise ValueError('output_unbound')
        field=output.get('notebook_output') if content=='notebook_result' else output
        value=field.get('result') if content=='notebook_result' and isinstance(field,dict) else output.get('logs') if content=='task_logs' else None
        truncated=field.get('truncated') if content=='notebook_result' and isinstance(field,dict) else output.get('logs_truncated') if content=='task_logs' else None
        if (not isinstance(value,str) or not value.strip() or type(truncated)is not bool
                or not 1<=len(value.encode('utf-8'))<=MAX_CONTENT or '\x00' in value):raise ValueError('output_unavailable')
        receipts[-1].update(identity_bound=True,object_binding=binding);del output,metadata,field
        if _run_identity(read('task_after'),task_id,job_id,key,content)!=task:raise ValueError('task_changed')
        receipts[-1].update(identity_bound=True,object_binding=binding)
        if _parent_identity(read('parent_after'),job_id,parent_id,task_id,key,content)!=parent:raise ValueError('parent_changed')
        receipts[-1].update(identity_bound=True,object_binding=binding)
        final_wid,final_host=_workspace_identity(read('workspace_after'),rid)
        if (final_wid,final_host)!=(wid,host):raise ValueError('workspace_changed')
        receipts[-1]['identity_bound']=True;del parent,task,wid,host
        raw=value.encode('utf-8');del value
        result=scan_with_source(scan_content,raw,ident+'.task_output',timeout=remaining(reader,state)/2,
            _redact_values=lambda values:remember(reader,'configuration_secret_redactions',values),
            source=target_source(target,resource_id=ident,scope=scope));count=len(raw);del raw
        marker['parts']=[{'bytes':count,'engines':deepcopy(result['engines']),'complete':result['complete']}]
        leaks=merge_leaks(result['leaks']);bounded=[];locations=0
        for leak in leaks:
            if len(bounded)>=MAX_LEAKS or locations+len(leak['locations'])>MAX_LOCATIONS:break
            bounded.append(leak);locations+=len(leak['locations'])
        marker['leaks']=bounded;remaining(reader,state)
        marker['complete']=result['complete'] is True and not truncated and len(bounded)==len(leaks)
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
        KIND+'_selection':{s:[identity(t)for t in targets if target_scope(t).casefold()==s.casefold()]for s in scopes}}
    if not enabled(options):return
    for scope in scopes:
        selected=[t for t in targets if target_scope(t).casefold()==scope.casefold()]
        if selected:
            def fetch(selected=selected,scope=scope):yield[(_scan_job if 'task_run_id' in t else _scan)(reader,transport,t,scope,state,receipts)for t in selected]
            reader.run([(KIND,scope,SERVICE,fetch)])


def final_snapshot(reader,snapshot):
    snapshot.setdefault('metadata',{}).update(getattr(reader,'databricks_notebook_secret_metadata',{}))
    from .azure_ml_selected_job_secret_indicators import final_snapshot as existing
    return existing(reader,snapshot)
