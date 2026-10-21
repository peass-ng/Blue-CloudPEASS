"""Pure optional ML asset literals and exactly associated plain storage sources.

No registration, datastore credentials, source listing, execution or URL following.
"""

from peaso.secret_evidence import scan_with_source, target_source
import http.client
import json
import re
import time
from copy import deepcopy
from urllib.parse import quote
from uuid import uuid4
from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint
from . import azure_selected_storage_secret_indicators as storage
from .azure_selected_declaration_secret_indicators import GUID, SCOPE, SEG, ARM, _bound, _pairs
from .azure_selected_secret_integration_20261020 import remember

SERVICE='Microsoft.MachineLearningServices'
API='2026-05-01'
WORKSPACE_API='2026-03-01'
SCHEMA='azure-selected-ml-asset-source-v1'
MARKER='SelectedMLAssetSecretIndicators'
PROFILES={
 'environment':{'kind':'azure_ml_selected_environment_conda','check':'azure.review.machine_learning.selected_environment_conda_secret_indicators','option':'selected_azure_ml_environment_versions','asset':'environments','title':'Selected ML environment text has no detected secrets'},
 'code':{'kind':'azure_ml_selected_code_file','check':'azure.review.machine_learning.selected_code_file_secret_indicators','option':'selected_azure_ml_code_files','asset':'codes','title':'Selected ML code source files have no detected secrets'},
}
KINDS=tuple(p['kind']for p in PROFILES.values())
MAX_TARGETS=4
MAX_CALLS=56  # Four selected job-bound code files use at most 14 reads each.
MAX_TOTAL=8*1024*1024
MAX_ARM=512*1024
MAX_CONTENT=256*1024
MAX_SECONDS=120
MAX_LEAKS=256
MAX_LOCATIONS=512
ASSET=r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}'
BASE=r'(/subscriptions/'+GUID+r')/resourceGroups/'+SEG+r'/providers/Microsoft\.MachineLearningServices/workspaces/[A-Za-z0-9][A-Za-z0-9_-]{2,32}'


def enabled(options,profile):
    return options.get('content_secret_scans')is True and isinstance(options.get('_content_secret_scan_kinds'),list)and PROFILES[profile]['kind']in options['_content_secret_scan_kinds']


def parse(profile,target):
    allowed=({'resource_id'},{'resource_id','datastore','storage'})if profile=='environment'else({'resource_id','datastore','storage'},{'resource_id','datastore','storage','job_resource_id'})
    if not isinstance(target,dict)or set(target)not in allowed:raise ValueError('invalid_selection')
    rid=target['resource_id'];p=PROFILES[profile]
    match=re.fullmatch('('+BASE+')/'+p['asset']+'/('+ASSET+')/versions/('+ASSET+')',rid,re.I)if isinstance(rid,str)and len(rid)<=1024 else None
    if not match or any(s in('.','..')for s in rid.split('/')):raise ValueError('invalid_selection')
    if 'job_resource_id' in target:
        job=target['job_resource_id']
        j=re.fullmatch(re.escape(match[1])+r'/jobs/('+ASSET+')',job,re.I)if isinstance(job,str)and len(job)<=1024 else None
        if not j or job.rsplit('/',1)[1] in('.','..'):raise ValueError('invalid_selection')
    if 'storage'in target:
        if not isinstance(target['datastore'],str)or not re.fullmatch(ASSET,target['datastore'])or target['datastore']in('.','..'):raise ValueError('invalid_selection')
        service,scope,*_=storage.parse(target['storage'])
        if scope.casefold()!=match[2].casefold()or target['storage']['format']!='text'or(profile=='environment'and service!='blob'):raise ValueError('invalid_selection')
    return match[2],rid,match[1]


def identity(profile,target):
    # ML container names and versions are case-sensitive native route segments.
    scope,rid,workspace=parse(profile,target)
    native=deepcopy(target);native['resource_id']=workspace.casefold()+rid[len(workspace):]
    if 'job_resource_id'in native:native['job_resource_id']=workspace.casefold()+native['job_resource_id'][len(workspace):]
    if 'storage'in target:
        native['storage']['resource_id']=native['storage']['resource_id'].casefold()
        if native['storage']['service']=='file':native['storage']['object']=native['storage']['object'].casefold()
    return PROFILES[profile]['kind']+':'+_fingerprint(json.dumps(native,sort_keys=True,separators=(',',':')))


def selected_targets(options,scopes,profile=None):
    if not isinstance(options,dict)or 'content_secret_scans'in options and type(options['content_secret_scans'])is not bool:raise ValueError('invalid_selection')
    result={};count=0
    for name in([profile]if profile else list(PROFILES)):
        option=PROFILES[name]['option']
        if option not in options and not enabled(options,name):result[name]=[];continue
        targets=options.get(option)
        if (not isinstance(scopes,list)or not 1<=len(scopes)<=8 or any(not isinstance(s,str)or not SCOPE.fullmatch(s)for s in scopes)
                or len({s.casefold()for s in scopes})!=len(scopes)or not isinstance(targets,list)or not 1<=len(targets)<=MAX_TARGETS):raise ValueError('invalid_selection')
        seen=set()
        for target in targets:
            scope,_,_=parse(name,target);ident=identity(name,target)
            if scope.casefold()not in{s.casefold()for s in scopes}or ident in seen:raise ValueError('invalid_selection')
            seen.add(ident)
        result[name]=deepcopy(targets);count+=len(targets)
    if count>MAX_TARGETS:raise ValueError('invalid_selection')
    return result[profile]if profile else result


def remaining(reader,state):
    reader.check_cancelled();left=state['deadline']-time.monotonic()
    if left<=0:raise ValueError('deadline')
    return min(10,left)


def _get(reader,transport,state,ledger,ident,scope,op,rid,version):
    """Fixed ARM GET only, uncached and DEBUG-suppressed; raw errors never read."""
    remaining(reader,state)
    if state['calls']>=MAX_CALLS:raise ValueError('call_limit')
    state['calls']+=1;path=rid+'?api-version='+version
    proof={'id':'ml-asset-read:'+uuid4().hex,'identity':ident,'scope':scope,'capture':state['capture'],'operation':op,
        'method':'GET','origin':'arm','request':_fingerprint('GET\nmanagement.azure.com\n'+path),'version':version,
        'tenant':None,'principal':None,'bound':False,'status':'unavailable','bytes':0,'native_request':None}
    ledger.append(proof);connection=response=None
    try:
        token=storage._token(transport,ARM,state);proof.update(**state['authority'])
        connection=http.client.HTTPSConnection('management.azure.com',timeout=remaining(reader,state));connection.set_debuglevel(0)
        connection.request('GET',path,body=None,headers={'Authorization':'Bearer '+token,'Accept':'application/json','Accept-Encoding':'identity'});del token
        response=connection.getresponse()
        if response.status!=200 or response.getheader('Location')or response.getheader('Link')or response.getheader('Content-Encoding')not in(None,'','identity')or response.getheader('Content-Range')or response.getheader('Transfer-Encoding'):raise ValueError('native_unavailable')
        if (response.getheader('Content-Type')or'').split(';')[0].lower()!='application/json':raise ValueError('native_type')
        length=response.getheader('Content-Length')
        if not isinstance(length,str)or not re.fullmatch('[0-9]{1,8}',length)or not 1<=int(length)<=MAX_ARM:raise ValueError('native_bound')
        request=response.getheader('x-ms-request-id')
        if not isinstance(request,str)or not re.fullmatch('[A-Za-z0-9-]{1,128}',request):raise ValueError('native_provenance')
        proof['native_request']=_fingerprint(request);raw=bytearray()
        while True:
            timeout=remaining(reader,state)
            if getattr(connection,'sock',None)is not None:connection.sock.settimeout(timeout)
            chunk=response.read(min(16384,MAX_ARM+1-len(raw)))
            if not isinstance(chunk,bytes):raise ValueError('native_stream')
            if not chunk:break
            raw.extend(chunk);state['bytes']+=len(chunk);proof['bytes']=len(raw)
            if len(raw)>MAX_ARM or state['bytes']>MAX_TOTAL:raise ValueError('byte_limit')
        if len(raw)!=int(length):raise ValueError('native_partial')
        data=json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs,parse_constant=lambda _:(_ for _ in()).throw(ValueError('native_number')))
        if not isinstance(data,dict)or any(k in data for k in('error','nextLink','partial','_partial','_coverage','continuationToken')):raise ValueError('native_partial')
        proof['status']='collected';return data
    finally:
        if response is not None:response.close()
        if connection is not None:connection.close()


def _storage_read(reader,transport,state,ledger,ident,target,op,method,host,path,expected=None):
    """Exact existing supported storage GET/HEAD, with the same parent deadline."""
    remaining(reader,state)
    if state['calls']>=MAX_CALLS:raise ValueError('call_limit')
    state['calls']+=1
    child={**state,'calls':0,'bytes':0};receipts=[]
    try:
        return storage._read(reader,transport,child,receipts,target,op,host,path,method,MAX_CONTENT if host!='management.azure.com'else MAX_ARM,expected=expected)
    finally:
        state['authority']=child.get('authority');state['bytes']+=child['bytes']
        for receipt in receipts:
            receipt=deepcopy(receipt)
            receipt.update(identity=ident,request=receipt['request'].removeprefix('storage-source-request:'),native_request=receipt['native_request'].removeprefix('storage-source-response:')if receipt['native_request']else None)
            receipt.pop('http_status');ledger.append(receipt)
        if state['bytes']>MAX_TOTAL:raise ValueError('byte_limit')


def _asset(data,rid,profile):
    props=_bound(data,rid,SERVICE+'/workspaces/'+PROFILES[profile]['asset']+'/versions')
    if data['id'].rsplit('/',3)[-3:]!=rid.rsplit('/',3)[-3:]or data['name']!=rid.rsplit('/',1)[1]:raise ValueError('asset_case')
    if props.get('provisioningState')not in(None,'Succeeded')or props.get('isArchived',False)is not False:raise ValueError('asset_unavailable')
    return props


def _workspace(data,rid,tenant):
    p=_bound(data,rid,SERVICE+'/workspaces')
    if p.get('provisioningState')!='Succeeded'or str(p.get('tenantId','')).casefold()!=tenant.casefold()or not isinstance(p.get('workspaceId'),str)or not re.fullmatch(GUID,p['workspaceId'],re.I):raise ValueError('workspace_unbound')
    return _fingerprint(p['workspaceId'].casefold())


def code_binding(properties,target,workspace,datastore,uri=None,exact_relative=None):
    """Native URI association only: canonical paths, exact storage parent, no SAS."""
    st=target['storage'];service,scope,rid,account,container,path,version,_=storage.parse(st)
    name=target['datastore'];store_id=workspace+'/datastores/'+name
    p=_bound(datastore,store_id,SERVICE+'/workspaces/datastores')
    if datastore['name']!=name or datastore['id'].rsplit('/',1)[1]!=name:raise ValueError('datastore_case')
    credentials=p.get('credentials')
    if not isinstance(credentials,dict)or credentials.get('credentialsType')not in('None','AccountKey','Sas','ServicePrincipal','Certificate'):raise ValueError('datastore_metadata')
    # Ordinary Get metadata may contain safe stored-auth discriminators. Never
    # use them for storage auth; fail closed on an unexpected credential body.
    typ=credentials['credentialsType'];secrets=credentials.get('secrets')
    safe={'credentialsType','secrets'}|({'authorityUrl','clientId','resourceUrl','tenantId','thumbprint'}if typ in('ServicePrincipal','Certificate')else set())
    if set(credentials)-safe or secrets not in(None,{}, {'secretsType':typ}):raise ValueError('unexpected_protected_payload')
    if (p.get('datastoreType')!=('AzureBlob'if service=='blob'else'AzureFile')or p.get('accountName')!=account
            or p.get('containerName'if service=='blob'else'fileShareName')!=container or p.get('endpoint')!='core.windows.net'
            or p.get('protocol')!='https'or p.get('subscriptionId','').casefold()!=scope.rsplit('/',1)[1].casefold()
            or p.get('resourceGroup','').casefold()!=rid.split('/')[4].casefold()):raise ValueError('datastore_unbound')
    uri=properties.get('codeUri')if uri is None else uri
    if not isinstance(uri,str)or not 1<=len(uri)<=2048 or any(c in uri for c in('%','?','#','\\','\r','\n')):raise ValueError('unsupported_code_uri')
    prefixes=['azureml://datastores/'+name+'/paths/',
        'azureml://subscriptions/'+scope.rsplit('/',1)[1]+'/resourcegroups/'+workspace.split('/')[4]+'/workspaces/'+workspace.rsplit('/',1)[1]+'/datastores/'+name+'/paths/',
        'https://'+account+'.'+service+'.core.windows.net/'+container+'/']
    roots=[uri[len(prefix):]for prefix in prefixes if uri.startswith(prefix)]
    if len(roots)!=1:raise ValueError('unsupported_code_uri')
    root=roots[0];folder=root.endswith('/');canonical=root[:-1]if folder else root
    # Same conservative character/path grammar as selected storage; reject even encoded aliases.
    storage.parse({**st,'object':canonical})
    if exact_relative is None:
        if (folder and not path.startswith(canonical+'/'))or(not folder and path!=canonical):raise ValueError('file_outside_code_uri')
    elif not folder or path!=canonical+'/'+exact_relative:raise ValueError('file_outside_build_context')
    return _fingerprint(json.dumps({k:p[k]for k in('datastoreType','accountName','endpoint','protocol','subscriptionId','resourceGroup')},sort_keys=True)+'\n'+uri)


def build_binding(properties,target,workspace,datastore):
    """Bind one declared Dockerfile under one native blob build context."""
    build=properties.get('build')
    if not isinstance(build,dict):raise ValueError('unsupported_build')
    dockerfile=build.get('dockerfilePath')
    if (not isinstance(dockerfile,str)or not 1<=len(dockerfile)<=512
            or dockerfile.startswith('/')or any(c in dockerfile for c in('%','?','#','\\','\r','\n'))
            or any(p in('','.', '..')for p in dockerfile.split('/'))):raise ValueError('unsupported_dockerfile')
    uri=build.get('contextUri')
    if not isinstance(uri,str):raise ValueError('unsupported_build_context')
    association=code_binding(properties,target,workspace,datastore,uri=uri,exact_relative=dockerfile)
    return _fingerprint(association+'\n'+dockerfile)


def _job(data,target,code_rid):
    rid=target['job_resource_id'];props=_bound(data,rid,SERVICE+'/workspaces/jobs')
    if (data.get('name')!=rid.rsplit('/',1)[1] or data.get('id','').rsplit('/',1)[1]!=rid.rsplit('/',1)[1]
            or props.get('jobType')!='Command' or props.get('codeId')!=code_rid):
        raise ValueError('job_code_unbound')
    return _fingerprint(json.dumps(data,sort_keys=True,separators=(',',':'),allow_nan=False))


def _one(reader,transport,state,ledger,profile,target,scope):
    p=PROFILES[profile];ident=identity(profile,target);_,rid,workspace=parse(profile,target);start=len(ledger)
    build=profile=='environment'and 'storage'in target
    external=profile=='code'or build
    marker={'schema':SCHEMA,'identity':ident,'scope':scope,'capture':state['capture'],'profile':profile,'complete':False,'native_complete':False,
        'workspace_binding':None,'association_binding':None,'object_binding':None,'storage_service':target['storage']['service']if external else None,
        'immutable_source_proven':False,'parts':[],'leaks':[],'source_requests':[],'verification':'not_attempted'}
    job_bound=profile=='code'and 'job_resource_id'in target
    if job_bound:marker['job_binding']=None
    try:
        def get(op,path,version=API):return reader.call(_get,reader,transport,state,ledger,ident,scope,op,path,version)
        sub=get('subscription',scope,'2022-12-01');storage._bound_subscription(sub,scope,state);ledger[-1]['bound']=True;del sub
        binding=_workspace(get('workspace_before',workspace,WORKSPACE_API),workspace,state['authority']['tenant']);ledger[-1]['bound']=True;marker['workspace_binding']=binding
        if job_bound:
            marker['job_binding']=_job(get('job_before',target['job_resource_id'],'2024-04-01'),target,rid)
            ledger[-1]['bound']=True
        props=_asset(get('asset_before',rid),rid,profile);ledger[-1]['bound']=True
        if profile=='environment'and not build:
            value=props.get('condaFile')
            if not isinstance(value,str)or value.strip().lower()in('','***','[redacted]','<redacted>')or '@microsoft.keyvault('in value.lower():raise ValueError('inline_unavailable')
            if not re.search(r'(?m)^\s*dependencies\s*:',value)or '\n'not in value:raise ValueError('unsupported_conda_inline')
            raw=value.encode('utf-8');storage.text(raw)
            if len(raw)>MAX_CONTENT:raise ValueError('content_bound')
            association=_fingerprint(value);marker['association_binding']=association;del value
        else:
            st=target['storage'];store=workspace+'/datastores/'+target['datastore']
            bind=build_binding if build else code_binding
            association=bind(props,target,workspace,get('datastore_before',store));ledger[-1]['bound']=True
            marker['association_binding']=association
            def read(op,method,host,path,expected=None):return reader.call(_storage_read,reader,transport,state,ledger,ident,st,op,method,host,path,expected)
            native=read('account','GET','management.azure.com',st['resource_id']+'?api-version='+storage.ARM_VERSION);storage._bound_account(native,st);ledger[-1]['bound']=True;del native
            host,path=storage.data_route(st)
            before=read('properties_before','HEAD',host,path)
            raw=read('content','GET',host,path,before)
            after=read('properties_after','HEAD',host,path)
            if before!=after:raise ValueError('object_changed')
            marker['object_binding']=_fingerprint(json.dumps(before,sort_keys=True));storage.text(raw)
            if bind(props,target,workspace,get('datastore_after',store))!=association:raise ValueError('datastore_changed')
            ledger[-1]['bound']=True
        del props
        closing=_asset(get('asset_after',rid),rid,profile);ledger[-1]['bound']=True
        if profile=='environment'and not build:
            if closing.get('condaFile')is None or _fingerprint(closing['condaFile'])!=association:raise ValueError('asset_changed')
        elif bind(closing,target,workspace,get('datastore_final',store))!=association:raise ValueError('asset_changed')
        if external:ledger[-1]['bound']=True
        if _workspace(get('workspace_after',workspace,WORKSPACE_API),workspace,state['authority']['tenant'])!=binding:raise ValueError('workspace_changed')
        ledger[-1]['bound']=True;del closing
        marker['native_complete']=True;remaining(reader,state)
        result=scan_with_source(scan_content, raw,ident+'.'+profile,timeout=remaining(reader,state)/2,_redact_values=lambda values:remember(reader,'configuration_secret_redactions',values), source={**target_source(target, scope=scope), 'resource_id':ident});size=len(raw);del raw
        marker['parts']=[{'bytes':size,'complete':result['complete'],'engines':deepcopy(result['engines'])}]
        leaks=merge_leaks(result['leaks'])
        if len(leaks)>MAX_LEAKS or sum(len(l['locations'])for l in leaks)>MAX_LOCATIONS:raise ValueError('leak_bound')
        marker['leaks']=leaks;remaining(reader,state);marker['complete']=result['complete']is True
        if job_bound:
            if _job(get('job_after',target['job_resource_id'],'2024-04-01'),target,rid)!=marker['job_binding']:
                raise ValueError('job_changed')
            ledger[-1]['bound']=True
    except Exception:marker['complete']=False
    marker['source_requests']=[r['id']for r in ledger[start:]]
    return {'id':ident,MARKER:marker,'_provenance':{'scope':scope,'capture':state['capture'],'source_requests':marker['source_requests'][:]}}


def operations(profile,build=False,job=False):
    external=profile=='code'or build
    return ('subscription','workspace_before')+(('job_before',)if job else())+('asset_before',)+(('datastore_before','account','properties_before','content','properties_after','datastore_after')if external else())+('asset_after',)+(('datastore_final',)if external else())+('workspace_after',)+(('job_after',)if job else())


def collect(reader,transport,scopes,wanted,options):
    targets=selected_targets(options,scopes);reader.ml_asset_secret_metadata={}
    if not hasattr(reader,'configuration_secret_redactions'):reader.configuration_secret_redactions=set()
    state={'capture':'ml-asset-capture:'+uuid4().hex,'calls':0,'bytes':0,'deadline':time.monotonic()+MAX_SECONDS,'authority':None}
    for name,p in PROFILES.items():
        if p['kind']not in wanted:continue
        ledger=[];kind=p['kind'];reader.ml_asset_secret_metadata.update({kind+'_authorized':enabled(options,name),kind+'_capture':state['capture'],kind+'_receipts':ledger,
            kind+'_selection':{s:[identity(name,t)for t in targets[name]if parse(name,t)[0].casefold()==s.casefold()]for s in scopes}})
        if not enabled(options,name):continue
        for scope in scopes:
            selected=[t for t in targets[name]if parse(name,t)[0].casefold()==scope.casefold()]
            if selected:
                def fetch(selected=selected,scope=scope,name=name,ledger=ledger):yield[_one(reader,transport,state,ledger,name,t,scope)for t in selected]
                reader.run([(kind,scope,SERVICE,fetch)])


def final_snapshot(reader,snapshot):
    snapshot.setdefault('metadata',{}).update(getattr(reader,'ml_asset_secret_metadata',{}))
    from .azure_databricks_notebook_secret_indicators import final_snapshot as existing
    return existing(reader,snapshot)
