"""Independent native ARM declaration inputs; no historical CASES as provider data."""
from copy import deepcopy
from dataclasses import replace
import json
import socket
from urllib.parse import parse_qs,urlsplit
import pytest
from peaso.checks import CHECKS
from peaso.checks import azure_automation_aci_metadata_review_20261020 as check
from peaso.collectors import azure,azure_automation_aci_metadata_native_20261020 as native
from peaso.engine import evaluate_snapshot,plan_collection

SUB='11111111-1111-1111-1111-111111111111';TENANT='22222222-2222-2222-2222-222222222222'
PRINCIPAL='33333333-3333-3333-3333-333333333333';CUSTOMER='44444444-4444-4444-4444-444444444444'
SCOPE='/subscriptions/'+SUB
SENTINEL='NATIVE_WORKSPACE_KEY_SENTINEL_NOT_A_SECRET'
TYPES={check.AUTOMATION:('automation_account','Microsoft.Automation/automationAccounts','2023-11-01','automation_cmk_declaration'),
       check.ACI:('container_group','Microsoft.ContainerInstance/containerGroups','2023-05-01','aci_log_analytics_declaration')}

@pytest.fixture(autouse=True)
def no_live(monkeypatch):
 attempts=[]
 def blocked(*a,**kw):attempts.append('socket/DNS/auth');raise AssertionError('Native declarations forbid live IO')
 for n in ('create_connection','getaddrinfo','gethostbyname','gethostbyname_ex','gethostbyaddr','getnameinfo'):monkeypatch.setattr(socket,n,blocked)
 for n in ('connect','connect_ex','sendto'):monkeypatch.setattr(socket.socket,n,blocked)
 monkeypatch.setattr(azure,'credential_for',blocked);monkeypatch.setattr(azure,'AzureTransport',blocked)
 yield
 assert not attempts,attempts


def resource(cid,mode='good'):
 kind,typ,version,evidence=TYPES[cid];rid=SCOPE+'/resourceGroups/native/providers/'+typ+'/native-account'
 obj={'id':rid,'name':'native-account','type':typ,'location':'eastus','properties':{}}
 if cid==check.AUTOMATION:
  obj['identity']={'type':'SystemAssigned','principalId':PRINCIPAL,'tenantId':TENANT}
  obj['properties']={'state':'Ok','encryption':{'keySource':'Microsoft.Keyvault','keyVaultProperties':{'keyName':'native-key','keyvaultUri':'https://native-vault.vault.azure.net','keyVersion':'7c73556c521340209371eaf623cc099d'}}}
  path='properties.encryption.keySource'
  if mode=='bad':obj['properties']['encryption']['keySource']='Microsoft.Automation'
 else:
  obj['properties']={'provisioningState':'Succeeded','osType':'Linux','containers':[{'name':'native','properties':{'image':'mcr.microsoft.com/azuredocs/aci-helloworld','resources':{'requests':{'cpu':1,'memoryInGB':1}},'environmentVariables':[{'name':'LITERAL','value':'VALUE_SENTINEL'},{'name':'SECURE','secureValue':'SECURE_SENTINEL'}]}}],
   'diagnostics':{'logAnalytics':{'workspaceId':CUSTOMER,'logType':'ContainerInsights','workspaceKey':SENTINEL}}}
  path='properties.diagnostics.logAnalytics.workspaceId'
  if mode=='bad':obj['properties']['diagnostics']={}
 if mode in ('missing','malformed'):
  target=obj;parts=path.split('.')
  for p in parts[:-1]:target=target[p]
  if mode=='missing':target.pop(parts[-1])
  else:target[parts[-1]]=[42]
 return obj


class NativeHTTP:
 tenant=verified_tenant=TENANT
 def __init__(self,cid,mode,obj):self.cid,self.mode,self.obj=cid,mode,obj;self.calls=[];self.errors=[]
 def request(self,url,*,body=None,audience=azure.ARM):
  p=urlsplit(url);q=parse_qs(p.query);method='POST' if body is not None else 'GET';self.calls.append({'method':method,'url':url,'body':deepcopy(body)})
  kind,typ,version,evidence=TYPES[self.cid]
  try:
   assert p.scheme=='https' and p.netloc=='management.azure.com' and not p.fragment and audience==azure.ARM
   rows=[] if self.mode=='empty' else [deepcopy(self.obj)]
   if self.mode=='foreign':rows[0]['id']=rows[0]['id'].replace(SUB,'99999999-9999-9999-9999-999999999999')
   if p.path=='/providers/Microsoft.ResourceGraph/resources':
    assert method=='POST' and q=={'api-version':['2022-10-01']} and body['subscriptions']==[SUB]
    # ARG discovery is independently projected metadata, not a copied full ACI
    # GET containing workspace credentials. Deciding declarations come from GET.
    return {'data':[{k:r[k] for k in ('id','name','type','location')} for r in rows]}
   assert method=='GET'
   if p.path==SCOPE+'/resources':assert q=={'api-version':['2021-04-01']};return {'value':rows}
   if p.path==SCOPE+'/providers/'+typ:
    assert q.get('api-version')==[version]
    if self.mode=='denied':raise azure.AzureReadError('forbidden',403)
    if q.get('page')==['2']:raise azure.AzureReadError('forbidden',403)
    result={'value':rows}
    if self.mode=='partial':result['nextLink']=azure.ARM+p.path+'?api-version='+version+'&page=2'
    return result
   if p.path==self.obj['id']:
    assert q=={'api-version':[version]}
    if self.mode=='get-denied':raise azure.AzureReadError('forbidden',403)
    if self.mode=='deleted':raise azure.AzureReadError('deleted',404)
    if self.mode=='error-body':raise ValueError(SENTINEL)
    return deepcopy(self.obj)
   if p.path==self.obj['id']+'/providers/Microsoft.Insights/diagnosticSettings':
    assert q=={'api-version':['2021-05-01-preview']};return {'value':[]}
   if self.cid==check.AUTOMATION and p.path in (self.obj['id']+'/variables',self.obj['id']+'/webhooks'):
    assert q=={'api-version':['2015-10-31' if p.path.endswith('/webhooks') else '2023-11-01']};return {'value':[]}
   raise AssertionError('Unexpected native metadata route '+p.path)
  except azure.AzureReadError:raise
  except AssertionError as exc:self.errors.append(str(exc));raise


def run(cid,mode,record_property,mutate=None,options=None):
 obj=resource(cid,mode)
 if mutate:mutate(obj)
 api=NativeHTTP(cid,mode,obj);deps=next(c.dependencies for c in CHECKS if c.id==cid)
 snap=azure.collect({'provider':'azure','scopes':[SUB],'options':{'concurrency':1,'retries':0,**(options or {})}},deps,transport=api)
 assert not api.errors,api.errors
 before=deepcopy(snap);out=evaluate_snapshot(snap,checks=[cid],include_not_applicable=True);assert snap==before
 rows=[r for r in out['findings'] if r['check_id']==cid];assert rows
 record_property('native_receipt',json.dumps({'check_id':cid,'mode':mode,'calls':api.calls,'statuses':[r['status'] for r in rows],
  'evidence':[r['evidence'] for r in rows],'envelopes':[{k:c[k] for k in ('type','scope','status')} for c in snap['collections']]},sort_keys=True))
 return snap,rows


@pytest.mark.parametrize('cid',[check.AUTOMATION,check.ACI])
@pytest.mark.parametrize('mode',['good','bad','missing','malformed','denied','get-denied','deleted','partial','foreign','empty','error-body'])
def test_native_metadata_matrix(cid,mode,record_property):
 snap,rows=run(cid,mode,record_property);statuses={r['status'] for r in rows}
 if mode=='good':assert statuses=={'PASS'},rows
 elif mode=='bad':assert statuses=={'FAIL'},rows
 elif mode=='empty':assert statuses<={'EMPTY','NOT_APPLICABLE','UNKNOWN'},rows
 else:assert statuses<={'UNKNOWN','DENIED'},rows
 assert SENTINEL not in json.dumps([snap,rows])


def test_native_workspace_key_hidden_from_snapshot_and_actual_request_cache(record_property,monkeypatch):
 caches=[];original=native.collect
 def capture(reader,request,scopes,wanted):
  original(reader,request,scopes,wanted)
  for cell in request.__closure__ or ():
   value=cell.cell_contents
   if isinstance(value,dict) and any(isinstance(k,tuple) and len(k)==3 for k in value):caches.append(deepcopy(value))
 monkeypatch.setattr(native,'collect',capture)
 snap,rows=run(check.ACI,'good',record_property)
 assert caches and SENTINEL not in repr(caches)
 assert SENTINEL not in json.dumps([snap,rows])
 group=next(c['items'][0] for c in snap['collections'] if c['type']=='container_group')
 env=group['properties']['containers'][0]['properties']['environmentVariables']
 assert env==[{'name':'LITERAL','value':'[REDACTED]'},{'name':'SECURE','secureValue':'[REDACTED]'}]


@pytest.mark.parametrize('cid',[check.AUTOMATION,check.ACI])
@pytest.mark.parametrize('field',['id','name','type','properties'])
def test_native_get_identity_mismatch(cid,field,record_property,monkeypatch):
 original=NativeHTTP.request
 def request(self,url,**kw):
  result=original(self,url,**kw)
  if urlsplit(url).path==self.obj['id']:
   if field=='id':result['id']=result['id'].replace(SUB,'99999999-9999-9999-9999-999999999999')
   elif field=='name':result['name']='different'
   elif field=='type':result['type']='Microsoft.Storage/storageAccounts'
   else:result['properties']=[]
  return result
 monkeypatch.setattr(NativeHTTP,'request',request)
 _,rows=run(cid,'good',record_property);assert {r['status'] for r in rows}=={'UNKNOWN'},rows


@pytest.mark.parametrize('field,value,expected',[
 ('keyName','','FAIL'),('keyVersion','','FAIL'),('keyvaultUri','','FAIL'),('keyName',[42],'UNKNOWN'),
 ('keyvaultUri','http://native.vault.azure.net','UNKNOWN'),('keyvaultUri','https://native.vault.azure.net.evil.example','UNKNOWN'),
 ('keyvaultUri','https://native.vault.azure.net/keys/key','UNKNOWN'),('keyvaultUri','https://user@native.vault.azure.net','UNKNOWN')])
def test_native_automation_reference_fields(field,value,expected,record_property):
 _,rows=run(check.AUTOMATION,'good',record_property,lambda o:o['properties']['encryption']['keyVaultProperties'].__setitem__(field,value))
 assert {r['status'] for r in rows}=={expected},rows


@pytest.mark.parametrize('value,expected',[('None','FAIL'),('UserAssigned','UNKNOWN'),('SystemAssigned, UserAssigned','PASS'),('Unrecognized','UNKNOWN')])
def test_native_automation_attached_identity(value,expected,record_property):
 _,rows=run(check.AUTOMATION,'good',record_property,lambda o:o['identity'].__setitem__('type',value))
 assert {r['status'] for r in rows}=={expected},rows


@pytest.mark.parametrize('workspace,mode,expected',[(CUSTOMER,'ContainerInstanceLogs','PASS'),(CUSTOMER.upper(),'ContainerInsights','PASS'),
 ('','ContainerInsights','FAIL'),(SCOPE+'/resourceGroups/r/providers/Microsoft.OperationalInsights/workspaces/native','ContainerInsights','UNKNOWN'),
 ('00000000-0000-0000-0000-000000000000','ContainerInsights','UNKNOWN'),(CUSTOMER,'Unsupported','UNKNOWN')])
def test_native_aci_customer_uuid_and_log_type(workspace,mode,expected,record_property):
 def mutate(o):o['properties']['diagnostics']['logAnalytics'].update(workspaceId=workspace,logType=mode)
 _,rows=run(check.ACI,'good',record_property,mutate);assert {r['status'] for r in rows}=={expected},rows


@pytest.mark.parametrize('cid',[check.AUTOMATION,check.ACI])
@pytest.mark.parametrize('branch',['pass','fail','unknown'])
def test_native_fixture_capture(cid,branch,record_property,monkeypatch):
 from peaso import engine
 original=next(c for c in CHECKS if c.id==cid);captures=[]
 def capture(item,index):
  status,evidence=original.evaluate(item,index);captures.append({'item':deepcopy(item),'index':deepcopy(index),'status':status,'evidence':deepcopy(evidence)});return status,evidence
 monkeypatch.setattr(engine,'_registry',lambda:[replace(c,evaluate=capture) if c.id==cid else c for c in CHECKS])
 run(cid,{'pass':'good','fail':'bad','unknown':'missing'}[branch],record_property)
 assert len(captures)==1 and captures[0]['status']=={'pass':'PASS','fail':'FAIL','unknown':'UNKNOWN'}[branch]
 record_property('native_fixture',json.dumps({'check_id':cid,'branch':branch,**captures[0]},sort_keys=True))


@pytest.mark.parametrize('cid',[check.AUTOMATION,check.ACI])
@pytest.mark.parametrize('change',['marker','numeric-complete','write','scope','operation','credential','customer','duplicate','request'])
def test_native_bound_consumer_tampering(cid,change,record_property,monkeypatch):
 from peaso import engine
 original=next(c for c in CHECKS if c.id==cid);captured=[]
 def capture(item,index):captured.append((deepcopy(item),deepcopy(index)));return original.evaluate(item,index)
 monkeypatch.setattr(engine,'_registry',lambda:[replace(c,evaluate=capture) if c.id==cid else c for c in CHECKS])
 run(cid,'good',record_property);item,index=captured[0];own=index['collections'][TYPES[cid][3]][0];row=own['items'][0]
 if change=='marker':row.pop(native.MARKER)
 elif change=='numeric-complete':row[native.MARKER]['complete']=1
 elif change=='write':row['_provenance']['read_only']=False
 elif change=='scope':row['_provenance']['scope']='/subscriptions/foreign'
 elif change=='operation':row['_provenance']['source_operation']='Update'
 elif change in ('credential','customer'):row['_provenance'][change+'_context_id']='foreign'
 elif change=='duplicate':own['items'].append(deepcopy(row))
 else:row[native.MARKER]['request_uri']='https://evil.example/metadata'
 assert original.evaluate(item,index)[0]=='UNKNOWN'


@pytest.mark.parametrize('cid',[check.AUTOMATION,check.ACI])
@pytest.mark.parametrize('options',[{'max_calls':1},{'collection_deadline_seconds':0.0000001},{'_cancel_check':lambda:True}])
def test_native_limits_remain_unresolved(cid,options,record_property):
 _,rows=run(cid,'good',record_property,options=options);assert {r['status'] for r in rows}<={'UNKNOWN','DENIED'},rows


@pytest.mark.parametrize('field',['keyName','keyVersion','keyvaultUri'])
def test_native_automation_omitted_reference_is_not_manufactured(field,record_property):
 _,rows=run(check.AUTOMATION,'good',record_property,lambda o:o['properties']['encryption']['keyVaultProperties'].pop(field))
 assert {r['status'] for r in rows}=={'UNKNOWN'},rows


@pytest.mark.parametrize('field',['workspaceId','logType'])
def test_native_aci_omitted_workspace_field_is_unknown(field,record_property):
 _,rows=run(check.ACI,'good',record_property,lambda o:o['properties']['diagnostics']['logAnalytics'].pop(field))
 assert {r['status'] for r in rows}=={'UNKNOWN'},rows


@pytest.mark.parametrize('cid',[check.AUTOMATION,check.ACI])
def test_native_public_scope_selection_adds_only_own_evidence(cid,record_property):
 deps=next(c.dependencies for c in CHECKS if c.id==cid);wanted=plan_collection({'provider':'azure','scopes':[SUB],'checks':[cid]})
 assert TYPES[cid][3] in wanted and {k for k in native.CONTRACTS if k in wanted}=={TYPES[cid][3]}
 assert native.required_types(set(deps))=={TYPES[cid][0]}
 snap,_=run(cid,'good',record_property);assert {c['type'] for c in snap['collections']}&set(native.CONTRACTS)=={TYPES[cid][3]}


@pytest.mark.parametrize('url,expected',[
 ('https://management.azure.com'+SCOPE+'/providers/Microsoft.ContainerInstance/containerGroups?api-version=2023-05-01',True),
 ('https://management.azure.com'+SCOPE+'/resourceGroups/r/providers/Microsoft.ContainerInstance/containerGroups?api-version=2023-05-01',True),
 ('https://management.azure.com'+SCOPE+'/resourceGroups/r/providers/Microsoft.ContainerInstance/containerGroups/g?api-version=2023-05-01',True),
 ('https://evil.example'+SCOPE+'/providers/Microsoft.ContainerInstance/containerGroups?api-version=2023-05-01',False),
 ('https://management.azure.com'+SCOPE.replace(SUB,'99999999-9999-9999-9999-999999999999')+'/providers/Microsoft.ContainerInstance/containerGroups?api-version=2023-05-01',False),
 ('https://management.azure.com'+SCOPE+'/resourceGroups/r/providers/Microsoft.ContainerInstance/containerGroups/g/containers/c/logs?api-version=2023-05-01',False),
 ('https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01',False),
 ('https://management.azure.com'+SCOPE+'/providers/Microsoft.ContainerInstance/containerGroups?api-version=unknown',False)])
def test_native_aci_cache_route_is_structural_and_selected(url,expected):assert native.aci_metadata_route(url,[SCOPE]) is expected
