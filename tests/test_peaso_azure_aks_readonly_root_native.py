"""Actual Kubernetes API schemas through ARM-bound Azure collection and signed engine."""
import copy,json
from types import SimpleNamespace
import pytest
from peaso.collectors import azure,k8s,collect_live
from peaso.collectors import azure_aks_workloads_native as native
from peaso.engine import collect_snapshot,evaluate_snapshot,plan_collection
from peaso.server.validation import validate_connector
from tests.test_peaso_azure_aks_workloads_native import ca,fixture,obj,RID,HOST,TOKEN
from tests.test_peaso_azure_bulk_native import Transport,SCOPE,SUB
CHECK=native.READ_ONLY_ROOT
KINDS=tuple(native.WORKLOADS)
SECRET='workload-private-literal-not-metadata'
REFERENCE='private-secret-reference-not-metadata'

def case(ca,mode='good',affected='aks_pod'):
 routes,_,options,auth,_=fixture(ca)
 # Root-filesystem policy has no custom owner criterion. Explicit auth binds each cluster.
 options.pop('compliance_parameters')
 routes[SCOPE+'/providers/Microsoft.Kubernetes/connectedClusters']={'value':[]}
 namespaces=[obj('Namespace','kube-system'),obj('Namespace','default')]
 rows={};schemas={}
 for kind,(path,typ,version,specpath)in native.WORKLOADS.items():
  workload=obj(typ,'app','default');workload['apiVersion']=version
  container={'name':'app','securityContext':{'readOnlyRootFilesystem':True},'env':[{'name':'PASSWORD','value':SECRET},{'name':'REFERENCE','valueFrom':{'secretKeyRef':{'name':REFERENCE,'key':'password'}}}],'command':[SECRET],'args':[SECRET]}
  spec={'containers':[container]};node=workload
  for key in specpath.split('.')[:-1]:node=node.setdefault(key,{})
  node[specpath.split('.')[-1]]=spec
  if kind==affected:
   if mode=='false':container['securityContext']['readOnlyRootFilesystem']=False
   if mode=='omitted_flag':container['securityContext'].pop('readOnlyRootFilesystem')
   if mode=='omitted_security':container.pop('securityContext')
   if mode=='init_true':spec['initContainers']=[{'name':'setup','securityContext':{'readOnlyRootFilesystem':True}}]
   if mode=='ephemeral_true':spec['ephemeralContainers']=[{'name':'debug','securityContext':{'readOnlyRootFilesystem':True}}]
   if mode=='init_false':spec['initContainers']=[{'name':'setup','securityContext':{'readOnlyRootFilesystem':False}}]
   if mode=='ephemeral_false':spec['ephemeralContainers']=[{'name':'debug','securityContext':{'readOnlyRootFilesystem':False}}]
   if mode=='bad_flag':container['securityContext']['readOnlyRootFilesystem']=1
   if mode=='null_flag':container['securityContext']['readOnlyRootFilesystem']=None
   if mode=='string_flag':container['securityContext']['readOnlyRootFilesystem']='true'
   if mode=='null_security':container['securityContext']=None
   if mode=='null_init':spec['initContainers']=None
   if mode=='null_ephemeral':spec['ephemeralContainers']=None
   if mode=='bad_init':spec['initContainers']={}
   if mode=='duplicate_name':spec['initContainers']=[{'name':'app','securityContext':{'readOnlyRootFilesystem':True}}]
   if mode=='missing_containers':spec.pop('containers')
   if mode=='empty_containers':spec['containers']=[]
   if mode=='wrong_object_kind':workload['kind']='Service'
   if mode=='wrong_object_version':workload['apiVersion']='apps/v1beta1'
   if mode=='missing_uid':workload['metadata'].pop('uid')
   if mode=='foreign_namespace':workload['metadata']['namespace']='foreign'
  rows[path]=[workload,copy.deepcopy(workload)]if mode=='duplicate_uid'and kind==affected else[workload]
  if mode=='empty':rows[path]=[]
  schemas[path]=(version,typ+'List')
 if mode=='missing_credential':auth.pop('aks_workloads')
 if mode=='foreign_endpoint':routes[RID]['properties']['fqdn']='other.example.org'
 if mode=='tenant_mismatch':routes['/subscriptions']['value'][0]['tenantId']='foreign'
 if mode=='arc':routes[SCOPE+'/providers/Microsoft.Kubernetes/connectedClusters']={'value':[{'id':SCOPE+'/resourceGroups/rg/providers/Microsoft.Kubernetes/connectedClusters/arc'}]}
 if mode=='arc_denied':routes[SCOPE+'/providers/Microsoft.Kubernetes/connectedClusters']=azure.AzureReadError('forbidden',403)
 if mode=='page_cap':options['max_pages']=1
 if mode=='call_cap':options['max_calls']=4
 if mode=='resource_cap':options['max_resources']=3
 class Api:
  def __init__(self):self.calls=[];self.closed=False;self.uid_reads=0
  def get_json(self,path,params):
   self.calls.append((path,copy.deepcopy(params)))
   if path=='/api/v1/namespaces/kube-system':
    self.uid_reads+=1;row=copy.deepcopy(namespaces[0])
    if mode=='rotated_uid'and self.uid_reads>1:row['metadata']['uid']='foreign-cluster'
    return row
   if path=='/api/v1/namespaces':return {'apiVersion':'v1','kind':'NamespaceList','metadata':{'resourceVersion':'42','continue':''},'items':copy.deepcopy(namespaces)}
   assert path in schemas,('unexpected API',path)
   if mode=='denied'and path==native.WORKLOADS[affected][0]:raise azure.AzureReadError('forbidden',403)
   version,typ=schemas[path];result={'apiVersion':version,'kind':typ,'metadata':{'resourceVersion':'42','continue':''},'items':copy.deepcopy(rows[path])}
   if path==native.WORKLOADS[affected][0]:
    if mode=='wrong_list_kind':result['kind']='PodList'if typ!='PodList'else'ServiceList'
    if mode=='wrong_list_version':result['apiVersion']='foreign/v1'
    if mode=='missing_list_version':result['metadata'].pop('resourceVersion')
    if mode in('paged','partial','repeated_token','version_changed','page_cap'):
     if params.get('continue'):
      if mode=='partial':raise azure.AzureReadError('forbidden',403)
      result['items']=[]
      if mode=='repeated_token':result['metadata']['continue']='next'
      if mode=='version_changed':result['metadata']['resourceVersion']='43'
     else:result['metadata']['continue']='next'
   return result
  def close(self):self.closed=True
 return routes,options,auth,Api

def capture(monkeypatch,ca,mode='good',affected='aks_pod',via='direct'):
 routes,options,auth,Api=case(ca,mode,affected);api=Transport(routes);api.close=lambda:None;clients=[]
 def new_client(context):
  assert context['server']=='https://'+HOST and context['token']==TOKEN and context['_disable_proxy']is True
  result=Api();clients.append(result);return result
 monkeypatch.setattr(k8s,'_new_api',new_client);original=azure.collect
 def collect(connector,requirements=None):return original(connector,requirements,transport=api)
 connector={'provider':'azure','scopes':[SUB],'auth':auth,'options':options}
 if via=='direct':snapshot=collect(connector,list(KINDS))
 else:
  monkeypatch.setattr(azure,'collect',collect)
  if via=='dispatcher':snapshot=collect_live(connector,list(KINDS))
  else:snapshot=collect_snapshot({'connector':connector,'checks':[CHECK]})
 report=evaluate_snapshot(snapshot,checks=[CHECK],include_not_applicable=True)
 findings=report['findings'];assert len(findings)==1
 assert all(client.closed for client in clients)
 serialized=json.dumps(snapshot)+json.dumps(report)
 assert all(value not in serialized for value in(TOKEN,SECRET,REFERENCE))
 return findings[0]['status'],snapshot,clients

@pytest.mark.parametrize('via',['direct','dispatcher','planner'])
def test_native_complete_six_kind_root_filesystems_pass_public_pipeline(monkeypatch,ca,via):
 status,snapshot,clients=capture(monkeypatch,ca,via=via);assert status=='PASS'
 collections=[c for c in snapshot['collections']if c['type']in KINDS]
 assert len(collections)==6 and all(c['status']=='collected'and len(c['items'])==1 for c in collections)
 assert {path for client in clients for path,_ in client.calls}=={'/api/v1/namespaces','/api/v1/namespaces/kube-system'}|{x[0]for x in native.WORKLOADS.values()}
 assert all('listkeys'not in path.lower()and'/secrets'not in path.lower()and'/exec'not in path.lower()for client in clients for path,_ in client.calls)

@pytest.mark.parametrize('kind',KINDS)
@pytest.mark.parametrize('mode',['false','omitted_flag','omitted_security','init_false'])
def test_native_false_default_or_init_counterexample_fails(monkeypatch,ca,kind,mode):
 assert capture(monkeypatch,ca,mode,kind)[0]=='FAIL'


def test_native_ephemeral_container_false_fails(monkeypatch,ca):
 assert capture(monkeypatch,ca,'ephemeral_false')[0]=='FAIL'

@pytest.mark.parametrize('kind',KINDS)
@pytest.mark.parametrize('mode',['bad_flag','null_flag','null_security','null_init','missing_containers','wrong_object_version','wrong_list_version'])
def test_native_bad_workload_shapes_do_not_claim_pass(monkeypatch,ca,kind,mode):
 assert capture(monkeypatch,ca,mode,kind)[0]=='UNKNOWN'

@pytest.mark.parametrize('mode',['string_flag','null_ephemeral','bad_init','duplicate_name','empty_containers','wrong_object_kind','missing_uid','foreign_namespace','duplicate_uid','wrong_list_kind','missing_list_version','partial','repeated_token','version_changed','page_cap','call_cap','resource_cap','rotated_uid','missing_credential','foreign_endpoint','tenant_mismatch','arc','arc_denied'])
def test_identity_universe_and_partial_read_boundaries(monkeypatch,ca,mode):
 status,_,clients=capture(monkeypatch,ca,mode)
 assert status in('UNKNOWN','DENIED')
 if mode in('foreign_endpoint','missing_credential','tenant_mismatch','arc','arc_denied'):assert not clients

@pytest.mark.parametrize('kind',KINDS)
def test_endpoint_denial_never_becomes_empty_inventory(monkeypatch,ca,kind):
 status,snapshot,_=capture(monkeypatch,ca,'denied',kind)
 assert status in('UNKNOWN','DENIED')
 assert all(c['status']not in('empty','collected')for c in snapshot['collections']if c['type']in KINDS)


def test_native_optional_absent_arrays_are_explicitly_measured_not_null_defaults(monkeypatch,ca):
 status,snapshot,_=capture(monkeypatch,ca);assert status=='PASS'
 for env in snapshot['collections']:
  if env['type']not in KINDS:continue
  row=env['items'][0];path=native.WORKLOADS[env['type']][3];expected=[path+'.initContainers']
  if env['type']=='aks_pod':expected.append(path+'.ephemeralContainers')
  assert row['_provenance']['optional_absent_arrays']==expected
  assert row['_provenance']['cluster_id']==RID.lower()and row['_provenance']['read_only']is True
  assert row['_provenance']['source_operation']==native.WORKLOADS[env['type']][0]+':LIST'
  assert 'env'not in json.dumps(row)and'command'not in json.dumps(row)and'args'not in json.dumps(row)and'secretKeyRef'not in json.dumps(row)


def test_readonly_has_no_new_approval_flags_and_preserves_sibling_owner_authority(monkeypatch,ca):
 routes,options,auth,_=case(ca);options['retries']=1
 options['compliance_policy']={'sw33':{'status':'collected','scope':SCOPE,'backupAlerts':{'responseWindowMinutes':5}}}
 for mode in('local','cognito'):validate_connector('azure',auth,options,SimpleNamespace(auth_mode=mode))
 # Historical local authority timestamps remain untouched rather than being refreshed.
 options['compliance_policy']['sw33'].update({'observed_at':'2026-10-15T00:00:00Z','max_age_seconds':86400})
 def unavailable(context):raise azure.AzureReadError('fixture_explicit_auth_unavailable',401)
 monkeypatch.setattr(k8s,'_new_api',unavailable)
 original=azure.collect
 monkeypatch.setattr(azure,'collect',lambda connector,requirements=None:original(connector,requirements,transport=Transport(routes)))
 snapshot=collect_live({'provider':'azure','scopes':[SUB],'auth':auth,'options':options},list(KINDS))
 # No actual Kubernetes client is opened in this separate unavailable-evidence test.
 assert snapshot['metadata']['compliance_policy']['sw33']==options['compliance_policy']['sw33']
 assert evaluate_snapshot(snapshot,checks=[CHECK])['findings'][0]['status']=='DENIED'


def test_plan_expands_actual_parent_universe_without_selecting_unrelated_workloads():
 planned=set(plan_collection({'connector':{'provider':'azure'},'checks':[CHECK]}))
 assert set(KINDS)|{'aks_cluster','arc_kubernetes_cluster','subscription'}<=planned
 assert 'service'not in planned and'limit_range'not in planned


@pytest.mark.parametrize('kind',KINDS)
def test_native_readonly_init_containers_and_immutable_signed_evaluation(monkeypatch,ca,kind):
 status,snapshot,_=capture(monkeypatch,ca,'init_true',kind)
 assert status=='PASS'
 before=json.dumps(snapshot,sort_keys=True)
 assert evaluate_snapshot(snapshot,checks=[CHECK])['findings'][0]['status']=='PASS'
 assert json.dumps(snapshot,sort_keys=True)==before


def test_native_readonly_ephemeral_container_passes(monkeypatch,ca):
 assert capture(monkeypatch,ca,'ephemeral_true')[0]=='PASS'


def test_native_complete_empty_six_inventories_is_measured_not_unavailable(monkeypatch,ca):
 status,snapshot,_=capture(monkeypatch,ca,'empty')
 assert status=='PASS'
 assert all(c['status']=='empty'and c['items']==[] for c in snapshot['collections']if c['type']in KINDS)
