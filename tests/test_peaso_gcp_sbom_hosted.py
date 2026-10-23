import copy
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso.gcp_sbom_policy import normalize
from peaso.server.validation import validate_connector
SCOPE='projects/demo-project';SERVICE=SCOPE+'/locations/us-central1/services/app'
REVIEW={'status':'collected','scope':SCOPE,'sbomCloudRunServices':[SERVICE]}
AUTH={'method':'token','token':'customer-supplied-token'}
@pytest.mark.parametrize('mode',['cognito','none'])
@pytest.mark.parametrize('count',[1,1000])
def test_actual_hosted_intake_accepts_only_owner_workload_scope_without_mutating(mode,count):
 review={**REVIEW,'sbomCloudRunServices':[SERVICE+str(i) for i in range(count)]};options={'sw52':review};original=copy.deepcopy(options);auth=copy.deepcopy(AUTH)
 validate_connector('gcp',auth,options,SimpleNamespace(auth_mode=mode))
 assert options==original and auth==AUTH
 normalized=normalize(review,[SCOPE]);assert normalized==review and normalized is not review and normalized['sbomCloudRunServices'] is not review['sbomCloudRunServices']

def bad_reviews():
 return [
  None,False,[],{}, {'status':'collected','scope':SCOPE}, {**REVIEW,'status':True},{**REVIEW,'status':'approved'},
  {**REVIEW,'scope':'organizations/123'},{**REVIEW,'scope':'https://example.test/project'}, {**REVIEW,'scope':SCOPE+'\n'},
  {**REVIEW,'scope':'projects/demo-project/extra'}, {**REVIEW,'scope':'projects/../demo-project'},
  {**REVIEW,'sbomCloudRunServices':[]},{**REVIEW,'sbomCloudRunServices':False},{**REVIEW,'sbomCloudRunServices':SERVICE},
  {**REVIEW,'sbomCloudRunServices':[SERVICE,SERVICE]}, {**REVIEW,'sbomCloudRunServices':[SERVICE+str(i) for i in range(1001)]},
  {**REVIEW,'sbomCloudRunServices':[SERVICE.replace(SCOPE,'projects/foreign-project')]},
  {**REVIEW,'sbomCloudRunServices':['https://run.googleapis.com/v2/'+SERVICE]},
  {**REVIEW,'sbomCloudRunServices':['https://attacker.example']},{**REVIEW,'sbomCloudRunServices':[SERVICE+'?url=https://evil.test']},
  {**REVIEW,'sbomCloudRunServices':[SERVICE+'/extra']},{**REVIEW,'sbomCloudRunServices':[SERVICE.replace('/app','/../app')]},
  {**REVIEW,'sbomCloudRunServices':[SERVICE+'\n']},{**REVIEW,'sbomCloudRunServices':[SERVICE+'-']},
  {**REVIEW,'sbomCloudRunServices':[False]},{**REVIEW,'sbomCloudRunServices':[[SERVICE]]},{**REVIEW,'sbomCloudRunServices':[{'name':SERVICE}]},
  {**REVIEW,'observations':{'digest':'sha256:forged'}},{**REVIEW,'native_facts':{'pass':True}}, {**REVIEW,'endpoint':'https://evil.test'},
  {**REVIEW,'command':'id'},{**REVIEW,'source_requests':['forged']},{**REVIEW,'approved_deployed_images':['fake']},
  {**REVIEW,'review':{'scope':SCOPE}},{**REVIEW,'sbomCloudRunServices':[SERVICE.replace('us-central1','us%2fcentral1')]},
 ]
@pytest.mark.parametrize('review',bad_reviews())
@pytest.mark.parametrize('mode',['cognito','none'])
def test_actual_intake_rejects_observations_urls_nesting_and_foreign_workload_ids(review,mode):
 with pytest.raises(HTTPException) as error:validate_connector('gcp',copy.deepcopy(AUTH),{'sw52':review},SimpleNamespace(auth_mode=mode))
 assert error.value.status_code==422

@pytest.mark.parametrize('provider',['aws','azure','k8s'])
@pytest.mark.parametrize('mode',['cognito','none'])
def test_actual_intake_rejects_sw52_for_other_providers(provider,mode):
 with pytest.raises(HTTPException) as error:validate_connector(provider,{}, {'sw52':copy.deepcopy(REVIEW)},SimpleNamespace(auth_mode=mode))
 assert error.value.status_code==422

@pytest.mark.parametrize('scopes',[[],['projects/foreign-project'],[SCOPE,'projects/foreign-project'],[SCOPE,SCOPE],SCOPE])
def test_normalize_with_actual_selected_scopes_rejects_mismatch_or_ambiguous_selection(scopes):
 with pytest.raises(ValueError):normalize(REVIEW,scopes)

def test_actual_intake_cannot_validate_scopes_which_are_not_an_argument():
 review={'status':'collected','scope':'projects/different-project','sbomCloudRunServices':['projects/different-project/locations/us-central1/services/app']}
 validate_connector('gcp',copy.deepcopy(AUTH),{'sw52':review},SimpleNamespace(auth_mode='cognito'))
 with pytest.raises(ValueError):normalize(review,[SCOPE])

def test_cyclic_nested_observation_is_rejected_without_traversal_or_serialization():
 review=copy.deepcopy(REVIEW);review['observations']=review
 with pytest.raises(HTTPException) as error:validate_connector('gcp',copy.deepcopy(AUTH),{'sw52':review},SimpleNamespace(auth_mode='cognito'))
 assert error.value.status_code==422

@pytest.mark.parametrize('mode',['complete','missing','no_policy'])
@pytest.mark.parametrize('check_id,accepted',[('gcp_c5_sbom',False),('gcp_pci_iam_policy_ca1281da7ab2',False),('gcp_pci_iam_policy_9a8ce875703d',False),('gcp-compliance.control.cis_v120_6_2_13',False),('custom.unknown_owner_policy',False),('gcp.storage.uniform_access',True)])
def test_real_http_persists_encrypted_connector_and_admits_only_active_native_check(mode,check_id,accepted,tmp_path,monkeypatch):
 from tests.connector_access_receipts import checked_create, mock_access_pass
 mock_access_pass(monkeypatch)
 import importlib,importlib.util,json
 from pathlib import Path
 from fastapi.testclient import TestClient
 from peaso.auth import Identity,CredentialCipher
 from peaso.server import create_app
 from peaso.server.config import Settings
 from peaso.storage import SQLiteStore,FileArtifacts
 from peaso.worker import Worker
 from peaso.engine import collect_snapshot,evaluate_snapshot
 from peaso.collectors import gcp
 # Reuse the API-shaped native fixture; all HTTP/cloud traffic stays in memory.
 spec=importlib.util.spec_from_file_location('_sbom_roundtrip_api_fixture',Path(__file__).with_name('test_peaso_gcp_sbom_native.py'))
 native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
 api=native.API('missing' if mode=='missing' else 'complete')
 monkeypatch.setattr(gcp,'Credentials',lambda *a,**kw:None);monkeypatch.setattr(gcp,'Transport',lambda *a,**kw:api)
 app_module=importlib.import_module('peaso.server.app')
 dispatched=[]
 monkeypatch.setattr(app_module,'WorkflowDispatcher',lambda **kw:SimpleNamespace(dispatch=lambda *a,**kwargs:dispatched.append((a,kwargs))))
 class Identities:
  def authenticate(self,*args):return Identity('sbom-customer',True,cognito_username='sbom-customer')
  def is_paid(self,*args):return True
 settings=Settings(state_dir=tmp_path/'state',identity_dir=tmp_path/'identity',auth_mode='cognito')
 store=SQLiteStore(settings.state_dir);artifacts=FileArtifacts(tmp_path/'artifacts')
 app=create_app(settings,store=store,artifacts=artifacts,authenticator=Identities())
 options={'regions':[native.REGION],'include_inherited':False,'resource_iam':False}
 if mode!='no_policy':options['sw52']=copy.deepcopy(REVIEW)
 captured=[];responses=[]
 class Pipe:
  def close(self):pass
  def poll(self,*args):return bool(responses)
  def recv(self):return responses.pop(0)
 class Process:
  def __init__(self,**kw):self.request=kw['args'][1]
  def start(self):
   # Replace process isolation only; real worker decrypts/revalidates the saved
   # request, and real collect_snapshot/collector/engine execute unchanged.
   captured.append(copy.deepcopy(self.request))
   snap=collect_snapshot(self.request)
   ref=artifacts.put(self.request['tenant_id'],self.request['scan_id'],'snapshot',snap)
   responses.append((True,ref))
  def is_alive(self):return False
  def join(self,*args,**kw):pass
 context=SimpleNamespace(Pipe=lambda **kw:(Pipe(),Pipe()),Process=Process)
 worker_module=importlib.import_module('peaso.worker')
 monkeypatch.setattr(worker_module.multiprocessing,'get_context',lambda method:context)
 with TestClient(app,base_url='http://127.0.0.1:8000') as client:
  client.headers['Authorization']='Bearer fake-cognito-user'
  response=client.post('/api/connectors',json=checked_create(client,{'name':'SBOM roundtrip','provider':'gcp','auth':copy.deepcopy(AUTH),'scopes':[SCOPE],'options':options}))
  assert response.status_code==201,response.text
  ident=response.json()['id'];row=store.connector('sbom-customer',ident)
  private=CredentialCipher(settings.identity_dir).decrypt(row['auth'])
  assert private['options']==options and private['auth']==AUTH
  assert AUTH['token'] not in row['auth'] and AUTH['token'] not in response.text
  rejected=client.patch('/api/connectors/'+ident,json={'options':{**options,'sw52':{**REVIEW,'observations':{'fake_digest':'forged'}}}})
  assert rejected.status_code==422
  saved=CredentialCipher(settings.identity_dir).decrypt(store.connector('sbom-customer',ident)['auth'])
  assert saved['options']==options
  if not accepted:
   def forbidden_enqueue(*args,**kwargs):
    pytest.fail('Unsupported owner/manual check reached the enqueue boundary')
   monkeypatch.setattr(store,'enqueue',forbidden_enqueue)
  job=client.post('/api/scans',json={'connector_id':ident,'checks':[check_id],'ai_enabled':False})
  assert job.status_code==(201 if accepted else 422),job.text
  if not accepted:
   assert any(word in job.text.lower() for word in ('not available','unsupported','manual evidence','unknown check'))
  assert len(dispatched)==int(accepted)
  assert len(store.jobs('sbom-customer'))==int(accepted)
  assert captured==[] and api.requests==[]
  assert store.connector('sbom-customer',ident)['auth']==row['auth']
