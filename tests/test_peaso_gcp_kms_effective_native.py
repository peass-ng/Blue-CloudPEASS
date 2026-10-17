import copy,threading
from urllib.parse import urlsplit
import pytest
from peaso.collectors import collect_live,gcp
from peaso.engine import evaluate_snapshot,plan_collection
SCOPE='projects/demo-project';NUMBER='1234567890';RING=SCOPE+'/locations/global/keyRings/test-ring';KEY=RING+'/cryptoKeys/test-key';CHECK='gcp_pci_kms_key_a3927a5f3b84';PERM='cloudkms.cryptoKeyVersions.useToEncrypt'
class API:
 def __init__(self,mode):self.mode=mode;self.calls=0;self.lock=threading.Lock();self.requests=[];self.evidence=[]
 def close(self):pass
 def request(self,method,url,**kw):
  with self.lock:self.calls+=1;rid='r'+str(self.calls);self.requests.append((method,url,copy.deepcopy(kw)))
  p=urlsplit(url).path;mode=self.mode;role='projects/demo-project/roles/custom' if mode=='custom' else 'roles/cloudkms.cryptoKeyEncrypter'
  members=['user:a@example.com']
  if mode=='four':members=['user:'+x+'@example.com' for x in 'abcd']
  if mode=='three':members=['user:'+x+'@example.com' for x in 'abc']
  if mode=='service_account':members=['serviceAccount:account@demo-project.iam.gserviceaccount.com']
  if mode in ('group','public','domain','federated'):members=[{'group':'group:team@example.com','public':'allUsers','domain':'domain:example.com','federated':'principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/*'}[mode]]
  binding={'role':role,'members':members}
  if mode=='conditional':binding['condition']={'expression':'true'}
  if p=='/v3/'+SCOPE:d={'name':'projects/'+NUMBER,'projectId':'demo-project'}
  elif p=='/v1/'+SCOPE+':getAncestry':
   if mode=='denied_ancestry':raise gcp.ReadError('denied','no')
   d={'ancestor':[{'resourceId':{'type':'project','id':NUMBER}}]}
   if mode=='ancestor':d['ancestor'].append({'resourceId':{'type':'organization','id':'999'}})
  elif p=='/v3/organizations/999':d={'name':'organizations/999'}
  elif p.endswith(':getIamPolicy'):
   if mode=='key_iam_denied' and p=='/v1/'+KEY+':getIamPolicy':raise gcp.ReadError('denied','no')
   if mode=='ring_iam_denied' and p=='/v1/'+RING+':getIamPolicy':raise gcp.ReadError('denied','no')
   d={'bindings':[]}
   if p=='/v1/'+KEY+':getIamPolicy' and mode not in ('ancestor','ring','empty_crypto'):d['bindings']=[binding]
   if p=='/v1/'+KEY+':getIamPolicy' and mode=='noncrypto_group':d['bindings']=[{'role':'roles/viewer','members':['group:team@example.com']}]
   if p=='/v1/'+RING+':getIamPolicy' and mode=='ring':d['bindings']=[binding]
   if p=='/v3/organizations/999:getIamPolicy' and mode=='ancestor':d['bindings']=[binding]
  elif p.endswith('/keyRings'):d={'keyRings':[{'name':RING}]}
  elif p.endswith('/cryptoKeys'):d={'cryptoKeys':[{'name':KEY,'purpose':'ENCRYPT_DECRYPT'}]}
  elif '/roles/' in p:
   if mode=='role_denied':raise gcp.ReadError('denied','no')
   d={'name':p[len('/v1/'):],'includedPermissions':[] if p.endswith('/viewer') else [PERM]}
   if mode=='foreign_role':d['name']='roles/foreign'
   if mode=='role_missing_permissions':d.pop('includedPermissions')
  elif p=='/v3beta/iam:troubleshoot':
   if mode=='troubleshooter_denied':raise gcp.ReadError('denied','no')
   access=copy.deepcopy(kw['body']['accessTuple']);state='CANNOT_ACCESS' if mode=='deny' else 'UNKNOWN_INFO' if mode=='partial_effective' else 'UNKNOWN_CONDITIONAL' if mode=='conditional_effective' else 'CAN_ACCESS'
   d={'accessTuple':access,'overallAccessState':state,'pabPolicyExplanation':{'principalAccessBoundaryAccessState':'PAB_ACCESS_STATE_NOT_ENFORCED'}}
   if mode=='foreign_troubleshoot':d['accessTuple']['fullResourceName']='//cloudkms.googleapis.com/foreign'
   if mode=='no_pab_proof':d.pop('pabPolicyExplanation')
  else:d={}
  self.evidence.append({'id':rid,'url':url,'method':method,'status':'collected'})
  return copy.deepcopy(d),rid
@pytest.mark.parametrize('mode,expected',[
 ('direct','PASS'),('three','PASS'),('four','FAIL'),('service_account','PASS'),('custom','PASS'),('ancestor','PASS'),('ring','PASS'),
 ('empty_crypto','PASS'),('noncrypto_group','PASS'),('deny','PASS'),('group','UNKNOWN'),('public','UNKNOWN'),('domain','UNKNOWN'),('federated','UNKNOWN'),
 ('conditional','UNKNOWN'),('denied_ancestry','UNKNOWN'),('key_iam_denied','UNKNOWN'),('ring_iam_denied','UNKNOWN'),('role_denied','UNKNOWN'),
 ('foreign_role','UNKNOWN'),('role_missing_permissions','UNKNOWN'),('troubleshooter_denied','UNKNOWN'),('partial_effective','UNKNOWN'),
 ('conditional_effective','UNKNOWN'),('foreign_troubleshoot','UNKNOWN'),('no_pab_proof','UNKNOWN')])
def test_native_kms_effective_pipeline(mode,expected,monkeypatch):
 api=API(mode);monkeypatch.setattr(gcp,'Credentials',lambda *a,**kw:None);monkeypatch.setattr(gcp,'Transport',lambda *a,**kw:api)
 c={'provider':'gcp','scopes':[SCOPE],'options':{'resource_iam':False,'metrics_scopes':False,'include_inherited':True,'kms_locations':['global']}}
 snap=collect_live(c,plan_collection({'connector':c,'checks':[CHECK]}));report=evaluate_snapshot(snap,checks=[CHECK],include_not_applicable=True)
 f=[f for f in report['findings'] if f['check_id']==CHECK];assert len(f)==1 and f[0]['status']==expected,f
 if expected!='UNKNOWN' and mode=='deny':assert f[0]['evidence']['effective_principals']==[]
 assert all(method=='GET' or url.endswith((':getIamPolicy',':getAncestry','/v3beta/iam:troubleshoot')) for method,url,kw in api.requests)

def test_real_transport_allows_only_exact_readonly_troubleshooter_post(monkeypatch):
 from types import SimpleNamespace
 calls=[]
 def request(method,url,**kw):
  calls.append((method,url));return SimpleNamespace(status_code=200,json=lambda:{'overallAccessState':'CAN_ACCESS'})
 transport=gcp.Transport(SimpleNamespace(headers=dict,close=lambda:None),{},sleep=lambda _:None)
 monkeypatch.setattr(transport,'_session',lambda:SimpleNamespace(request=request,close=lambda:None))
 try:
  value,rid=transport.request('POST','https://policytroubleshooter.googleapis.com/v3beta/iam:troubleshoot',body={'accessTuple':{'principal':'a@example.com','fullResourceName':'//cloudkms.googleapis.com/'+KEY,'permission':PERM}},scope=SCOPE)
  assert value['overallAccessState']=='CAN_ACCESS' and len(calls)==1
  for method,url in [('POST','https://compute.googleapis.com/v3beta/iam:troubleshoot'),('POST','https://policytroubleshooter.googleapis.com/v3beta/iam:setIamPolicy'),('POST','https://policytroubleshooter.googleapis.com/v3/iam:troubleshoot'),('DELETE','https://policytroubleshooter.googleapis.com/v3beta/iam:troubleshoot')]:
   with pytest.raises(gcp.ReadError,match='cloud_mutation_prohibited'):transport.request(method,url)
  assert len(calls)==1
 finally:transport.close()
