import copy,threading
from urllib.parse import urlsplit
import pytest
from peaso.collectors import collect_live,gcp
from peaso.engine import evaluate_snapshot,plan_collection
SCOPE='projects/demo-project';REGION='us-central1';SERVICE=SCOPE+'/locations/'+REGION+'/services/app';REPO=SCOPE+'/locations/'+REGION+'/repositories/images';DIGEST='sha256:'+'a'*64;URI=REGION+'-docker.pkg.dev/demo-project/images/app@'+DIGEST;CHECK='gcp_c5_sbom'
class API:
 def __init__(self,mode):self.mode=mode;self.calls=0;self.lock=threading.Lock();self.requests=[];self.evidence=[]
 def close(self):pass
 def request(self,method,url,**kw):
  with self.lock:self.calls+=1;rid='r'+str(self.calls);self.requests.append((method,url,copy.deepcopy(kw)))
  p=urlsplit(url).path;mode=self.mode;params=kw.get('params',{})
  if p=='/v3/'+SCOPE:d={'name':'projects/1234567890','projectId':'demo-project'}
  elif p.endswith(':getIamPolicy'):d={'bindings':[]}
  elif p=='/v1/'+SCOPE+'/locations/'+REGION+'/repositories':d={'repositories':[{'name':REPO,'format':'MAVEN' if mode=='repository_not_docker' else 'DOCKER'}]}
  elif p=='/v2/'+SCOPE+'/locations/'+REGION+'/services':d={'services':[{'name':SERVICE}]}
  elif p.endswith('/dockerImages'):
   if mode=='images_denied':raise gcp.ReadError('denied','no')
   d={'dockerImages':[{'name':REPO+'/dockerImages/app@'+DIGEST,'uri':URI}]}
   if mode=='image_mismatch':d['dockerImages'][0]['uri']=URI.replace('a'*64,'b'*64)
   if mode=='images_partial':d['nextPageToken']='next'
  elif p=='/v1/'+SCOPE+'/occurrences':
   if mode=='occurrences_denied':raise gcp.ReadError('denied','no')
   d={'occurrences':[] if mode in ('missing','occurrences_second_page','absent_repository') and not params.get('pageToken') else [{'name':SCOPE+'/occurrences/one','kind':'SBOM_REFERENCE','resourceUri':'https://'+URI,'noteName':'projects/sbom-notes/notes/sbom'}]}
   if mode=='occurrences_partial':d['nextPageToken']='next'
   if mode=='occurrences_second_page' and not params.get('pageToken'):d['nextPageToken']='next'
   if mode=='wrong_kind':d['occurrences'][0]['kind']='BUILD'
   if mode=='wrong_note':d['occurrences'][0]['noteName']='bad'
   if mode=='wrong_occurrence_resource':d['occurrences'][0]['resourceUri']=URI.replace('a'*64,'b'*64)
  elif p.endswith('/services/app') and '/apis/' in p:
   if mode=='service_denied':raise gcp.ReadError('denied','no')
   d={'metadata':{'name':'app','namespace':'1234567890','generation':1},'status':{'observedGeneration':1,'traffic':[{'revisionName':'app-00001','percent':100}]}}
   if mode=='service_foreign':d['metadata']['namespace']='foreign'
   if mode=='service_reconciling':d['status']['observedGeneration']=0
   if mode=='missing_traffic':d['status'].pop('traffic')
   if mode=='partial_traffic':d['status']['traffic'][0]['percent']=50
   if mode=='tagged_old':d['status']['traffic'].append({'revisionName':'app-00000','percent':0,'tag':'previous'})
  elif '/revisions/' in p:
   if mode=='revision_denied':raise gcp.ReadError('denied','no')
   rev=p.rsplit('/',1)[1]
   d={'metadata':{'name':rev,'namespace':'1234567890','labels':{'serving.knative.dev/service':'app'}},'spec':{'containers':[{'image':'tagged-image:latest'}]},'status':{'imageDigest':URI,'conditions':[{'type':'Ready','status':'True'}]}}
   if mode=='revision_foreign':d['metadata']['labels']['serving.knative.dev/service']='foreign'
   if mode=='revision_ready_conflict':d['status']['conditions'].append({'type':'Ready','status':'False'})
   if mode=='revision_not_ready':d['status']['conditions'][0]['status']='False'
   if mode=='revision_tag_only':d['status']['imageDigest']=URI.split('@')[0]+':latest'
   if mode=='multicontainer':d['spec']['containers'].append({'image':'other:latest'})
   if mode=='absent_repository':d['status']['imageDigest']=URI.replace('/images/','/uninventoried-repo/')
   if mode=='revision_wrong_project':d['status']['imageDigest']=URI.replace('/demo-project/','/foreign-project/')
   if mode=='tagged_old' and rev=='app-00000':d['status']['imageDigest']=URI.replace('a'*64,'b'*64)
  else:d={}
  self.evidence.append({'id':rid,'url':url,'method':method,'status':'collected'});return copy.deepcopy(d),rid
@pytest.mark.parametrize('mode,expected',[
 ('absent_repository','UNKNOWN'),('repository_not_docker','UNKNOWN'),('complete','PASS'),('missing','FAIL'),('no_policy','UNKNOWN'),('foreign_policy','UNKNOWN'),('images_denied','UNKNOWN'),('images_partial','UNKNOWN'),('image_mismatch','UNKNOWN'),
 ('occurrences_denied','UNKNOWN'),('occurrences_partial','UNKNOWN'),('occurrences_second_page','PASS'),('wrong_kind','UNKNOWN'),('wrong_note','UNKNOWN'),('wrong_occurrence_resource','FAIL'),
 ('service_denied','UNKNOWN'),('service_foreign','UNKNOWN'),('service_reconciling','UNKNOWN'),('missing_traffic','UNKNOWN'),('partial_traffic','UNKNOWN'),
 ('revision_denied','UNKNOWN'),('revision_foreign','UNKNOWN'),('revision_ready_conflict','UNKNOWN'),('revision_not_ready','UNKNOWN'),('revision_tag_only','UNKNOWN'),('multicontainer','UNKNOWN'),('revision_wrong_project','UNKNOWN'),('tagged_old','UNKNOWN')])
def test_native_sbom_pipeline(mode,expected,monkeypatch):
 api=API(mode);monkeypatch.setattr(gcp,'Credentials',lambda *a,**kw:None);monkeypatch.setattr(gcp,'Transport',lambda *a,**kw:api)
 c={'provider':'gcp','scopes':[SCOPE],'options':{'resource_iam':False,'metrics_scopes':False,'include_inherited':False,'artifactregistry_locations':[REGION],'cloudrun_locations':[REGION],'max_pages':1 if mode!='occurrences_second_page' else 2,'sw52':{'status':'collected','scope':SCOPE,'sbomCloudRunServices':[SERVICE]}}}
 if mode=='no_policy':c['options'].pop('sw52')
 if mode=='foreign_policy':c['options']['sw52']['sbomCloudRunServices']=[SERVICE.replace(SCOPE,'projects/foreign-project')]
 snap=collect_live(c,plan_collection({'connector':c,'checks':[CHECK]}));r=evaluate_snapshot(snap,checks=[CHECK],include_not_applicable=True);f=[f for f in r['findings'] if f['check_id']==CHECK]
 assert len(f)==1 and f[0]['status']==expected,f
 if mode=='complete':
  repos=next(col for col in snap['collections'] if col['type']=='artifact_repository')
  deployed=next(col for col in snap['collections'] if col['type']=='deployed_image')
  assert repos['status']=='collected' and deployed['status']=='collected'
  assert all(row['format']=='DOCKER' for row in repos['items'])
  assert {row['repository'] for row in deployed['items']} <= {row['name'] for row in repos['items']}
 if mode=='absent_repository':
  assert not any(finding['status']=='PASS' for finding in f)
 assert all(method in ('GET','POST') for method,url,kw in api.requests)
 for method,url,kw in api.requests:
  if '-run.googleapis.com/' in url:assert method=='GET' and set(kw['params'])=={'fields'} and 'env' not in kw['params']['fields']
  if url.endswith('/occurrences'):assert kw['params']['filter']=='kind="SBOM_REFERENCE"' and 'sbomReference' not in kw['params']['fields']

def test_real_transport_regional_metadata_requires_internal_literal_endpoint_scope_and_mask(monkeypatch):
 from types import SimpleNamespace
 url='https://us-central1-run.googleapis.com/apis/serving.knative.dev/v1/namespaces/demo-project/revisions/app-00001'
 mask={'fields':'metadata(name,namespace,labels),spec(containers(image)),status(imageDigest,conditions)'}
 calls=[]
 transport=gcp.Transport(SimpleNamespace(headers=dict,close=lambda:None),{},sleep=lambda _:None)
 session=SimpleNamespace(request=lambda method,url,**kw:(calls.append((method,url,kw)) or SimpleNamespace(status_code=200,json=lambda:{})),close=lambda:None)
 monkeypatch.setattr(transport,'_session',lambda:session)
 try:
  with pytest.raises(gcp.ReadError,match='unsafe_api_endpoint'):transport.request('GET',url,scope=SCOPE,params=mask)
  transport.run_sbom_metadata_reads[url]=(SCOPE,copy.deepcopy(mask))
  transport.request('GET',url,scope=SCOPE,params=mask)
  assert len(calls)==1
  for method,endpoint,scope,params,body in [
   ('GET',url,'projects/foreign',mask,None),('GET',url,SCOPE,{'fields':'spec'},None),('POST',url,SCOPE,mask,None),
   ('GET',url.replace('us-central1','us-east1'),SCOPE,mask,None),('GET',url.replace('app-00001','app-00002'),SCOPE,mask,None),
   ('GET',url,SCOPE,mask,{'secret':'value'}),('GET',url.replace('https:','http:'),SCOPE,mask,None)]:
   with pytest.raises(gcp.ReadError,match='unsafe_api_endpoint'):transport.request(method,endpoint,scope=scope,params=params,body=body)
  assert len(calls)==1
 finally:transport.close()

@pytest.mark.parametrize('mode',['foreign','multiple'])
def test_actual_collection_cannot_use_intake_policy_for_different_selected_scope(mode,monkeypatch):
 api=API('complete');monkeypatch.setattr(gcp,'Credentials',lambda *a,**kw:None);monkeypatch.setattr(gcp,'Transport',lambda *a,**kw:api)
 review={'status':'collected','scope':SCOPE,'sbomCloudRunServices':[SERVICE]}
 scopes=[SCOPE,'projects/second-project'] if mode=='multiple' else ['projects/second-project']
 c={'provider':'gcp','scopes':scopes,'options':{'resource_iam':False,'metrics_scopes':False,'include_inherited':False,'artifactregistry_locations':[REGION],'cloudrun_locations':[REGION],'sw52':review}}
 if mode=='foreign':
  with pytest.raises(ValueError):collect_live(c,plan_collection({'connector':c,'checks':[CHECK]}))
 else:
  snap=collect_live(c,plan_collection({'connector':c,'checks':[CHECK]}));r=evaluate_snapshot(snap,checks=[CHECK],include_not_applicable=True)
  f=[f for f in r['findings'] if f['check_id']==CHECK]
  scoped=[finding for finding in f if finding['scope']==SCOPE]
  assert scoped and all(finding['status']=='UNKNOWN' for finding in scoped),f
  assert all(finding['status'] in ('UNKNOWN','EMPTY') for finding in f),f
 assert not any('-run.googleapis.com/' in url for method,url,kw in api.requests)
