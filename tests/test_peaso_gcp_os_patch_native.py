import copy,threading
from datetime import datetime,timedelta,timezone
from urllib.parse import urlsplit
import pytest
from peaso.collectors import collect_live,gcp
from peaso.engine import evaluate_snapshot,plan_collection
SCOPE='projects/demo-project';IDS=['gcp.compute.os_patch_compliance','gcp_compute_os_patch_compliance','gcp_c5_patch_deployment']
class API:
 def __init__(self,mode):self.mode=mode;self.evidence=[];self.calls=0;self.lock=threading.Lock();self.now=datetime.now(timezone.utc)
 def close(self):pass
 def request(self,method,url,**kw):
  with self.lock:self.calls+=1;rid='r'+str(self.calls)
  p=urlsplit(url).path;mode=self.mode
  at=lambda age=0:(self.now-timedelta(hours=age)).isoformat()
  if p.endswith('/aggregated/instances'):d={'items':{'zones/us-central1-a':{'instances':[{'name':'vm','id':'123','zone':'https://www.googleapis.com/compute/v1/'+SCOPE+'/zones/us-central1-a','status':'RUNNING'}]}}}
  elif p.endswith('/inventory'):
   if mode=='inventory_denied':raise gcp.ReadError('denied','no')
   d={'name':SCOPE+'/locations/us-central1-a/instances/123/inventory','updateTime':at(25 if mode=='inventory_stale' else 0),'items':{'p':{'type':'INSTALLED_PACKAGE','installedPackage':{'aptPackage':{'packageName':'openssl','version':'1.0'}}}}}
  elif p.endswith('/vulnerabilityReport'):
   if mode=='report_denied':raise gcp.ReadError('denied','no')
   d={'name':SCOPE+'/locations/us-central1-a/instances/'+('999' if mode=='foreign_report' else '123')+'/vulnerabilityReport','updateTime':at(25 if mode=='report_stale' else -1 if mode=='report_future' else 0),'vulnerabilities':[]}
   if mode in ('critical_fix','high_fix','critical_without_fix'):
    d['vulnerabilities']=[{'details':{'severity':'HIGH' if mode=='high_fix' else 'CRITICAL'},'items':[{'availableInventoryItemId':'fix'} if mode!='critical_without_fix' else {}]}]
   if mode=='foreign_project_report':d['name']=d['name'].replace(SCOPE,'projects/foreign-project')
   if mode=='omitted_empty_report':d.pop('vulnerabilities')
   if mode=='malformed_report':d['vulnerabilities']={}
  elif p.endswith('/patchDeployments'):
   if mode=='deployment_denied':raise gcp.ReadError('denied','no')
   d={'patchDeployments':[]}
   if mode.startswith('schedule_'):
    r={'name':SCOPE+'/patchDeployments/daily','state':'ACTIVE','instanceFilter':{'all':True},'recurringSchedule':{'frequency':'DAILY','nextExecuteTime':at(-5)}}
    if mode=='schedule_paused':r['state']='PAUSED'
    if mode=='schedule_unspecified':r['state']='STATE_UNSPECIFIED'
    if mode=='schedule_expired':r['recurringSchedule']['endTime']=at(1)
    if mode=='schedule_future_start':r['recurringSchedule']['startTime']=at(-1)
    if mode=='schedule_missing_next':r['recurringSchedule'].pop('nextExecuteTime')
    if mode=='schedule_unsupported_filter':r['instanceFilter']={'zones':['us-central1-a']}
    if mode=='schedule_foreign_target':r['instanceFilter']={'instances':['projects/foreign/zones/us-central1-a/instances/other']}
    if mode=='schedule_nonmatch':r['instanceFilter']={'instances':['zones/us-central1-a/instances/other']}
    if mode=='schedule_explicit':r['instanceFilter']={'instances':['zones/us-central1-a/instances/vm']}
    if mode=='schedule_foreign':r['name']='projects/foreign/patchDeployments/daily'
    d={'patchDeployments':[r]}
   if mode=='deployment_partial':d['nextPageToken']='next'
   if mode=='schedule_duplicate':d['patchDeployments']*=2
  elif p=='/v3/'+SCOPE:d={'name':SCOPE,'projectId':'demo-project'}
  elif p.endswith(':getIamPolicy'):d={'bindings':[]}
  else:d={}
  self.evidence.append({'id':rid,'url':url,'method':method,'status':'collected'})
  return copy.deepcopy(d),rid
@pytest.mark.parametrize('mode,expected',[
 ('empty',['PASS','PASS','FAIL']),('inventory_denied',['UNKNOWN']*3),('inventory_stale',['UNKNOWN']*3),
 ('foreign_project_report',['UNKNOWN','UNKNOWN','FAIL']),('omitted_empty_report',['PASS','PASS','FAIL']),('report_denied',['UNKNOWN','UNKNOWN','FAIL']),('foreign_report',['UNKNOWN','UNKNOWN','FAIL']),('malformed_report',['UNKNOWN','UNKNOWN','FAIL']),
 ('report_stale',['UNKNOWN','UNKNOWN','FAIL']),('report_future',['UNKNOWN','UNKNOWN','FAIL']),
 ('critical_fix',['UNKNOWN','UNKNOWN','FAIL']),('high_fix',['UNKNOWN','PASS','FAIL']),('critical_without_fix',['UNKNOWN','UNKNOWN','FAIL']),
 ('deployment_denied',['PASS','PASS','UNKNOWN']),('deployment_partial',['PASS','PASS','UNKNOWN']),
 ('schedule_duplicate',['PASS','PASS','UNKNOWN']),('schedule_active',['PASS','PASS','UNKNOWN']),('schedule_explicit',['PASS','PASS','UNKNOWN']),
 ('schedule_paused',['PASS','PASS','FAIL']),('schedule_expired',['PASS','PASS','FAIL']),('schedule_future_start',['PASS','PASS','FAIL']),
 ('schedule_foreign_target',['PASS','PASS','UNKNOWN']),('schedule_nonmatch',['PASS','PASS','FAIL']),('schedule_unspecified',['PASS','PASS','UNKNOWN']),
 ('schedule_missing_next',['PASS','PASS','UNKNOWN']),('schedule_unsupported_filter',['PASS','PASS','UNKNOWN']),('schedule_foreign',['PASS','PASS','UNKNOWN'])])
def test_native_os_pipeline(mode,expected,monkeypatch):
 api=API(mode);monkeypatch.setattr(gcp,'Credentials',lambda *a,**kw:None);monkeypatch.setattr(gcp,'Transport',lambda *a,**kw:api)
 c={'provider':'gcp','scopes':[SCOPE],'options':{'resource_iam':False,'metrics_scopes':False,'max_pages':1,'compliance_policy':{'status':'collected','scope':SCOPE,'vm_scope':['vm'],'approved_patch_age_hours':72,'approved_patch_sla_hours':48,'approved_patch_grace_hours':48}}}
 snap=collect_live(c,plan_collection({'connector':c,'checks':IDS}));r=evaluate_snapshot(snap,checks=IDS,include_not_applicable=True)
 actual={i:[f['status'] for f in r['findings'] if f['check_id']==i] for i in IDS}
 assert actual=={i:[status] for i,status in zip(IDS,expected)},actual
