import copy,json
from datetime import datetime,timezone,timedelta
from urllib.parse import parse_qs,urlsplit
import pytest
from peaso.collectors import azure,collect_live
from peaso.engine import evaluate_snapshot
from tests.test_peaso_azure_bulk_native import SCOPE,BASE,Transport,parent
CHECK='azure_c5_ops_20_01b'
WORKSPACE=BASE+'Microsoft.OperationalInsights/workspaces/security'
ONBOARD=WORKSPACE+'/providers/Microsoft.SecurityInsights/onboardingStates/default'
INCIDENT=WORKSPACE+'/providers/Microsoft.SecurityInsights/incidents/11111111-2222-3333-4444-555555555555'

def capture(mode='mismatch',**extra):
 now=datetime.now(timezone.utc);when=(now-timedelta(minutes=1)).isoformat()
 incident={'id':INCIDENT,'properties':{'status':'Closed','classification':'FalsePositive','classificationReason':'IncorrectAlertLogic','severity':'High','createdTimeUtc':when,'lastModifiedTimeUtc':when,'description':'private-marker','title':'private-marker','owner':{'email':'private-marker'}}}
 paths={SCOPE+'/providers/Microsoft.OperationalInsights/workspaces':{'value':[parent(WORKSPACE,'Microsoft.OperationalInsights/workspaces',{})]},WORKSPACE+'/providers/Microsoft.SecurityInsights/onboardingStates':{'value':[{'id':ONBOARD,'properties':{'customerManagedKey':False}}]},WORKSPACE+'/providers/Microsoft.SecurityInsights/incidents':{'value':[incident]}}
 if mode=='priority':incident['properties']['classification']='TruePositive';incident['properties']['severity']='Informational'
 if mode=='matching':incident['properties']['classification']='TruePositive'
 if mode=='missingclassification':incident['properties'].pop('classification')
 if mode=='outsidereview':incident['properties']['lastModifiedTimeUtc']=(now-timedelta(days=30)).isoformat()
 if mode=='emptyincidents':paths[WORKSPACE+'/providers/Microsoft.SecurityInsights/incidents']={'value':[]}
 if mode=='notonboarded':paths[WORKSPACE+'/providers/Microsoft.SecurityInsights/onboardingStates']={'value':[]}
 if mode=='emptyworkspaces':paths[SCOPE+'/providers/Microsoft.OperationalInsights/workspaces']={'value':[]}
 if mode=='denied':paths[SCOPE+'/providers/Microsoft.OperationalInsights/workspaces']=azure.AzureReadError('forbidden',403)
 if mode=='incidentdenied':paths[WORKSPACE+'/providers/Microsoft.SecurityInsights/incidents']=azure.AzureReadError('forbidden',403)
 if mode=='onboard404':paths[WORKSPACE+'/providers/Microsoft.SecurityInsights/onboardingStates']=azure.AzureReadError('not_found',404)
 if mode=='foreign':paths[SCOPE+'/providers/Microsoft.OperationalInsights/workspaces']['value'][0]['id']=WORKSPACE.replace(SCOPE,'/subscriptions/33333333-3333-3333-3333-333333333333')
 if mode=='foreignincident':incident['id']=INCIDENT.replace('/workspaces/security/','/workspaces/foreign/')
 if mode=='foreignonboard':paths[WORKSPACE+'/providers/Microsoft.SecurityInsights/onboardingStates']['value'][0]['id']=ONBOARD.replace('/workspaces/security/','/workspaces/foreign/')
 if mode=='duplicate':paths[WORKSPACE+'/providers/Microsoft.SecurityInsights/incidents']['value']*=2
 if mode=='partial':
  original=copy.deepcopy(incident)
  paths[WORKSPACE+'/providers/Microsoft.SecurityInsights/incidents']=lambda q:azure.AzureReadError('forbidden',403)if 'page'in q else{'value':[original],'nextLink':azure.ARM+WORKSPACE+'/providers/Microsoft.SecurityInsights/incidents?page=2'}
 policy={'sw32':{'status':'collected','scope':SCOPE,'incident_review':{'start':(now-timedelta(days=1)).isoformat(),'end':now.isoformat(),'approved':True,'allowed_classifications':['TruePositive'],'allowed_priorities':['High','Medium','Low']}}}
 if mode=='foreignpolicy':policy['sw32']['scope']='/subscriptions/33333333-3333-3333-3333-333333333333'
 if mode=='noapproval':policy['sw32']['incident_review']['approved']=False
 api=Transport(paths);native=azure.collect
 with pytest.MonkeyPatch.context()as m:
  m.setattr(azure,'collect',lambda c,k:native(c,k,transport=api))
  try:
   snapshot=collect_live({'provider':'azure','scopes':[SCOPE],'options':{'retries':0,'compliance_policy':policy,**extra}},['sentinel_workspace'])
  except ValueError:
   if mode in ('foreignpolicy','noapproval'):
    assert api.calls==[], 'invalid owner approval must be rejected before cloud requests'
   raise
 finding=evaluate_snapshot(snapshot,checks=[CHECK],include_not_applicable=True)['findings'][0]
 assert 'private-marker'not in json.dumps(snapshot)
 assert '"process_evidence": {'not in json.dumps(snapshot)
 assert all(urlsplit(c).hostname=='management.azure.com'for c in api.calls)
 return finding,snapshot

@pytest.mark.parametrize('mode,expected',[('mismatch','FAIL'),('priority','FAIL'),('matching','UNKNOWN'),('missingclassification','UNKNOWN'),('outsidereview','UNKNOWN'),('emptyincidents','UNKNOWN'),('notonboarded','UNKNOWN'),('emptyworkspaces','UNKNOWN'),('foreign','UNKNOWN'),('foreignincident','UNKNOWN'),('foreignonboard','UNKNOWN'),('duplicate','UNKNOWN'),('partial','UNKNOWN'),('denied','DENIED'),('incidentdenied','DENIED'),('onboard404','UNKNOWN'),('foreignpolicy','REJECTED_INPUT'),('noapproval','REJECTED_INPUT')])
def test_native_sentinel_only_proves_metadata_policy_mismatches(mode,expected):
 if expected=='REJECTED_INPUT':
  with pytest.raises(ValueError):capture(mode)
  return
 finding,snapshot=capture(mode)
 assert finding['status']==expected,finding
 assert finding['status']!='PASS'

@pytest.mark.parametrize('option,value',[('max_calls',1),('max_pages',1),('max_resources',1)])
def test_limits_cannot_create_sentinel_process_pass(option,value):
 finding,_=capture('partial'if option=='max_pages'else'matching',**{option:value})
 assert finding['status']in('UNKNOWN','DENIED')
