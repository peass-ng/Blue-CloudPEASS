import copy,json
from urllib.parse import urlsplit
import pytest
from peaso.collectors import azure,collect_live
from peaso.engine import evaluate_snapshot
from tests.test_peaso_azure_bulk_native import SCOPE,BASE,Transport,parent
CHECK='azure_c5_ops_25_02b';NAME='11111111-2222-3333-4444-555555555555'
RESOURCE=BASE+'Microsoft.Compute/virtualMachines/server'
ASSESSMENT=RESOURCE+'/providers/Microsoft.Security/assessments/'+NAME
METADATA='/providers/Microsoft.Security/assessmentMetadata/'+NAME

def capture(mode='good',**kw):
 assessment=parent(ASSESSMENT,'Microsoft.Security/assessments',{'status':{'code':'Unhealthy'}});assessment['name']=NAME
 meta=parent(METADATA,'Microsoft.Security/assessmentMetadata',{'severity':'High','partnerData':{'secret':'private-marker'},'description':'private-marker'});meta['name']=NAME
 paths={SCOPE+'/providers/Microsoft.Security/assessments':{'value':[assessment]},SCOPE+'/providers/Microsoft.Security/assessmentMetadata':{'value':[meta]}}
 policy={'sw32':{'scope':SCOPE,'status':'collected','vulnerability_severity_criteria':{'approved':True,'version':'v1','expectedSeverityByAssessmentName':{NAME:'High'}}}}
 criteria=policy['sw32']['vulnerability_severity_criteria']
 if mode=='subscription':assessment['id']=SCOPE+'/providers/Microsoft.Security/assessments/'+NAME
 if mode=='resourcegroup':assessment['id']=SCOPE+'/resourceGroups/rg/providers/Microsoft.Security/assessments/'+NAME
 if mode=='nested':assessment['id']=RESOURCE+'/extensions/extension/providers/Microsoft.Security/assessments/'+NAME
 if mode=='foreignTenant':assessment['id']='/tenants/33333333-3333-3333-3333-333333333333/providers/Microsoft.Security/assessments/'+NAME
 if mode=='wrongProvider':assessment['id']=ASSESSMENT.replace('/providers/Microsoft.Security/assessments/','/providers/Microsoft.Other/assessments/')
 if mode=='subassessment':assessment['id']=ASSESSMENT+'/subAssessments/child'
 if mode=='traversal':assessment['id']=RESOURCE+'/../providers/Microsoft.Security/assessments/'+NAME
 if mode=='duplicateprovider':assessment['id']=ASSESSMENT+'/providers/Microsoft.Security/assessments/'+NAME
 if mode=='conflictingassessment':
  first=copy.deepcopy(assessment);first['properties']['status']['code']='NotApplicable';paths[SCOPE+'/providers/Microsoft.Security/assessments']['value']=[first,assessment]
 if mode=='both':
  from datetime import datetime,timezone,timedelta
  now=datetime.now(timezone.utc);policy['sw32']['incident_review']={'start':(now-timedelta(days=1)).isoformat(),'end':now.isoformat(),'approved':True,'allowed_classifications':['TruePositive'],'allowed_priorities':['High']}
 if mode=='mismatch':criteria['expectedSeverityByAssessmentName'][NAME]='Low'
 if mode=='missingmapping':criteria.pop('expectedSeverityByAssessmentName')
 if mode=='wrongmapping':criteria['expectedSeverityByAssessmentName']={'other':'High'}
 if mode=='unapproved':criteria['approved']=False
 if mode=='foreignpolicy':policy['sw32']['scope']='/subscriptions/33333333-3333-3333-3333-333333333333'
 if mode=='unprovenuniverse':criteria['finding_coverage_complete']=True
 if mode=='observations':criteria['assigned_severity_matches_criteria']=True
 if mode=='missingseverity':meta['properties'].pop('severity')
 if mode=='unknownseverity':meta['properties']['severity']='Critical'
 if mode=='duplicate':paths[SCOPE+'/providers/Microsoft.Security/assessmentMetadata']['value']*=2
 if mode=='foreign':meta['id']=METADATA.replace('/providers/','/subscriptions/33333333-3333-3333-3333-333333333333/providers/',1)
 if mode=='localmeta':meta['id']=SCOPE+METADATA
 if mode=='foreignassessment':assessment['id']=ASSESSMENT.replace(SCOPE,'/subscriptions/33333333-3333-3333-3333-333333333333')
 if mode=='wrongname':assessment['name']='other'
 if mode=='notapplicable':assessment['properties']['status']['code']='NotApplicable'
 if mode=='empty':paths[SCOPE+'/providers/Microsoft.Security/assessments']={'value':[]}
 if mode=='metadenied':paths[SCOPE+'/providers/Microsoft.Security/assessmentMetadata']=azure.AzureReadError('forbidden',403)
 if mode=='assessmentdenied':paths[SCOPE+'/providers/Microsoft.Security/assessments']=azure.AzureReadError('forbidden',403)
 if mode=='partial':paths[SCOPE+'/providers/Microsoft.Security/assessmentMetadata']=lambda q:azure.AzureReadError('forbidden',403)if 'page'in q else{'value':[meta],'nextLink':azure.ARM+SCOPE+'/providers/Microsoft.Security/assessmentMetadata?page=2'}
 api=Transport(paths);native=azure.collect
 with pytest.MonkeyPatch.context()as m:
  m.setattr(azure,'collect',lambda c,k:native(c,k,transport=api))
  snapshot=collect_live({'provider':'azure','scopes':[SCOPE],'options':{'retries':0,'compliance_policy':policy,**kw}},['assessment_metadata'])
 finding=evaluate_snapshot(snapshot,checks=[CHECK],include_not_applicable=True)['findings'][0]
 assert 'private-marker'not in json.dumps(snapshot)
 assert all(urlsplit(u).hostname=='management.azure.com'for u in api.calls)
 return finding,snapshot

@pytest.mark.parametrize('mode,expected',[('good','PASS'),('subscription','PASS'),('resourcegroup','PASS'),('nested','PASS'),('foreignTenant','UNKNOWN'),('wrongProvider','UNKNOWN'),('subassessment','UNKNOWN'),('traversal','UNKNOWN'),('duplicateprovider','UNKNOWN'),('conflictingassessment','UNKNOWN'),('localmeta','PASS'),('mismatch','FAIL'),('missingmapping','REJECTED'),('wrongmapping','UNKNOWN'),('unapproved','REJECTED'),('foreignpolicy','REJECTED'),('unprovenuniverse','REJECTED'),('observations','REJECTED'),('missingseverity','UNKNOWN'),('unknownseverity','UNKNOWN'),('duplicate','UNKNOWN'),('foreign','UNKNOWN'),('foreignassessment','UNKNOWN'),('wrongname','UNKNOWN'),('notapplicable','PASS'),('empty','PASS'),('metadenied','DENIED'),('assessmentdenied','DENIED'),('partial','UNKNOWN')])
def test_native_definition_severity_against_approved_static_criteria(mode,expected):
 if expected=='REJECTED':
  with pytest.raises(ValueError):capture(mode)
 else:
  finding,snapshot=capture(mode)
  assert finding['status']==expected,finding

@pytest.mark.parametrize('option,value',[('max_calls',1),('max_pages',1),('max_resources',1)])
def test_native_coverage_limits_never_become_severity_approval(option,value):
 finding,_=capture('partial'if option=='max_pages'else'good',**{option:value})
 assert finding['status']!='PASS',finding


def test_native_coverage_is_derived_and_not_submitted_by_owner():
 finding,snapshot=capture()
 assert finding['status']=='PASS'
 criteria=snapshot['metadata']['compliance_policy']['sw32']['vulnerability_severity_criteria']
 assert criteria['finding_coverage_complete']is True


def test_sw32_normalizer_preserves_independent_features_without_observations():
 from peaso.azure_sw32_policy import normalize_sw32
 from datetime import datetime,timezone,timedelta
 now=datetime.now(timezone.utc)
 review={'start':(now-timedelta(days=1)).isoformat(),'end':now.isoformat(),'approved':True,'allowed_classifications':['TruePositive'],'allowed_priorities':['High']}
 severity={'approved':True,'version':'v1','expectedSeverityByAssessmentName':{NAME:'High'}}
 for fields in ({'incident_review':review},{'vulnerability_severity_criteria':severity},{'incident_review':review,'vulnerability_severity_criteria':severity}):
  value={'scope':SCOPE,'status':'collected',**fields}
  result=normalize_sw32(value,expected_scope=SCOPE)
  assert result==value and result is not value
  assert 'finding_coverage_complete'not in json.dumps(result)


@pytest.mark.parametrize('field,value',[('scope',None),('scope','/subscriptions/foreign'),('status','denied'),('observations',{}),('incidents',[]),('process_evidence',{}),('finding_coverage_complete',True)])
def test_sw32_normalizer_rejects_foreign_scope_or_observations(field,value):
 from peaso.azure_sw32_policy import normalize_sw32
 policy={'scope':SCOPE,'status':'collected','vulnerability_severity_criteria':{'approved':True,'version':'v1','expectedSeverityByAssessmentName':{NAME:'High'}},field:value}
 with pytest.raises(ValueError):normalize_sw32(policy)


@pytest.mark.parametrize('field,value',[('finding_coverage_complete',True),('assigned_severity_matches_criteria',True),('metadata',{}),('version',None),('approved',1),('expectedSeverityByAssessmentName',{NAME:['High']})])
def test_severity_approvals_cannot_submit_native_coverage_or_results(field,value):
 from peaso.azure_sw32_policy import normalize_sw32
 policy={'scope':SCOPE,'status':'collected','vulnerability_severity_criteria':{'approved':True,'version':'v1','expectedSeverityByAssessmentName':{NAME:'High'},field:value}}
 with pytest.raises(ValueError):normalize_sw32(policy)


def test_native_severity_metadata_preserves_sentinel_policy_namespace():
 finding,snapshot=capture('both')
 assert finding['status']=='PASS'
 sw32=snapshot['metadata']['compliance_policy']['sw32']
 assert sw32['incident_review']['allowed_classifications']==['TruePositive']
 assert sw32['vulnerability_severity_criteria']['finding_coverage_complete']is True


@pytest.mark.parametrize('mutation',['observations','duplicate','future','unapproved','naive','foreignscope'])
def test_incident_normalizer_rejects_non_normative_or_invalid_review(mutation):
 from peaso.azure_sw32_policy import normalize_sw32
 from datetime import datetime,timezone,timedelta
 now=datetime.now(timezone.utc)
 review={'start':(now-timedelta(days=1)).isoformat(),'end':now.isoformat(),'approved':True,'allowed_classifications':['TruePositive'],'allowed_priorities':['High']}
 policy={'status':'collected','scope':SCOPE,'incident_review':review}
 if mutation=='observations':review['process_evidence']={'verified':True}
 if mutation=='duplicate':review['allowed_priorities']=['High','High']
 if mutation=='future':review['end']=(now+timedelta(days=1)).isoformat()
 if mutation=='unapproved':review['approved']=False
 if mutation=='naive':review['end']='2026-01-01T00:00:00'
 if mutation=='foreignscope':policy['scope']=SCOPE+'/resourceGroups/rg'
 with pytest.raises(ValueError):normalize_sw32(policy)


@pytest.mark.parametrize('mode',['empty','notapplicable','good'])
def test_no_approved_owner_criteria_never_uses_vacuous_pass(mode):
 finding,_=capture(mode,compliance_policy={})
 assert finding['status']=='UNKNOWN'


@pytest.mark.parametrize('suffix,expected',[
 ('/providers/Microsoft.Security/assessments/key',True),
 ('/resourceGroups/rg/providers/Microsoft.Security/assessments/key',True),
 ('/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm/providers/Microsoft.Security/assessments/key',True),
 ('/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm/extensions/ext/providers/Microsoft.Security/assessments/key',True),
 ('/providers/Microsoft.Other/assessments/key',False),
 ('/providers/Microsoft.Security/assessments/key/subAssessments/child',False),
 ('/providers/Microsoft.Security/assessments/key/providers/Microsoft.Security/assessments/again',False),
 ('/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm/../providers/Microsoft.Security/assessments/key',False),
 ('/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm//providers/Microsoft.Security/assessments/key',False),
 ('/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/providers/Microsoft.Security/assessments/key',False),
 ('/providers/Microsoft.Security/assessments/key?elsewhere',False),
 ('/providers/Microsoft.Security/assessments/key\\bad',False),
 ('/providers/Microsoft.Security/assessments/key\x00bad',False),
 ('/providers/Microsoft.Security/assessments/key\x7fbad',False),
 ('/providers/Microsoft.Security/assessments/%2e%2e',False)])
def test_signed_contract_accepts_only_unambiguous_native_assessment_paths(suffix,expected):
 import sys
 module=sys.modules['peaso.checks._bulk_pending_compliance_new_sw32']
 assert module._assessment_arm_identity(SCOPE+suffix,SCOPE)is expected
 assert module._assessment_arm_identity(SCOPE+suffix,'/subscriptions/33333333-3333-3333-3333-333333333333')is False
 assert module._assessment_arm_identity('/tenants/foreign'+suffix,SCOPE)is False
