# Historical fixture contracts; current native admission is tested separately.
"""Actual ARM response fields through the native collector and frozen SW16."""
import copy
import json
from datetime import datetime,timedelta,timezone
from urllib.parse import urlsplit,parse_qs
import pytest
from peaso.collectors import azure,azure_iot_policy_native as native
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from tests.test_peaso_azure_bulk_native import Transport,parent,SCOPE,SUB,BASE

CHECK=native.CHECK
DPS=BASE+'Microsoft.Devices/provisioningServices/provisioning'
DEF='/providers/Microsoft.Authorization/policyDefinitions/11111111-2222-3333-4444-555555555555'
ASSIGN=SCOPE+'/providers/Microsoft.Authorization/policyAssignments/cmk'
EXEMPT=SCOPE+'/providers/Microsoft.Authorization/policyExemptions/exempt'
LIST=SCOPE+'/providers/Microsoft.Devices/provisioningServices'
STATES=SCOPE+'/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults'
EXEMPTIONS=SCOPE+'/providers/Microsoft.Authorization/policyExemptions'

def options(**extra):
 return {'compliance_parameters':{'azure_iot_policy':{'status':'collected','scope':SCOPE,'assignedDefinitionId':DEF,'maxPolicyStateAge':3600}},**extra}

class API(Transport):
 def request(self,url,*,body=None,audience=azure.ARM):
  path=urlsplit(url).path
  if path==STATES:
   assert body=={},'PolicyInsights query is POST, never GET or triggerEvaluation'
   filt=parse_qs(urlsplit(url).query).get('$filter',[])
   assert len(filt)==1 and DEF in filt[0] and 'Microsoft.Devices/provisioningServices'in filt[0]
  else:assert body is None,'Only PolicyInsights query uses POST'
  assert audience==azure.ARM
  return super().request(url,body=body,audience=audience)

def fixture(mode='good'):
 now=datetime.now(timezone.utc)
 dps=parent(DPS,'Microsoft.Devices/provisioningServices',{'authorizationPolicies':[{'primaryKey':'private-marker'}]})
 state={'resourceId':DPS,'subscriptionId':SUB,'resourceType':'Microsoft.Devices/provisioningServices','policyAssignmentId':ASSIGN,'policyDefinitionId':DEF,'timestamp':now.isoformat(),'complianceState':'NonCompliant'if mode=='bad'else'Compliant','policyDefinitionAction':'audit','policyAssignmentScope':SCOPE,'policyAssignmentParameters':json.dumps({'effect':{'value':'Audit'}}),'policyDefinitionName':'private-marker'}
 assignment=parent(ASSIGN,'Microsoft.Authorization/policyAssignments',{'policyDefinitionId':DEF,'scope':SCOPE,'enforcementMode':'Default','parameters':{'effect':{'value':'Audit'}},'notScopes':[]})
 definition=parent(DEF,'Microsoft.Authorization/policyDefinitions',{'parameters':{'effect':{'type':'String','allowedValues':['Audit','Deny','Disabled'],'defaultValue':'Audit'}},'policyRule':{'if':{'field':'type','equals':'Microsoft.Devices/provisioningServices'},'then':{'effect':"[parameters('effect')]"}},'description':'private-marker'})
 m={LIST:{'value':[dps]},STATES:{'value':[state]},ASSIGN:assignment,DEF:definition,EXEMPTIONS:{'value':[]}}
 if mode=='changed_scope':state['policyAssignmentScope']=SCOPE+'/resourceGroups/foreign'
 if mode=='changed_effect':state['policyDefinitionAction']='disabled'
 if mode=='changed_parameters':state['policyAssignmentParameters']='{}'
 if mode=='changed_version':state['policyDefinitionVersion']='0.0.1'
 if mode=='assignment_modified_after_state':assignment['systemData']={'lastModifiedAt':(now+timedelta(seconds=1)).isoformat()}
 if mode=='definition_modified_after_state':definition['systemData']={'lastModifiedAt':(now+timedelta(seconds=1)).isoformat()}
 if mode=='slash_resource_type':state['resourceType']='/Microsoft.Devices/provisioningServices'
 if mode=='matching_version':
  state['policyDefinitionVersion']='1.0.0'
  definition['properties']['version']='1.0.0'
 if mode=='no_dps':m[LIST]={'value':[]}
 if mode=='missing_policy_state':m[STATES]={'value':[]}
 if mode=='stale':state['timestamp']=(now-timedelta(hours=2)).isoformat()
 if mode=='future':state['timestamp']=(now+timedelta(hours=2)).isoformat()
 if mode=='unknown_state':state['complianceState']='Exempt'
 if mode=='duplicate_state':m[STATES]['value']*=2
 if mode=='two_latest_states':m[STATES]['value'].append({**state,'timestamp':(now-timedelta(seconds=1)).isoformat()})
 if mode=='foreign_state':state['resourceId']=DPS.replace(SUB,'99999999-9999-9999-9999-999999999999')
 if mode=='uninventoried_dps':state['resourceId']=DPS+'foreign'
 if mode=='foreign_state_type':state['resourceType']='Microsoft.Devices/IotHubs'
 if mode=='foreign_state_subscription':state['subscriptionId']='99999999-9999-9999-9999-999999999999'
 if mode=='foreign_definition':state['policyDefinitionId']=DEF+'foreign'
 if mode=='foreign_assignment':state['policyAssignmentId']=ASSIGN.replace(SUB,'99999999-9999-9999-9999-999999999999')
 if mode=='wrong_assignment_get':assignment['id']=ASSIGN+'foreign'
 if mode=='wrong_assignment_type':assignment['type']='Microsoft.Devices/provisioningServices'
 if mode=='assignment_definition_changed':assignment['properties']['policyDefinitionId']=DEF+'foreign'
 if mode=='wrong_definition_get':definition['id']=DEF+'foreign'
 if mode=='wrong_definition_type':definition['type']='Microsoft.Authorization/policySetDefinitions'
 if mode=='missing_mode':assignment['properties'].pop('enforcementMode')
 if mode=='not_enforced':assignment['properties']['enforcementMode']='DoNotEnforce'
 if mode=='disabled':assignment['properties']['parameters']['effect']['value']='Disabled'
 if mode=='deny':
  assignment['properties']['parameters']['effect']['value']='Deny'
  state.update(policyDefinitionAction='deny',policyAssignmentParameters=json.dumps({'effect':{'value':'Deny'}}))
 if mode=='not_scope':assignment['properties']['notScopes']=[DPS]
 if mode=='resource_selector':assignment['properties']['resourceSelectors']=[{'name':'geo','selectors':[]}]
 if mode=='override':assignment['properties']['overrides']=[{'kind':'policyEffect','value':'Disabled'}]
 if mode=='missing_parameters':assignment['properties'].pop('parameters')
 if mode=='unknown_parameter':assignment['properties']['parameters']['unknown']={'value':'private-marker'}
 if mode=='unsupported_definition_parameters':definition['properties']['parameters']['unexpected']={'type':'String','defaultValue':'private-marker'}
 if mode=='unsupported_effect':definition['properties']['policyRule']['then']['effect']='DeployIfNotExists'
 if mode=='literal_effect':
  definition['properties'].update(parameters={},policyRule={'then':{'effect':'Audit'}})
  assignment['properties']['parameters']={}
  state['policyAssignmentParameters']='{}'
 if mode=='wrong_dps_type':dps['type']='Microsoft.Devices/IotHubs'
 if mode=='foreign_dps':dps['id']=DPS.replace(SUB,'99999999-9999-9999-9999-999999999999')
 if mode=='duplicate_dps':m[LIST]['value']*=2
 if mode in('dps_denied','states_denied','assignment_denied','definition_denied','exemptions_denied'):
  path={'dps_denied':LIST,'states_denied':STATES,'assignment_denied':ASSIGN,'definition_denied':DEF,'exemptions_denied':EXEMPTIONS}[mode]
  m[path]=azure.AzureReadError('forbidden',403)
 if mode in('active_exemption','expired_exemption','foreign_exemption','unknown_exemption_category','exemption_selectors','exemption_partial'):
  ex=parent(EXEMPT,'Microsoft.Authorization/policyExemptions',{'policyAssignmentId':ASSIGN,'exemptionCategory':'Waiver'})
  if mode=='expired_exemption':ex['properties']['expiresOn']=(now-timedelta(days=1)).isoformat()
  if mode=='foreign_exemption':ex['id']=EXEMPT.replace(SUB,'99999999-9999-9999-9999-999999999999')
  if mode=='unknown_exemption_category':ex['properties']['exemptionCategory']='Custom'
  if mode=='exemption_selectors':ex['properties']['policyDefinitionReferenceIds']=['private-marker']
  m[EXEMPTIONS]={'value':[ex]}
  if mode=='exemption_partial':m[EXEMPTIONS]=lambda q:azure.AzureReadError('forbidden',403)if'page'in q else{'value':[ex],'nextLink':azure.ARM+EXEMPTIONS+'?page=2'}
 if mode in('dps_second_page','dps_partial','dps_conflicting_pages'):
  other=copy.deepcopy(dps);other['properties']={'state':'Disabled'}
  m[LIST]=lambda q:({'value':[other]if mode=='dps_conflicting_pages'else[dps]}if mode!='dps_partial'else azure.AzureReadError('forbidden',403))if'page'in q else{'value':[dps]if mode=='dps_conflicting_pages'else[],'nextLink':azure.ARM+LIST+'?page=2'}
 if mode=='exemption_second_page_active':
  ex=parent(EXEMPT,'Microsoft.Authorization/policyExemptions',{'policyAssignmentId':ASSIGN,'exemptionCategory':'Waiver'})
  m[EXEMPTIONS]=lambda q:{'value':[ex]}if'page'in q else{'value':[],'nextLink':azure.ARM+EXEMPTIONS+'?page=2'}
 if mode in('states_partial','states_second_page','duplicate_state_pages','untrusted_continuation'):
  path=azure.ARM+STATES+'?'+urlencode_filter()+'&page=2'
  if mode=='untrusted_continuation':path='https://other.invalid'+STATES+'?page=2'
  m[STATES]=lambda q:({'value':[state]}if mode=='states_second_page'else{'value':[state]}if mode=='duplicate_state_pages'else azure.AzureReadError('forbidden',403))if'page'in q else{'value':[]if mode=='states_second_page'else[state],'@odata.nextLink':path}
 return m

def urlencode_filter():
 from urllib.parse import urlencode
 return urlencode({'api-version':'2024-10-01','$filter':"(resourceType eq 'Microsoft.Devices/provisioningServices' or resourceType eq '/Microsoft.Devices/provisioningServices') and policyDefinitionId eq '"+DEF+"'"})

def capture(mode='good',opts=None,planned=False):
 api=API(fixture(mode));connector={'provider':'azure','scopes':[SUB],'options':{'retries':0,**(options()if opts is None else opts)}}
 kinds=plan_collection({'connector':connector,'checks':[CHECK]})if planned else sorted(native.NATIVE_TYPES)
 snapshot=azure.collect(connector,kinds,transport=api)
 findings=evaluate_snapshot(snapshot,checks=[CHECK],include_not_applicable=True)['findings']
 assert len(findings)==1,findings
 assert 'private-marker'not in json.dumps(snapshot)
 return findings[0],snapshot,api

@pytest.mark.parametrize('mode,status',[
 ('dps_second_page','PASS'),('dps_partial','DENIED'),('dps_conflicting_pages','UNKNOWN'),('exemption_second_page_active','UNKNOWN'),('slash_resource_type','PASS'),('matching_version','PASS'),('good','PASS'),('bad','FAIL'),('deny','PASS'),('literal_effect','PASS'),('no_dps','NOT_APPLICABLE'),('states_second_page','PASS'),('expired_exemption','PASS'),
 ('changed_scope','UNKNOWN'),('changed_effect','UNKNOWN'),('changed_parameters','UNKNOWN'),('changed_version','UNKNOWN'),('assignment_modified_after_state','UNKNOWN'),('definition_modified_after_state','UNKNOWN'),('missing_policy_state','UNKNOWN'),('stale','UNKNOWN'),('future','UNKNOWN'),('unknown_state','UNKNOWN'),('duplicate_state','UNKNOWN'),('two_latest_states','UNKNOWN'),
 ('foreign_state','UNKNOWN'),('uninventoried_dps','UNKNOWN'),('foreign_state_type','UNKNOWN'),('foreign_state_subscription','UNKNOWN'),('foreign_definition','UNKNOWN'),('foreign_assignment','UNKNOWN'),
 ('wrong_assignment_get','UNKNOWN'),('wrong_assignment_type','UNKNOWN'),('assignment_definition_changed','UNKNOWN'),('wrong_definition_get','UNKNOWN'),('wrong_definition_type','UNKNOWN'),
 ('missing_mode','UNKNOWN'),('not_enforced','UNKNOWN'),('disabled','UNKNOWN'),('not_scope','UNKNOWN'),('resource_selector','UNKNOWN'),('override','UNKNOWN'),('missing_parameters','UNKNOWN'),('unknown_parameter','UNKNOWN'),('unsupported_definition_parameters','UNKNOWN'),('unsupported_effect','UNKNOWN'),
 ('wrong_dps_type','UNKNOWN'),('foreign_dps','UNKNOWN'),('duplicate_dps','UNKNOWN'),('dps_denied','DENIED'),('states_denied','DENIED'),('assignment_denied','DENIED'),('definition_denied','DENIED'),('exemptions_denied','DENIED'),
 ('active_exemption','UNKNOWN'),('foreign_exemption','UNKNOWN'),('unknown_exemption_category','UNKNOWN'),('exemption_selectors','UNKNOWN'),('exemption_partial','DENIED'),('states_partial','DENIED'),('duplicate_state_pages','UNKNOWN'),('untrusted_continuation','UNKNOWN')])
def test_real_arm_metadata_to_frozen_engine(mode,status):
 finding,snapshot,api=capture(mode)
 assert finding['status']==status,finding
 assert all('listKeys'not in url and'triggerEvaluation'not in url for url in api.calls)

@pytest.mark.parametrize('mutation',['missing','foreign_scope','inject_observation','bad_age','bad_definition','default_null'])
def test_owner_inputs_never_create_native_observations(mutation):
 opts=options();p=opts['compliance_parameters']['azure_iot_policy']
 if mutation=='missing':opts={}
 if mutation=='foreign_scope':p['scope']='/subscriptions/99999999-9999-9999-9999-999999999999'
 if mutation=='inject_observation':p['complianceState']='Compliant'
 if mutation=='bad_age':p['maxPolicyStateAge']=True
 if mutation=='bad_definition':p['assignedDefinitionId']='https://untrusted.invalid/definition'
 if mutation=='default_null':opts['compliance_parameters']['azure_iot_policy']=None
 if mutation in('inject_observation','bad_age','bad_definition','default_null'):
  with pytest.raises(ValueError):native.normalize(opts)
 else:assert capture(opts=opts)[0]['status']=='UNKNOWN'

def test_actual_planner_admits_all_three_exact_native_types():
 finding,snapshot,_=capture(planned=True)
 assert finding['status']=='PASS'
 assert native.NATIVE_TYPES<={c['type']for c in snapshot['collections']}


@pytest.mark.parametrize('mode',['local','cognito'])
def test_hosted_policy_roundtrip_keeps_only_normative_inputs(mode):
 from types import SimpleNamespace
 from peaso.server.validation import validate_connector
 opts=options()
 validate_connector('azure',{'method':'token','arm_token':'fixture'},opts,SimpleNamespace(auth_mode=mode))
 assert capture(opts=opts,planned=True)[0]['status']=='PASS'

@pytest.mark.parametrize('provider',['aws','gcp','k8s'])
@pytest.mark.parametrize('mode',['local','cognito'])
def test_intake_rejects_foreign_provider_before_auth_mode_return(provider,mode):
 from types import SimpleNamespace
 from fastapi import HTTPException
 from peaso.server.validation import validate_connector
 with pytest.raises(HTTPException)as rejected:
  validate_connector(provider,{},options(),SimpleNamespace(auth_mode=mode))
 assert rejected.value.status_code==422

@pytest.mark.parametrize('mode',['local','cognito'])
def test_intake_rejects_observation_claims(mode):
 from types import SimpleNamespace
 from fastapi import HTTPException
 from peaso.server.validation import validate_connector
 opts=options();opts['compliance_parameters']['azure_iot_policy']['Compliant']=True
 with pytest.raises(HTTPException)as rejected:
  validate_connector('azure',{},opts,SimpleNamespace(auth_mode=mode))
 assert rejected.value.status_code==422


def test_empty_native_dps_inventory_never_queries_policy_or_needs_approval():
 finding,snapshot,api=capture('no_dps',opts={})
 assert finding['status']=='NOT_APPLICABLE'
 assert all('PolicyInsights'not in url and 'policyExemptions'not in url for url in api.calls)
 assert all(c['status']=='empty'for c in snapshot['collections']if c['type']in native.NATIVE_TYPES)

@pytest.mark.parametrize('cap',['max_calls','max_pages','max_resources'])
def test_explicit_collection_caps_never_prove_complete_dps_compliance(cap):
 mode='states_second_page'if cap in('max_pages','max_calls')else'two_latest_states'
 finding,snapshot,_=capture(mode,opts=options(**{cap:1}))
 assert finding['status']in('UNKNOWN','DENIED')


def test_explicit_dps_only_inventory_never_activates_policy_queries():
 api=API(fixture())
 snapshot=azure.collect({'scopes':[SUB],'options':{'retries':0}},['iot_dps'],transport=api)
 assert {c['type']for c in snapshot['collections']}=={'iot_dps'}
 assert not any('PolicyInsights'in url or'policyExemptions'in url for url in api.calls)
