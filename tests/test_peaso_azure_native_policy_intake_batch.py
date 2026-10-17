"""Native owner-policy namespaces stay bounded and independent in hosted scans."""
import copy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso.server.validation import validate_connector
from tests.test_peaso_azure_function_limits_native import POLICY as FUNCTION

SUB=FUNCTION['scope']
INCIDENT={'status':'collected','scope':SUB,'incident_review':{'start':(datetime.now(timezone.utc)-timedelta(days=1)).isoformat(),'end':(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat(),'approved':True,'allowed_classifications':['TruePositive'],'allowed_priorities':['High','Medium','Low']}}
SEVERITY={'approved':True,'version':'v1','expectedSeverityByAssessmentName':{'11111111-2222-3333-4444-555555555555':'High'}}

def validate(provider,policy,mode):
 validate_connector(provider,{'method':'token','arm_token':'fixture'},{'compliance_policy':policy},SimpleNamespace(auth_mode=mode))

@pytest.mark.parametrize('mode',['local','cognito'])
@pytest.mark.parametrize('feature',['firewall','function','rotation','combined','incident','severity','incident_severity'])
def test_normative_features_are_independently_admitted(feature,mode):
 if feature in ('firewall','function','rotation','combined'):
  p={'status':'collected','scope':SUB}
  if feature in ('firewall','combined'):p['allowAzureServices']=False
  if feature in ('function','combined'):p.update(FUNCTION)
  if feature in ('rotation','combined'):p['maxDaysSinceRotation']=90
  policy={'sw15':p}
 else:
  p=copy.deepcopy(INCIDENT)
  if feature=='severity':p.pop('incident_review')
  if feature in ('severity','incident_severity'):p['vulnerability_severity_criteria']=copy.deepcopy(SEVERITY)
  policy={'sw32':p}
 original=copy.deepcopy(policy);validate('azure',policy,mode);assert policy==original

@pytest.mark.parametrize('mode',['local','cognito'])
@pytest.mark.parametrize('provider',['aws','gcp','k8s'])
@pytest.mark.parametrize('namespace',['sw15','sw32'])
def test_azure_policy_namespaces_reject_foreign_provider_before_local_return(provider,mode,namespace):
 policy={'sw15':copy.deepcopy(FUNCTION)}if namespace=='sw15'else{'sw32':copy.deepcopy(INCIDENT)}
 with pytest.raises(HTTPException)as e:validate(provider,policy,mode)
 assert e.value.status_code==422

@pytest.mark.parametrize('mode',['local','cognito'])
@pytest.mark.parametrize('namespace,field',[('sw15','operations_complete'),('sw15','authorized'),('sw15','currentVersion'),('sw32','finding_coverage_complete'),('sw32','assigned_severity_matches_criteria'),('sw32','process_evidence')])
def test_caller_cannot_supply_native_observations(namespace,field,mode):
 p=copy.deepcopy(FUNCTION if namespace=='sw15'else INCIDENT);p[field]=True
 with pytest.raises(HTTPException)as e:validate('azure',{namespace:p},mode)
 assert e.value.status_code==422

@pytest.mark.parametrize('mode',['local','cognito'])
@pytest.mark.parametrize('namespace',['sw15','sw32'])
@pytest.mark.parametrize('value',[None,[],True,{'status':'collected','scope':'/subscriptions/foreign'}])
def test_explicit_malformed_namespace_never_passes_intake(namespace,value,mode):
 with pytest.raises(HTTPException)as e:validate('azure',{namespace:copy.deepcopy(value)},mode)
 assert e.value.status_code==422

@pytest.mark.parametrize('mode',['local','cognito'])
def test_nested_severity_coverage_cannot_be_claimed_by_owner(mode):
 p=copy.deepcopy(INCIDENT);p['vulnerability_severity_criteria']=copy.deepcopy(SEVERITY)
 p['vulnerability_severity_criteria']['finding_coverage_complete']=True
 with pytest.raises(HTTPException)as e:validate('azure',{'sw32':p},mode)
 assert e.value.status_code==422


def test_iot_native_policy_preserves_other_sw16_owner_requirements():
 from tests.test_peaso_azure_iot_policy_native import capture,options,CHECK,SCOPE
 opts=options();other='azure.cis.monitor_resource_logging_services_support_it'
 review={'status':'collected','scope':SCOPE,'resources':[]}
 opts['compliance_policy']={'sw16':{other:copy.deepcopy(review)}}
 finding,snapshot,_=capture(opts=opts)
 assert finding['status']=='PASS'
 sw16=snapshot['metadata']['compliance_policy']['sw16']
 assert sw16[other]==review
 assert sw16[CHECK]['assignedDefinitionId']==opts['compliance_parameters']['azure_iot_policy']['assignedDefinitionId']


@pytest.mark.parametrize('mode',['local','cognito'])
def test_severity_owner_mapping_rejects_case_ambiguous_identity(mode):
 p={'status':'collected','scope':SUB,'vulnerability_severity_criteria':copy.deepcopy(SEVERITY)}
 p['vulnerability_severity_criteria']['expectedSeverityByAssessmentName']={
  'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee':'High',
  'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE':'Low'}
 with pytest.raises(HTTPException)as e:validate('azure',{'sw32':p},mode)
 assert e.value.status_code==422
