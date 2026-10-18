"""Guest baseline input is scoped owner intent; it cannot supply observations."""
import copy
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso.collectors import azure
from peaso.collectors.azure_guest_policy import normalize
from peaso.server.validation import validate_connector
from tests.test_peaso_azure_guest_reports import case, collected, SUFFIXES, PREFIX, SCOPE, run

def options(suffix=SUFFIXES[0]):
 _,_,_,policy=case(suffix)
 return {'compliance_parameters':{'azure_guest_configuration':{'scope':SCOPE,'checks':{PREFIX+suffix:policy}}}}

@pytest.mark.parametrize('suffix',SUFFIXES)
def test_all_six_declared_baselines_are_accepted_without_observed_facts(suffix):
 value=options(suffix);before=copy.deepcopy(value);policy=normalize(value)
 assert value==before and policy['source']=='owner_declared_policy'
 assert policy['scope']==SCOPE and policy['status']=='collected'
 vm,_,native,_=case(suffix);reader,_=collected(vm,native)
 assert run(reader,suffix,policy['checks'][PREFIX+suffix])=='PASS'

@pytest.mark.parametrize('auth_mode',['local','cognito'])
def test_hosted_and_local_intake_accept_same_policy(auth_mode):
 auth={'method':'token','arm_token':'fixture-token'};value=options();before=copy.deepcopy((auth,value))
 validate_connector('azure',auth,value,SimpleNamespace(auth_mode=auth_mode))
 assert (auth,value)==before

@pytest.mark.parametrize('mutation',['scope','check','status','source','observation','empty_group','duplicate_group','age_bool','age_negative','identity','scope_field'])
def test_bad_or_self_attested_policy_rejected_before_credentials(monkeypatch,mutation):
 value=options();raw=value['compliance_parameters']['azure_guest_configuration'];policy=raw['checks'][PREFIX+SUFFIXES[0]]
 if mutation=='scope':raw['scope']='https://attacker.invalid'
 if mutation=='check':raw['checks']={'unknown':policy}
 if mutation=='status':raw['status']='collected'
 if mutation=='source':policy['source']='native'
 if mutation=='observation':policy['observedMembers']=['alice']
 if mutation=='empty_group':policy['approvedAdministrators']=[]
 if mutation=='duplicate_group':policy['approvedAdministrators']=['alice','ALICE']
 if mutation=='age_bool':policy['maxReportAgeSeconds']=True
 if mutation=='age_negative':policy['maxReportAgeSeconds']=-1
 if mutation=='identity':policy['assignmentName']='../../foreign'
 if mutation=='scope_field':raw['tenant_id']='foreign'
 monkeypatch.setattr(azure,'AzureTransport',lambda *args:pytest.fail('must not acquire credentials'))
 with pytest.raises(ValueError):azure.collect({'provider':'azure','scopes':[SCOPE],'options':value},[])
 with pytest.raises(HTTPException)as failure:validate_connector('azure',{},value,SimpleNamespace(auth_mode='local'))
 assert failure.value.status_code==422

def test_valid_policy_for_unselected_subscription_rejected_before_credentials(monkeypatch):
 monkeypatch.setattr(azure,'AzureTransport',lambda *args:pytest.fail('must not acquire credentials'))
 with pytest.raises(ValueError):azure.collect({'scopes':['22222222-2222-2222-2222-222222222222'],'options':options()},[])

@pytest.mark.parametrize('provider',['aws','gcp','k8s'])
def test_policy_is_azure_only(provider):
 with pytest.raises(HTTPException)as failure:validate_connector(provider,{},options(),SimpleNamespace(auth_mode='local'))
 assert failure.value.status_code==422

def test_empty_thumbprint_requirement_needs_explicit_approval():
 value=options(SUFFIXES[5]);policy=value['compliance_parameters']['azure_guest_configuration']['checks'][PREFIX+SUFFIXES[5]]
 policy['requiredThumbprints']=[]
 with pytest.raises(ValueError):normalize(value)
 policy['emptyRequiredSetApproved']=True
 assert normalize(value)['checks'][PREFIX+SUFFIXES[5]]['requiredThumbprints']==[]

def test_firewall_baseline_cannot_replace_missing_categories_with_observations():
 value=options(SUFFIXES[3]);settings=value['compliance_parameters']['azure_guest_configuration']['checks'][PREFIX+SUFFIXES[3]]['requiredSettings']
 del settings['notifications']
 with pytest.raises(ValueError):normalize(value)
 settings['notifications']={'category':'notifications','expected':True,'observed':True}
 with pytest.raises(ValueError):normalize(value)
