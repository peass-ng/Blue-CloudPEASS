"""Cost alert intent is explicit owner input, never inferred from cloud facts."""
import copy
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso.collectors.aws_cost_policy import normalize
from peaso.collectors import aws
from peaso.server.validation import validate_connector

OPTIONS={'compliance_parameters':{'cost_anomaly_alerts':{'approved_recipients':['qa@example.invalid'],
 'cost_allocation_tag_key':'Environment','prod_tag_value':'Prod','qa_tag_value':'QA'}}}

def test_explicit_policy_does_not_mutate_input_or_certify_delivery():
 original=copy.deepcopy(OPTIONS);policy=normalize(OPTIONS)
 assert OPTIONS==original and policy['source']=='owner_declared_policy'
 assert policy['status']=='collected' and policy['delivery_verified']is False
 assert normalize({})is None and normalize({'compliance_parameters':{}})is None

@pytest.mark.parametrize('value',[
 {}, {'approved_recipients':[]}, {'approved_recipients':'qa@example.invalid'},
 {'approved_recipients':['x','x']}, {'approved_recipients':['x\ny']},
 {'approved_recipients':[' x']}, {'approved_recipients':['x'],'status':'collected'},
 {'approved_recipients':['x'],'prod_tag_value':'Prod'},
 {'approved_recipients':['x'],'cost_allocation_tag_key':False},
])
def test_invalid_policy_is_rejected_before_provider_calls(monkeypatch,value):
 def no_session(*args):raise AssertionError('credentials must not be acquired')
 monkeypatch.setattr(aws,'_session',no_session)
 options={'compliance_parameters':{'cost_anomaly_alerts':value}}
 with pytest.raises(ValueError):aws.collect({'provider':'aws','auth':{},'options':options},[])
 with pytest.raises(HTTPException)as failure:validate_connector('aws',{},options,SimpleNamespace(auth_mode='local'))
 assert failure.value.status_code==422

@pytest.mark.parametrize('provider',['gcp','azure','k8s'])
def test_policy_cannot_be_attached_to_another_provider(provider):
 with pytest.raises(HTTPException)as failure:validate_connector(provider,{},OPTIONS,SimpleNamespace(auth_mode='local'))
 assert failure.value.status_code==422

def test_valid_policy_is_accepted_by_local_intake():
 validate_connector('aws',{},OPTIONS,SimpleNamespace(auth_mode='local'))


def test_hosted_intake_accepts_declared_cost_policy_without_credential_changes():
 auth={'method':'access_keys','aws_access_key_id':'fixture-id','aws_secret_access_key':'fixture-secret'}
 before=copy.deepcopy((auth,OPTIONS))
 validate_connector('aws',auth,OPTIONS,SimpleNamespace(auth_mode='cognito'))
 assert (auth,OPTIONS)==before
