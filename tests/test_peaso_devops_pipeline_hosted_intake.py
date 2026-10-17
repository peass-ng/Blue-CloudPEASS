"""Portable hosted boundary tests: normative pins only, no provider calls."""
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso.server.validation import validate_connector

PROJECT='11111111-1111-1111-1111-111111111111'
SUB='/subscriptions/33333333-3333-3333-3333-333333333333'


def inputs():
    options={'compliance_parameters':{
        'azure_devops_git':{'subscriptions':[{'scope':SUB,'organization':'owned','project_ids':[PROJECT]}]},
        'azure_devops_pipelines':{'credentialVariableNames':['AZURE_CLIENT_SECRET'],
            'requiredVariableNames':['AZURE_CLIENT_SECRET'],
            'pipelines':[{'project_id':PROJECT,'pipeline_id':1,'definition_revision':3,'commit':'a'*40}]}}}
    return {'method':'token','token':'inert-arm-token','devops_credentials':[
        {'server':'https://dev.azure.com/owned','method':'pat','token':'inert-devops-token'}]},options


@pytest.mark.parametrize('mode',['local','cognito'])
def test_normative_pipeline_pins_accepted_in_both_modes(mode):
    auth,options=inputs()
    assert validate_connector('azure',auth,options,SimpleNamespace(auth_mode=mode)) is None


@pytest.mark.parametrize('mutation',['observations','complete','provenance','foreign-project','bool-id','branch-not-commit','unbound-applicability','foreign-provider'])
def test_hosted_rejects_observations_or_unbound_native_applicability(mutation):
    auth,options=inputs();policy=options['compliance_parameters']['azure_devops_pipelines'];provider='azure'
    if mutation=='observations':policy['variables']=[{'name':'AZURE_CLIENT_SECRET','isSecret':True}]
    if mutation=='complete':policy['coverage']='complete'
    if mutation=='provenance':policy['_provenance']={'read_only':True}
    if mutation=='foreign-project':policy['pipelines'][0]['project_id']='22222222-2222-2222-2222-222222222222'
    if mutation=='bool-id':policy['pipelines'][0]['pipeline_id']=True
    if mutation=='branch-not-commit':policy['pipelines'][0]['commit']='main'
    if mutation=='unbound-applicability':options['compliance_parameters'].pop('azure_devops_git');auth.pop('devops_credentials')
    if mutation=='foreign-provider':provider='gcp';auth={};options['compliance_parameters'].pop('azure_devops_git')
    with pytest.raises(HTTPException) as error:
        validate_connector(provider,auth,options,SimpleNamespace(auth_mode='cognito'))
    assert error.value.status_code==422


@pytest.mark.parametrize('mode',['local','cognito'])
def test_explicit_null_pipeline_namespace_is_not_absent(mode):
    from peaso.collectors.azure_devops_pipeline_native import normalize
    auth,options=inputs();options['compliance_parameters']['azure_devops_pipelines']=None
    with pytest.raises(ValueError):normalize(options,auth)
    with pytest.raises(HTTPException)as error:
        validate_connector('azure',auth,options,SimpleNamespace(auth_mode=mode))
    assert error.value.status_code==422
