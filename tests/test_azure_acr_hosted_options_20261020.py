"""Hosted image selectors cannot expand registry hosts or subscription scope."""
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso.server.validation import OPTIONS,validate_connector
SCOPE='/subscriptions/11111111-1111-4111-8111-111111111111'
TARGET={'registry_id':SCOPE+'/resourceGroups/review/providers/Microsoft.ContainerRegistry/registries/review',
        'repository':'app/review','digest':'sha256:'+'1'*64}
def validate(targets,scopes=None,provider='azure'):
    validate_connector(provider,{}, {'selected_azure_acr_images':targets,'content_secret_scans':True},
                       SimpleNamespace(auth_mode='local'),scopes=[SCOPE]if scopes is None else scopes)
def test_immutable_scoped_image_target_accepted_before_authentication():
    assert 'selected_azure_acr_images'in OPTIONS
    validate([dict(TARGET)])
@pytest.mark.parametrize('fault',['empty','none','string','duplicate','foreign','url','tag','upper_digest','path_escape','extra_host','many','no_scopes','wrong_provider'])
def test_invalid_image_selector_rejected_before_authentication(fault):
    targets,scopes,provider=[dict(TARGET)],[SCOPE],'azure'
    if fault=='empty':targets=[]
    elif fault=='none':targets=None
    elif fault=='string':targets='review'
    elif fault=='duplicate':targets*=2
    elif fault=='foreign':targets[0]['registry_id']=TARGET['registry_id'].replace('11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222')
    elif fault=='url':targets[0]['registry_id']='https://management.azure.com'+TARGET['registry_id']
    elif fault=='tag':targets[0]['digest']='latest'
    elif fault=='upper_digest':targets[0]['digest']='sha256:'+'A'*64
    elif fault=='path_escape':targets[0]['repository']='../foreign'
    elif fault=='extra_host':targets[0]['host']='foreign.example'
    elif fault=='many':targets=[{**TARGET,'repository':'app'+str(i)}for i in range(5)]
    elif fault=='no_scopes':scopes=[]
    elif fault=='wrong_provider':provider='gcp'
    with pytest.raises(HTTPException)as error:validate(targets,scopes,provider)
    assert error.value.status_code==422
