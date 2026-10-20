"""Exact optional app-settings targets fail before credential acquisition."""
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso.server.validation import OPTIONS, validate_connector
SCOPE='/subscriptions/11111111-1111-4111-8111-111111111111'
TARGET=SCOPE+'/resourceGroups/review/providers/Microsoft.Web/sites/review'

def validate(targets,provider='azure',scopes=None,flag=True):
    validate_connector(provider,{}, {'selected_azure_app_settings':targets,'content_secret_scans':flag},
                       SimpleNamespace(auth_mode='local'),scopes=[SCOPE] if scopes is None else scopes)

@pytest.mark.parametrize('suffix',['','/slots/staging'])
@pytest.mark.parametrize('flag',[True,False])
def test_exact_native_site_or_slot_target_accepted_without_credentials(suffix,flag):
    assert 'selected_azure_app_settings' in OPTIONS
    validate([TARGET+suffix],flag=flag)

@pytest.mark.parametrize('fault',['empty','none','string','duplicate','foreign','url','query','many','missing_scope','wrong_provider'])
def test_invalid_selector_rejected_before_authentication(fault):
    targets,scopes,provider=[TARGET],[SCOPE],'azure'
    if fault=='empty':targets=[]
    elif fault=='none':targets=None
    elif fault=='string':targets=TARGET
    elif fault=='duplicate':targets*=2
    elif fault=='foreign':targets=[TARGET.replace('11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222')]
    elif fault=='url':targets=['https://management.azure.com'+TARGET]
    elif fault=='query':targets=[TARGET+'?api-version=2025-03-01']
    elif fault=='many':targets=[TARGET+str(i)for i in range(9)]
    elif fault=='missing_scope':scopes=[]
    elif fault=='wrong_provider':provider='gcp'
    with pytest.raises(HTTPException)as error:validate(targets,provider,scopes)
    assert error.value.status_code==422
