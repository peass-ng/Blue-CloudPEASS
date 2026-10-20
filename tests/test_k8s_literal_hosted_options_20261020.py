"""Optional selected namespace literals reject broad and foreign selectors."""
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso.server.validation import OPTIONS,validate_connector
TARGET={'cluster_id':'review-cluster','namespace':'review','kind':'Pod','name':'review'}
def validate(targets,scopes=None,provider='k8s',flag=True):
    validate_connector(provider,{}, {'selected_k8s_literal_resources':targets,'content_secret_scans':flag},
                       SimpleNamespace(auth_mode='local'),scopes=['review']if scopes is None else scopes)
@pytest.mark.parametrize('kind',['Pod','ConfigMap'])
@pytest.mark.parametrize('flag',[False,True])
def test_exact_namespace_resource_selector_needs_no_credential_lookup(kind,flag):
    assert 'selected_k8s_literal_resources' in OPTIONS
    validate([{**TARGET,'kind':kind}],flag=flag)
@pytest.mark.parametrize('fault',['empty','none','string','duplicate','foreign_namespace','wildcard','many','secret','extra','clusters','wrong_provider'])
def test_invalid_selector_fails_before_authentication(fault):
    targets,scopes,provider=[dict(TARGET)],['review'],'k8s'
    if fault=='empty':targets=[]
    elif fault=='none':targets=None
    elif fault=='string':targets='review'
    elif fault=='duplicate':targets*=2
    elif fault=='foreign_namespace':targets[0]['namespace']='foreign'
    elif fault=='wildcard':scopes=['*','review']
    elif fault=='many':targets=[{**TARGET,'name':'review'+str(i)}for i in range(9)]
    elif fault=='secret':targets[0]['kind']='Secret'
    elif fault=='extra':targets[0]['server']='https://foreign.example'
    elif fault=='clusters':targets.append({**TARGET,'cluster_id':'foreign'})
    elif fault=='wrong_provider':provider='aws'
    with pytest.raises(HTTPException)as error:validate(targets,scopes,provider)
    assert error.value.status_code==422
