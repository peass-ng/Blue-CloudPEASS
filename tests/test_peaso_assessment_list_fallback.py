"""Failed optional metadata must preserve only the actual bound LIST read."""
from test_peaso_azure_docker_assessment_native import reader,run,SCOPE,row
from peaso.collectors import azure
import pytest

def list_proof():
    return {'source_operation':'Assessments_List','read_only':True,'observed_at':'2020-01-01T00:00:00+00:00',
        'api_version':'2020-01-01','representation':'metadata','scope':SCOPE,
        'credential_context_id':'capture','customer_context_id':'customer'}

def test_failed_optional_metadata_preserves_list_observation_without_refreshing_or_promoting_it():
    r=reader();proof=list_proof();r.collections[1]['items'][0]['_provenance']=proof.copy()
    value,calls=run(r,azure.AzureReadError('denied',403))
    assert len(calls)==1 and value['_provenance']==proof
    assert value['properties']['status']['code']=='Unhealthy'
    assert 'metadata_expanded' not in value['_provenance']
    assert 'metadata' not in value['properties']
    assert value['properties']['_coverage']['metadata']['status']=='not_collected'

@pytest.mark.parametrize('name,value',[('scope','/subscriptions/foreign'),('credential_context_id','foreign'),('source_operation','Assessments_Get')])
def test_unbound_or_previous_get_proof_is_not_retained_after_failed_metadata(name,value):
    r=reader();proof=list_proof();proof[name]=value;r.collections[1]['items'][0]['_provenance']=proof
    actual,_=run(r,azure.AzureReadError('denied',403))
    assert '_provenance' not in actual
