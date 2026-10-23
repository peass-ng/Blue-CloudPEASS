"""Public finding bounds and secret-only evidence remain independent per call."""
import importlib.util
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import pytest

spec=importlib.util.spec_from_file_location('peaso.storage._summary_test',Path(__file__).resolve().parents[1]/'peaso/storage/reports.py')
reports=importlib.util.module_from_spec(spec);spec.loader.exec_module(reports)


@pytest.mark.parametrize('field,maximum',[('title',400),('resource_id',1000),('scope',500),('remediation',1000),
    ('service',100),('check_id',200),('category',100),('provider',30),('native_resource_id',2000),('id',2000)])
def test_summary_preserves_exact_string_bounds_and_input(field,maximum):
    value='Å'*maximum
    original={field:value,'private_extra':'not public','evidence':{'private':'not public'},'finding_type':'logging'}
    result=reports.finding_summary(original)
    assert result[field]==value and result['finding_type']=='logging' and result['detail_available'] is True
    assert 'private_extra'not in result and 'evidence'not in result and 'summary_truncated'not in result
    longer=dict(original,**{field:value+'extra'})
    clipped=reports.finding_summary(longer)
    assert clipped[field]==value+' [Full value available in finding detail]' and clipped['summary_truncated'] is True
    assert longer[field]==value+'extra'


def test_secret_evidence_eligibility_does_not_leak_across_concurrent_calls():
    def summary(index):
        secret=index%2==0
        original={'id':str(index),'evidence_summary':'recorded metadata',
            'secret_fingerprint':'synthetic'if secret else'', 'frameworks':['Reviewed']}
        value=reports.finding_summary(original)
        assert ('evidence_summary'in value)==secret
        assert value['frameworks']==['Reviewed'] and original['evidence_summary']=='recorded metadata'
        return value
    with ThreadPoolExecutor(8)as pool:assert len(list(pool.map(summary,range(128))))==128


@pytest.mark.parametrize('value',[None,17,False,['a'],{'a':'b'}])
def test_non_string_public_values_keep_existing_shape(value):
    assert reports.finding_summary({'title':value})['title']==value
