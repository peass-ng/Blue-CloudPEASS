"""Value-level correlation retains a trusted positive's coverage limitation."""
from copy import deepcopy
import pytest
from peaso.secret_findings import deduplicate_secret_findings


def finding(complete,source='first'):
    return {'provider':'k8s','id':source,'check_id':'k8s.review.selected_literals.secret_indicators',
            'resource_id':source,'scope':'apps','status':'FAIL','frameworks':[],
            'evidence':{'complete':complete,'unrelated_private_value':'MUST_NOT_SURVIVE',
                        'secret_leaks':[{'fingerprint':'a'*64,'detectors':[{'engine':'kingfisher','rule':'fixture'}],
                                         'locations':[{'path':source+'.literals','line':1}]}]}}

@pytest.mark.parametrize('values',[[False],[False,True],[True,False]])
def test_one_leak_preserves_incomplete_positive_independent_of_merge_order(values):
    sources=[finding(value,str(i))for i,value in enumerate(values)];before=deepcopy(sources)
    out=deduplicate_secret_findings(sources)
    assert sources==before and len(out)==1
    assert out[0]['status']=='FAIL'
    assert out[0]['evidence']['complete']is False
    assert out[0]['evidence']['coverage']=='incomplete'
    assert out[0]['evidence']['observed'].endswith('Coverage is incomplete.')
    assert 'MUST_NOT_SURVIVE'not in str(out)
    assert len(out[0]['evidence']['secret_leaks'][0]['locations'])==len(values)


def test_grouping_does_not_invent_a_full_coverage_claim():
    out=deduplicate_secret_findings([finding(True)])
    assert 'complete'not in out[0]['evidence']
    assert 'Coverage is incomplete.'not in out[0]['evidence']['observed']
