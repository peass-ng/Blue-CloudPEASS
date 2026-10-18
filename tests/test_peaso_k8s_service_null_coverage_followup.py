"""Literal service annotations distinguish omitted from explicit unknown coverage."""
import pytest
from tests.test_peaso_k8s_service_selected_fact_authority import INTERNAL,SOURCE,observed

@pytest.mark.parametrize('key,value',[(INTERNAL,'true'),(SOURCE,'10.0.0.0/8')])
@pytest.mark.parametrize('retained',[True,False])
def test_explicit_null_literal_coverage_is_unknown(key,value,retained):
    annotations={'_coverage':{key:None}}
    if retained:annotations[key]=value
    assert observed({'spec':{'type':'LoadBalancer'},'metadata':{'annotations':annotations}})=='UNKNOWN'
