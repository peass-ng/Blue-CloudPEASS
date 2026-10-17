"""Typed IP certificate identities, local external observations only."""
import pytest
from tests.compliance_draft_isolation import staged_registry
with staged_registry(('compliance_new_sw13',)):
    from test_peaso_compliance_new_sw13 import app_fixture, evaluate, raw, m

def case(host='192.0.2.7', names=None, ips=None, sni=None):
    item, index = app_fixture(m.TLS)
    raw(index,'app_service_endpoint')['hostname'] = host
    record = raw(index,'tls_endpoint_observation')
    record.update(hostname=host,sni=sni)
    record['leaf']['subjectAlternativeNames'] = names or []
    if ips is not None: record['leaf']['subjectAlternativeIpAddresses'] = ips
    return item,index

def test_dns_wildcard_cannot_certify_ip_reference_identity():
    item,index=case(names=['*.0.2.7'],sni='192.0.2.7')
    assert evaluate(m.TLS,item,index)[0] == 'UNKNOWN'

@pytest.mark.parametrize('host,ips,expected',[
 ('192.0.2.7',['192.0.2.7'],'PASS'),
 ('2001:db8::7',['2001:0db8:0000:0000:0000:0000:0000:0007'],'PASS'),
 ('192.0.2.7',['192.0.2.8'],'FAIL'),
 ('192.0.2.7',[],'FAIL'),
 ('192.0.2.7',['*.0.2.7'],'UNKNOWN'),
])
def test_ip_san_uses_exact_parsed_ip_identity(host,ips,expected):
    item,index=case(host=host,ips=ips)
    assert evaluate(m.TLS,item,index)[0] == expected

@pytest.mark.parametrize('names', [['192.0.2.7'],['*.0.2.7']])
def test_untyped_san_cannot_stand_in_for_ip_address_san(names):
    item,index=case(names=names)
    assert evaluate(m.TLS,item,index)[0] == 'UNKNOWN'

def test_ip_observation_claiming_sni_is_unresolved():
    item,index=case(ips=['192.0.2.7'],sni='192.0.2.7')
    assert evaluate(m.TLS,item,index)[0] == 'UNKNOWN'

@pytest.mark.parametrize('host,expected',[('app.example.com','PASS'),('deep.app.example.com','FAIL')])
def test_dns_wildcard_keeps_single_label_semantics(host,expected):
    item,index=case(host=host,names=['*.example.com'],sni=host)
    assert evaluate(m.TLS,item,index)[0] == expected
