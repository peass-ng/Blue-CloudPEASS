"""Selected public TCP ports must be found inside valid Lightsail intervals."""
from copy import deepcopy
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES

IDS=['aws.cb.lightsail.ssh_rdp_http_world_closed','aws.cb.lightsail.ssh_restricted','aws.cb.lightsail.rdp_restricted']
@pytest.mark.parametrize('cid',IDS)
@pytest.mark.parametrize('low,high,status',[(1,65535,'FAIL'),(0,65535,'FAIL'),(40000,40001,'PASS'),(-1,65535,'UNKNOWN'),(2,1,'UNKNOWN'),(0,65536,'UNKNOWN'),(True,65535,'UNKNOWN')])
def test_whole_and_malformed_port_intervals(cid,low,high,status):
    c=next(c for c in CHECKS if c.id==cid);item=deepcopy(CASES[cid]['fail']);p=item['networking']['ports'][0]
    p.update(fromPort=low,toPort=high,cidrs=['0.0.0.0/0'],ipv6Cidrs=[])
    before=deepcopy(item);out,evidence=c.evaluate(item,{})
    assert out==status
    assert item==before
    if status=='FAIL':
        expected=[22,80,3389] if cid.endswith('world_closed') else [22] if cid.endswith('ssh_restricted') else [3389]
        assert evidence['open_ports']==expected

@pytest.mark.parametrize('cid',IDS)
def test_existing_ipv6_scope_remains_explicit(cid):
    c=next(c for c in CHECKS if c.id==cid);item=deepcopy(CASES[cid]['fail']);p=item['networking']['ports'][0]
    p.update(fromPort=1,toPort=65535,cidrs=[],ipv6Cidrs=['::/0'])
    assert c.evaluate(item,{})[0]==('FAIL' if cid.endswith('world_closed') else 'PASS')
