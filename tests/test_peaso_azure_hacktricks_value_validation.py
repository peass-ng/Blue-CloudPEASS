"""Read-only Azure configuration checks must not accept malformed declarations."""
from copy import deepcopy
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES

def evaluate(cid,item):
    return next(c for c in CHECKS if c.id==cid).evaluate(item,{})[0]

@pytest.mark.parametrize('modes,status',[([], 'PASS'),(['garbage'],'UNKNOWN'),(['sharedkey'],'UNKNOWN'),(['AAD'],'PASS'),(['TaskAuthenticationToken'],'PASS'),(['SharedKey'],'FAIL')])
def test_batch_unknown_authentication_mode_is_not_a_safe_default(modes,status):
    cid='azure.htbp.batch.shared_key_auth_disabled';item=deepcopy(CASES[cid]['pass'])
    item['properties']['allowedAuthenticationModes']=modes
    assert evaluate(cid,item)==status

@pytest.mark.parametrize('minutes,status',[(-1,'UNKNOWN'),(0,'UNKNOWN'),(60,'PASS'),(480,'PASS'),(481,'FAIL')])
def test_tap_lifetime_cannot_be_nonpositive(minutes,status):
    cid='azure.htbp.entra.temporary_access_pass_one_time';item=deepcopy(CASES[cid]['pass'])
    item['authenticationMethodConfigurations'][1]['maximumLifetimeInMinutes']=minutes
    assert evaluate(cid,item)==status

@pytest.mark.parametrize('start,end,status',[('255.255.255.255','0.0.0.0','UNKNOWN'),('203.0.113.1','203.0.113.9','PASS'),('0.0.0.0','255.255.255.255','FAIL'),('0.0.0.0','0.0.0.0','PASS')])
def test_synapse_reversed_address_range_is_not_compliant(start,end,status):
    cid='azure.htbp.synapse.firewall_no_allow_all_internet';item=deepcopy(CASES[cid]['fail'])
    item['firewallRules'][0]['properties'].update(startIpAddress=start,endIpAddress=end)
    assert evaluate(cid,item)==status
