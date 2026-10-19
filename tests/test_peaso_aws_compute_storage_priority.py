from copy import deepcopy
import pytest
from peaso.checks.aws_compute_storage_priority import contextual_severity

BASE={'provider':'aws','status':'FAIL','severity':'high','check_id':'aws.cb.lightsail.ssh_rdp_http_world_closed'}
@pytest.mark.parametrize('ports,expected',[([80],'medium'),([22],'high'),([3389],'high'),([22,80],'high'),([], 'high'),([443],'high'),(['80'],'high'),([True],'high'),([-1],'high'),(None,'high')])
def test_actual_port_evidence_controls_priority(ports,expected):
    finding={**BASE,'evidence':{'open_ports':ports}};before=deepcopy(finding)
    assert contextual_severity(finding)==expected
    assert finding==before

@pytest.mark.parametrize('change',[{'status':'UNKNOWN'},{'provider':'azure'},{'check_id':'unknown'},{'evidence':{}},{'check_id':'aws.cb.lightsail.ssh_restricted'}])
def test_uncertain_or_unrelated_facts_preserve_baseline(change):
    finding={**BASE,'evidence':{'open_ports':[80]},**change}
    assert contextual_severity(finding,'critical')=='critical'
