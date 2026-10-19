from copy import deepcopy
import pytest
from peaso.analysis.finding_clarity import HOW,ACTION,evidence_summary,network_priority
from peaso.analysis.common import finding
from peaso.remediation import template

@pytest.mark.parametrize('port,expected',[(443,'medium'),(80,'medium'),(22,'high'),(5432,'high')])
@pytest.mark.parametrize('provider',['aws','gcp','azure','k8s'])
def test_network_rule_priority_never_confuses_web_and_admin_ports(provider,port,expected):
    rules={
        'aws':{'IpProtocol':'tcp','FromPort':port,'ToPort':port},
        'gcp':{'allowed':[{'IPProtocol':'tcp','ports':[str(port)]}]},
        'azure':{'properties':{'protocol':'Tcp','destinationPortRange':str(port)}},
        'k8s':{'ports':[{'protocol':'TCP','port':port}]},
    }
    evidence={'rules':[{'native_rule':rules[provider]}]};before=deepcopy(evidence)
    assert network_priority(evidence)==expected
    assert evidence==before
    f={'check_id':'analysis.network_review','status':'MANUAL','evidence':evidence}
    s=evidence_summary(f)
    assert 'reachability is not established' in s
    if expected=='medium':assert 'TCP/'+str(port) in s

@pytest.mark.parametrize('rule',[{},None,{'IpProtocol':'-1'}, {'IpProtocol':'udp','FromPort':443,'ToPort':443},
    {'IpProtocol':'tcp','FromPort':80,'ToPort':443}, {'ports':[{'port':443,'endPort':444}]},
    {'properties':{'protocol':'*','destinationPortRange':'443'}}, {'allowed':[{'IPProtocol':'tcp'}]}])
def test_unresolved_protocols_ranges_and_malformed_rules_keep_priority(rule):
    assert network_priority({'rules':[{'native_rule':rule}]})=='high'


def test_mixed_rules_keep_high_priority():
    rules=[{'native_rule':{'IpProtocol':'tcp','FromPort':p,'ToPort':p}} for p in [443,22]]
    assert network_priority({'rules':rules})=='high'

@pytest.mark.parametrize('cid,provider',[(c,p) for c in sorted(HOW) for p in ['aws','gcp','azure','k8s'] if (c,p)!=('analysis.federated_trust','k8s')])
def test_projection_guidance_is_short_with_commands_and_refs_available(cid,provider):
    value=template(cid,provider)
    assert value is not None
    assert value['summary']==ACTION[cid] and value['steps']==[ACTION[cid]]
    assert len(value['steps'][0].split())<=30
    assert len(HOW[cid].split())<=35
    assert value.get('references')


def test_new_analysis_finding_has_specific_description_and_observation():
    resource={'provider':'aws','type':'security_group','id':'sg-1','scope':'123456789012/us-east-1','data':{'GroupId':'sg-1'}}
    e={'rules':[{'native_rule':{'IpProtocol':'tcp','FromPort':443,'ToPort':443}}]}
    actual=finding({},resource,'exposure','analysis.network_review','Review rule','high',e)
    assert actual['severity']=='medium'
    assert actual['status']=='MANUAL'
    assert actual['evidence']==e
    assert 'TCP/443' in actual['evidence_summary']
    assert actual['description']==HOW['analysis.network_review']
