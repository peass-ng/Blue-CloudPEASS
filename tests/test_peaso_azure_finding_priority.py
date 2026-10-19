from copy import deepcopy

import pytest

from peaso.checks.azure_finding_priority import contextual_severity


def finding(ports, **changes):
    result = {"check_id": "azure.claude.vm_nic_nsg_internet_tcp_ingress", "status": "FAIL", "severity": "high",
              "evidence": {"internet_allow_rules": [{"ports": ports}]}}
    result.update(changes)
    return result


@pytest.mark.parametrize("ports", [["443"], ["80", "443"], ["443-443"], [443]])
def test_web_only_declarations_are_medium(ports):
    value = finding(ports)
    before = deepcopy(value)
    assert contextual_severity(value) == "medium"
    assert value == before


@pytest.mark.parametrize("ports", [["22"], ["443", "22"], ["3389"], ["1433"], ["*"], ["0-65535"], ["80-443"]])
def test_administrative_data_and_broad_ranges_are_high(ports):
    assert contextual_severity(finding(ports, severity="critical")) == "high"


@pytest.mark.parametrize("ports", [None, [], ["invalid"], [None], [True], [65536], ["443;22"], ["100-1"]])
def test_missing_and_malformed_port_data_retains_baseline(ports):
    assert contextual_severity(finding(ports, severity="low")) == "low"


def test_unknown_status_non_nsg_and_unrelated_evidence_preserve_baseline():
    assert contextual_severity(finding(["443"], status="UNKNOWN")) == "high"
    assert contextual_severity(finding(["443"], check_id="azure.storage.no_public_network")) == "high"
    assert contextual_severity(finding(["443"], evidence={})) == "high"
    assert contextual_severity(None, "medium") == "medium"
    assert contextual_severity(finding(["443"], status="UNKNOWN"), "low") == "low"


def test_native_nsg_rule_shapes_and_icmp_scope():
    value = {"check_id": "azure.claude.nsg_internet_http_https", "status": "FAIL", "severity": "high",
             "evidence": {"direction": "Inbound", "exposed_rules": [{"protocol": "tcp", "port": 443}]}}
    assert contextual_severity(value) == "medium"
    value["evidence"]["exposed_rules"].append({"protocol": "tcp", "port": 22})
    assert contextual_severity(value) == "high"
    value["evidence"]["exposed_rules"] = [{"protocol": "icmp", "port": "all"}]
    assert contextual_severity(value, "medium") == "medium"
    value["evidence"]["direction"] = "Outbound"
    assert contextual_severity(value, "low") == "low"


def test_unreviewed_nsg_like_identifier_does_not_gain_contextual_downgrade():
    value = {"check_id": "azure.claude.nsg_internet_future_unreviewed", "status": "FAIL", "severity": "high",
             "evidence": {"direction": "Inbound", "exposed_rules": [{"protocol": "tcp", "port": 443}]}}
    assert contextual_severity(value) == "high"

@pytest.mark.parametrize('cid,key,port_key',[('azure.network.restrict_internet_ingress','broad_ingress_rules','destination_ports'),('azure.gap.nsg_declared_internet_http_https','declared_internet_allow_rules','ports')])
@pytest.mark.parametrize('ports,expected',[(['443'],'medium'),(['443','22'],'high'),(['80-81'],'high'),(['garbage'],'critical')])
def test_additional_source_bound_rule_declarations_have_consistent_contextual_priority(cid,key,port_key,ports,expected):
    value={'check_id':cid,'status':'FAIL','severity':'critical','evidence':{key:[{'protocol':'Tcp',port_key:ports}]}}
    assert contextual_severity(value)==expected
