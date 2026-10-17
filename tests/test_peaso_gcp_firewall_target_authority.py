"""Firewall attribution is declaration metadata, never effective reachability."""
from copy import deepcopy
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
CID="gcp.compute.restrict_internet_ingress"
SCOPE="projects/p"
NETWORK="https://www.googleapis.com/compute/v1/projects/p/global/networks/n"
RULE={"network":NETWORK,"targetTags":["ssh"],"allowed":[{"IPProtocol":"tcp"}],"sourceRanges":["0.0.0.0/0"]}
VM={"name":"vm","status":"RUNNING","tags":{"items":["ssh"]},"serviceAccounts":[{"email":"svc@example.com"}],"networkInterfaces":[{"network":NETWORK,"accessConfigs":[{"natIP":"203.0.113.1"}]}]}

def deny(row,key):row.setdefault("_coverage",{})[key]={"status":"denied"}

def evidence(rule,instances,status="collected"):
    snap=make_snapshot("gcp",[SCOPE],[{"type":"firewall","scope":SCOPE,"status":"collected","items":[deepcopy(rule)]},{"type":"instance","scope":SCOPE,"status":status,"items":deepcopy(instances)}],created_at="2026-10-17T00:00:00Z")
    before=deepcopy(snap);rows=[f for f in evaluate_snapshot(snap,checks=[CID])["findings"] if f["check_id"]==CID]
    assert snap==before and len(rows)==1 and rows[0]["status"]=="FAIL"
    return rows[0]["evidence"]

def assert_unattributed(value):
    assert not isinstance(value["target_instances"],int)
    assert "practical_severity" not in value

def test_denied_rule_selector_or_network_cannot_claim_zero_low():
    for key in ("network","targetTags","targetServiceAccounts"):
        rule=deepcopy(RULE);rule["targetTags"]=["stale"];deny(rule,key)
        assert_unattributed(evidence(rule,[VM]))

def test_denied_instance_network_or_selector_cannot_claim_zero_low():
    for key in ("network","tags","serviceAccounts"):
        rule=deepcopy(RULE);vm=deepcopy(VM)
        if key=="network":vm["networkInterfaces"][0]["network"]=NETWORK+"-stale";deny(vm["networkInterfaces"][0],key)
        elif key=="tags":vm["tags"]={"items":["stale"]};deny(vm,key)
        else:rule["targetServiceAccounts"]=["expected@example.com"];vm["serviceAccounts"][0]["email"]="stale@example.com";deny(vm,key)
        assert_unattributed(evidence(rule,[vm]))

def test_denied_nested_tag_or_email_cannot_claim_zero():
    vm=deepcopy(VM);vm["tags"]["items"]=["stale"];deny(vm["tags"],"items")
    assert_unattributed(evidence(RULE,[vm]))
    vm=deepcopy(VM);vm["serviceAccounts"][0]["email"]="stale@example.com";deny(vm["serviceAccounts"][0],"email")
    rule=deepcopy(RULE);rule.pop("targetTags");rule["targetServiceAccounts"]=["svc@example.com"]
    assert_unattributed(evidence(rule,[vm]))

def test_known_zero_and_target_counts_retain_honest_annotations():
    vm=deepcopy(VM);vm["tags"]["items"]=["other"]
    value=evidence(RULE,[vm]);assert value["target_instances"]==0 and value["practical_severity"]=="low"
    value=evidence(RULE,[VM]);assert value["target_instances"]==1 and value["target_instances_running"]==1
    assert value["target_instance_sample"][0]["external_ip"] is True

def test_partial_match_counts_are_lower_bounds_not_complete_zero():
    unknown=deepcopy(VM);unknown["name"]="unknown";deny(unknown,"tags")
    for rows in ([VM,unknown],[unknown,VM]):
        value=evidence(RULE,rows);assert_unattributed(value)
        assert value["target_instances_lower_bound"]==1

def test_unavailable_running_status_does_not_become_zero_running():
    vm=deepcopy(VM);vm["status"]="TERMINATED";deny(vm,"status")
    value=evidence(RULE,[vm]);assert value["target_instances"]==1
    assert not isinstance(value["target_instances_running"],int)
    assert value["target_instances_running_lower_bound"]==0
    assert value["target_instance_sample"][0]["status"] is None

def test_unavailable_or_omitted_external_configs_have_distinct_labels():
    for field in ("accessConfigs","ipv6AccessConfigs"):
        vm=deepcopy(VM);nic=vm["networkInterfaces"][0];nic.pop("accessConfigs",None);deny(nic,field)
        value=evidence(RULE,[vm]);assert value["target_instance_sample"][0]["external_ip"] not in (True,False)
    vm=deepcopy(VM);vm["networkInterfaces"][0].pop("accessConfigs")
    assert evidence(RULE,[vm])["target_instance_sample"][0]["external_ip"] is False

def test_irrelevant_denied_selectors_and_known_network_mismatch():
    rule=deepcopy(RULE);rule.pop("targetTags")
    vm=deepcopy(VM);deny(vm,"tags");deny(vm,"serviceAccounts")
    assert evidence(rule,[vm])["target_instances"]==1
    vm["networkInterfaces"][0]["network"]=NETWORK+"-other"
    value=evidence(RULE,[vm]);assert value["target_instances"]==0 and value["practical_severity"]=="low"

def test_source_inventory_denial_and_malformed_network_fact_do_not_affect_verdict():
    assert_unattributed(evidence(RULE,[],status="denied"))
    vm=deepcopy(VM);vm["networkInterfaces"]=[None]
    assert_unattributed(evidence(RULE,[vm]))
