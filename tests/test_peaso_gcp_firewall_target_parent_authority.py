"""Unavailable parent declarations cannot establish complete zero target attribution."""
from copy import deepcopy
import pytest
from test_peaso_gcp_firewall_target_authority import RULE,VM,NETWORK,evidence,assert_unattributed

@pytest.mark.parametrize("parent",["nic","tags"])
@pytest.mark.parametrize("mode",["empty","unreadable","null"])
def test_unavailable_parent_cannot_authorize_retained_nonmatch(parent,mode):
    vm=deepcopy(VM)
    row=vm["networkInterfaces"][0] if parent=="nic" else vm["tags"]
    if parent=="nic":row["network"]=NETWORK+"-stale"
    else:row["items"]=["stale"]
    row["collection_status"]="empty" if mode=="empty" else None if mode=="null" else "collected"
    if mode=="unreadable":row["_coverage"]={"collection_status":{"status":"denied"}}
    assert_unattributed(evidence(RULE,[vm]))

def test_native_empty_arrays_and_known_network_mismatch_are_still_decisive():
    assert evidence(RULE,[VM])["target_instances"]==1
    vm=deepcopy(VM);vm["tags"]["items"]=[]
    assert evidence(RULE,[vm])["target_instances"]==0
    vm["networkInterfaces"][0]["network"]=NETWORK+"-other"
    vm["tags"]["collection_status"]="empty"
    assert evidence(RULE,[vm])["target_instances"]==0
