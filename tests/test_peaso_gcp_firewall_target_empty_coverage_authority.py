"""Contradictory empty coverage cannot authorize firewall target metadata."""
from copy import deepcopy

import pytest

from tests.test_peaso_gcp_firewall_target_authority import RULE, VM, NETWORK, evidence, assert_unattributed


def empty(row, key):
    row.setdefault("_coverage", {})[key] = {"status": "empty"}


@pytest.mark.parametrize("location", [
    "rule_network", "rule_tags", "rule_accounts", "instance_nic_network",
    "instance_tags_items", "instance_account_email", "instance_nics",
])
def test_retained_nonempty_selected_fact_with_empty_coverage_cannot_prove_zero(location):
    rule, vm = deepcopy(RULE), deepcopy(VM)
    if location == "rule_network":
        rule["network"] = NETWORK + "-stale"; empty(rule, "network")
    elif location == "rule_tags":
        rule["targetTags"] = ["stale"]; empty(rule, "targetTags")
    elif location == "rule_accounts":
        rule["targetTags"] = []; rule["targetServiceAccounts"] = ["stale@example.com"]
        empty(rule, "targetServiceAccounts")
    elif location == "instance_nic_network":
        vm["networkInterfaces"][0]["network"] = NETWORK + "-stale"
        empty(vm["networkInterfaces"][0], "network")
    elif location == "instance_tags_items":
        vm["tags"]["items"] = ["stale"]; empty(vm["tags"], "items")
    elif location == "instance_account_email":
        rule["targetTags"] = []; rule["targetServiceAccounts"] = ["svc@example.com"]
        vm["serviceAccounts"][0]["email"] = "stale@example.com"
        empty(vm["serviceAccounts"][0], "email")
    else:
        vm["networkInterfaces"] = [{"network": NETWORK + "-stale"}]
        empty(vm, "networkInterfaces")
    assert_unattributed(evidence(rule, [vm]))


def test_consistent_empty_arrays_and_native_omission_still_decide_membership():
    rule, vm = deepcopy(RULE), deepcopy(VM)
    rule["targetTags"] = []; empty(rule, "targetTags")
    vm["tags"]["items"] = []; empty(vm["tags"], "items")
    assert evidence(rule, [vm])["target_instances"] == 1
    vm["networkInterfaces"] = []; empty(vm, "networkInterfaces")
    value = evidence(rule, [vm])
    assert value["target_instances"] == 0 and value["practical_severity"] == "low"
    vm = deepcopy(VM); vm.pop("tags")
    assert evidence(rule, [vm])["target_instances"] == 1


def test_known_network_mismatch_excludes_unknown_tags_and_partial_membership_has_bound():
    mismatch = deepcopy(VM)
    mismatch["networkInterfaces"][0]["network"] = NETWORK + "-other"
    mismatch["tags"]["items"] = ["stale"]; empty(mismatch["tags"], "items")
    value = evidence(RULE, [mismatch])
    assert value["target_instances"] == 0 and value["practical_severity"] == "low"
    unresolved = deepcopy(VM); unresolved["name"] = "unknown"; unresolved["tags"]["items"] = ["stale"]
    empty(unresolved["tags"], "items")
    value = evidence(RULE, [VM, unresolved])
    assert_unattributed(value)
    assert value["target_instances_lower_bound"] == 1


def test_empty_coverage_cannot_use_retained_running_or_external_config_labels():
    vm = deepcopy(VM); empty(vm, "status")
    value = evidence(RULE, [vm])
    assert value["target_instances"] == 1
    assert not isinstance(value["target_instances_running"], int)
    vm = deepcopy(VM); empty(vm["networkInterfaces"][0], "accessConfigs")
    value = evidence(RULE, [vm])
    assert value["target_instance_sample"][0]["external_ip"] not in (True, False)
    vm["networkInterfaces"][0]["accessConfigs"] = []
    assert evidence(RULE, [vm])["target_instance_sample"][0]["external_ip"] is False
