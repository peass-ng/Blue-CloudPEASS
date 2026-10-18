"""A selected access config parent must support the configured presence label."""
from copy import deepcopy

from test_peaso_gcp_firewall_target_authority import RULE, VM, evidence


def _sample(vm):
    value = evidence(RULE, [vm])
    assert value["target_instances"] == 1
    assert value["target_instances_running"] == 1
    return value["target_instance_sample"][0]["external_ip"]


def test_explicit_empty_or_null_config_parent_is_unknown():
    for status in ("empty", None):
        vm = deepcopy(VM)
        vm["networkInterfaces"][0]["accessConfigs"] = [{"collection_status": status}]
        assert isinstance(_sample(vm), str)


def test_denied_ipv6_config_parent_is_unknown():
    vm = deepcopy(VM)
    nic = vm["networkInterfaces"][0]
    nic.pop("accessConfigs")
    nic["ipv6AccessConfigs"] = [{"_coverage": {"collection_status": {"status": "denied"}}}]
    assert isinstance(_sample(vm), str)


def test_independent_valid_config_remains_true():
    vm = deepcopy(VM)
    vm["networkInterfaces"][0]["ipv6AccessConfigs"] = [{"collection_status": "empty"}]
    assert _sample(vm) is True


def test_native_config_array_omission_remains_false():
    vm = deepcopy(VM)
    vm["networkInterfaces"][0].pop("accessConfigs")
    assert _sample(vm) is False
