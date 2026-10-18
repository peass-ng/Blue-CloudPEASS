"""Offline Service Bus network-rule applicability and source correction fixtures."""

import copy

import pytest

from peaso.checks import CHECKS


CHECK = next(check for check in CHECKS if check.id == "azure.claude.servicebus_namespace_network_restricted")
SUBNET = "/subscriptions/s/resourceGroups/r/providers/Microsoft.Network/virtualNetworks/v/subnets/a"


def namespace(*, public="Enabled", action="Deny", ips=(), subnets=(), tier="Premium", status="Active"):
    return {"sku": {"tier": tier}, "properties": {"status": status},
            "networkRuleSet": {"properties": {"publicNetworkAccess": public, "defaultAction": action,
                                              "ipRules": list(ips), "virtualNetworkRules": list(subnets)}}}


def assess(item):
    original = copy.deepcopy(item)
    result = CHECK.evaluate(item, {})
    assert item == original
    return result


def test_public_disabled_is_direct_configuration_evidence():
    item = namespace(public="Disabled", action="Allow")
    del item["networkRuleSet"]["properties"]["ipRules"]
    assert assess(item)[0] == "PASS"
    item["properties"]["publicNetworkAccess"] = "Enabled"
    assert assess(item)[0] == "UNKNOWN"  # Contradictory observed namespace and rule-set flags.


def test_deny_requires_an_observed_allow_rule_and_allow_is_open():
    status, evidence = assess(namespace())
    assert status == "FAIL" and evidence["ip_rule_count"] == evidence["virtual_network_rule_count"] == 0
    assert "no IP or virtual-network rule" in evidence["reason"]
    assert assess(namespace(action="Allow"))[0] == "FAIL"
    assert assess(namespace(action="Allow", ips=[{"ipMask": "192.0.2.1"}]))[0] == "FAIL"


def test_bounded_ip_and_virtual_network_rules_support_configured_restriction():
    ip = {"ipMask": "192.0.2.0/24", "action": "Allow"}
    vnet = {"subnet": {"id": SUBNET}}
    for item in (namespace(ips=[ip]), namespace(subnets=[vnet]), namespace(ips=[ip], subnets=[vnet])):
        status, evidence = assess(item)
        assert status == "PASS"
        assert "runtime reachability are separate" in evidence["semantics"]
    item = namespace(ips=[ip])
    item["networkRuleSet"]["properties"]["trustedServiceAccessEnabled"] = True
    assert assess(item)[1]["trusted_service_access_enabled"] is True


@pytest.mark.parametrize("mask", ["0.0.0.0/0", "0.0.0.0"])
def test_world_allow_range_is_not_a_restriction(mask):
    # A host 0.0.0.0 is syntactically narrow; only the /0 form is whole IPv4.
    status = assess(namespace(ips=[{"ipMask": mask, "action": "Allow"}]))[0]
    assert status == ("FAIL" if mask.endswith("/0") else "PASS")


@pytest.mark.parametrize("masks,expected", [
    (["0.0.0.0/1", "128.0.0.0/1"], "FAIL"),
    (["128.0.0.0/1", "0.0.0.0/1", "0.0.0.0/2"], "FAIL"),
    (["0.0.0.0/2", "64.0.0.0/2"], "PASS"),
    (["0.0.0.0/1", "0.0.0.0/1"], "PASS"),
])
def test_ipv4_allow_union_is_bounded_or_covers_all(masks, expected):
    rules = [{"ipMask": mask, "action": "Allow"} for mask in masks]
    assert assess(namespace(ips=rules))[0] == expected
    if expected == "FAIL":
        assert assess(namespace(ips=rules, subnets=[{"subnet": {"id": SUBNET}}]))[0] == "FAIL"


@pytest.mark.parametrize("change", [
    lambda p: p.pop("ipRules"),
    lambda p: p.pop("virtualNetworkRules"),
    lambda p: p.update(ipRules={"ipMask": "192.0.2.1"}),
    lambda p: p.update(ipRules=[{"ipMask": "not-an-ip", "action": "Allow"}]),
    lambda p: p.update(ipRules=[{"ipMask": "::/0", "action": "Allow"}]),
    lambda p: p.update(ipRules=[{"ipMask": "192.0.2.1", "action": "Deny"}]),
    lambda p: p.update(virtualNetworkRules=[{"subnet": {"id": "subnet-only"}}]),
])
def test_missing_or_malformed_rules_are_unknown(change):
    item = namespace()
    change(item["networkRuleSet"]["properties"])
    assert assess(item)[0] == "UNKNOWN"


def test_denied_or_missing_rule_set_and_unsupported_public_mode_are_unknown():
    item = namespace()
    item["_coverage"] = {"networkRuleSet": {"status": "denied", "error": "403"}}
    assert assess(item)[0] == "UNKNOWN"
    item = namespace()
    del item["networkRuleSet"]
    assert assess(item)[0] == "UNKNOWN"
    assert assess(namespace(public="SecuredByPerimeter"))[0] == "UNKNOWN"


def test_explicit_premium_active_scope_and_missing_scope_facts():
    assert assess(namespace(tier="Standard"))[0] == "NOT_APPLICABLE"
    assert assess(namespace(tier="Basic"))[0] == "NOT_APPLICABLE"
    assert assess(namespace(status="Disabled"))[0] == "NOT_APPLICABLE"
    assert assess(namespace(status="Unknown"))[0] == "UNKNOWN"
    assert assess(namespace(status="Unknown", tier="Standard"))[0] == "UNKNOWN"
    item = namespace()
    del item["sku"]
    assert assess(item)[0] == "UNKNOWN"
    item = namespace()
    del item["properties"]["status"]
    assert assess(item)[0] == "UNKNOWN"
