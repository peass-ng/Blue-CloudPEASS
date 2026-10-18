"""NSG source-port facts are required to prove an Allow is fully shadowed."""
import copy

import pytest

from peaso.checks.claude_azure_common import nsg_rule
from peaso.engine import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
CID = "azure.claude.nsg_internet_ssh"


def rule(name, access, priority, source_port="*", source="Internet"):
    item = nsg_rule(name, "Tcp", source, "22", access=access)
    item["properties"].update(priority=priority, destinationAddressPrefix="*", sourcePortRange=source_port)
    return item


def assessed(rules):
    item = {"id": SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/n",
            "properties": {"securityRules": rules}}
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "nsg", "scope": SCOPE,
                                                  "status": "collected", "items": [item]}])
    before = copy.deepcopy(snapshot)
    imported = collect_snapshot({"connector": {"provider": "azure", "scopes": [SCOPE],
                                                 "options": {"snapshot": snapshot}}, "checks": [CID]})
    findings = [f for f in evaluate_snapshot(imported, checks=[CID])["findings"] if f["check_id"] == CID]
    assert len(findings) == 1 and snapshot == before and imported == before
    return findings[0]["status"]


def test_narrow_source_port_deny_cannot_shadow_wildcard_allow():
    assert assessed([rule("deny", "Deny", 100, "80"), rule("allow", "Allow", 200)]) == "FAIL"


def test_gap_in_multiple_deny_source_ports_keeps_exposure():
    denies = [rule("low", "Deny", 100, "0-1023"), rule("high", "Deny", 110, "1025-65535")]
    assert assessed([*denies, rule("allow", "Allow", 200)]) == "FAIL"


def test_joint_source_port_denies_can_shadow_full_allow():
    denies = [rule("low", "Deny", 100, "0-1023"), rule("high", "Deny", 110, "1024-65535")]
    assert assessed([*denies, rule("allow", "Allow", 200)]) == "PASS"


def test_wildcard_deny_covers_specific_allow_source_port():
    assert assessed([rule("deny", "Deny", 100), rule("allow", "Allow", 200, "80")]) == "PASS"


@pytest.mark.parametrize("mutate", [
    lambda p: p.pop("sourcePortRange"),
    lambda p: p.update(_coverage={"sourcePortRange": {"status": "denied"}}),
    lambda p: p.update(sourcePortRange="bad"),
    lambda p: p.update(sourcePortRange="80-79"),
    lambda p: p.update(sourcePortRanges="80"),
])
def test_unavailable_deny_source_port_cannot_prove_shadow(mutate):
    deny = rule("deny", "Deny", 100)
    mutate(deny["properties"])
    assert assessed([deny, rule("allow", "Allow", 200)]) == "UNKNOWN"


@pytest.mark.parametrize("mutate", [
    lambda p: p.pop("sourcePortRange"),
    lambda p: p.update(_coverage={"sourcePortRange": {"status": "denied"}}),
])
def test_unavailable_allow_source_port_cannot_prove_exposure(mutate):
    allow = rule("allow", "Allow", 200)
    mutate(allow["properties"])
    assert assessed([allow]) == "UNKNOWN"


def test_selected_plural_source_ports_ignore_unused_denied_singular():
    deny = rule("deny", "Deny", 100)
    deny["properties"].update(sourcePortRanges=["0-1023", "1024-65535"],
                              _coverage={"sourcePortRange": {"status": "denied"}})
    assert assessed([deny, rule("allow", "Allow", 200)]) == "PASS"


def test_source_port_deny_still_obeys_priority_and_ipv6_family():
    assert assessed([rule("late", "Deny", 300), rule("allow", "Allow", 200)]) == "FAIL"
    assert assessed([rule("ipv4", "Deny", 100, source="0.0.0.0/0"),
                     rule("allow6", "Allow", 200, source="::/0")]) == "FAIL"


def test_allow_source_port_union_requires_complete_deny():
    allow = rule("allow", "Allow", 200)
    allow["properties"].update(sourcePortRanges=["80", "443"])
    deny80 = rule("deny80", "Deny", 100, "80")
    deny443 = rule("deny443", "Deny", 110, "443")
    assert assessed([deny80, allow]) == "FAIL"
    assert assessed([deny80, deny443, allow]) == "PASS"


def test_denied_selected_plural_source_ports_cannot_use_singular_value():
    deny = rule("deny", "Deny", 100)
    deny["properties"].update(sourcePortRanges=["*"],
                              _coverage={"sourcePortRanges": {"status": "denied"}})
    assert assessed([deny, rule("allow", "Allow", 200)]) == "UNKNOWN"


def test_shadow_does_not_depend_on_rule_display_name():
    deny = rule("deny", "Deny", 100)
    deny.pop("name")
    assert assessed([deny, rule("allow", "Allow", 200)]) == "PASS"
