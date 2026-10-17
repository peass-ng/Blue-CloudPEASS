"""Offline public-engine IPv6 NSG exposure and family-aware shadowing."""

import copy

import pytest

from peaso.checks.claude_azure_common import nsg_rule
from peaso.engine import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
CID = "azure.claude.nsg_internet_ssh"


def rule(name, source, access="Allow", priority=200, protocol="Tcp", port="22", dest="*"):
    item = nsg_rule(name, protocol, source, port, access=access)
    item["properties"].update(priority=priority, destinationAddressPrefix=dest)
    return item


def assessed(rules):
    item = {"id": SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/n",
            "properties": {"securityRules": rules}}
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "nsg", "scope": SCOPE, "status": "collected",
                                                "items": [item]}], metadata={"fixture": "offline NSG rule facts"})
    before = copy.deepcopy(snapshot)
    imported = collect_snapshot({"connector": {"provider": "azure", "scopes": [SCOPE],
                                               "options": {"snapshot": snapshot}}, "checks": [CID]})
    findings = [finding for finding in evaluate_snapshot(imported, checks=[CID])["findings"]
                if finding["check_id"] == CID]
    assert len(findings) == 1 and snapshot == before and imported == before
    return findings[0]["status"]


def test_universal_ipv6_cidr_is_internet_exposure():
    assert assessed([rule("allow6", "::/0")]) == "FAIL"


@pytest.mark.parametrize("deny_source,allow_source", [
    ("0.0.0.0/0", "::/0"),
    ("::/0", "0.0.0.0/0"),
    ("0.0.0.0/0", "*"),
    ("::/0", "Internet"),
])
def test_one_family_deny_cannot_close_the_other(deny_source, allow_source):
    assert assessed([rule("deny", deny_source, "Deny", 100), rule("allow", allow_source)]) == "FAIL"


@pytest.mark.parametrize("deny_source", ("::/0", "*", "Internet"))
def test_ipv6_or_dual_family_deny_shadows_ipv6_allow(deny_source):
    assert assessed([rule("deny", deny_source, "Deny", 100), rule("allow6", "::/0")]) == "PASS"


@pytest.mark.parametrize("allow_source", ("*", "Internet", ["0.0.0.0/0", "::/0"]))
def test_separate_family_denies_jointly_close_dual_family_allow(allow_source):
    assert assessed([rule("deny4", "0.0.0.0/0", "Deny", 100),
                     rule("deny6", "::/0", "Deny", 110), rule("allow", allow_source)]) == "PASS"


@pytest.mark.parametrize("change", (
    {"protocol": "Udp"}, {"port": "3389"}, {"dest": "10.0.0.4"}, {"priority": 300},
))
def test_ipv6_deny_must_match_protocol_port_destination_and_priority(change):
    deny = rule("deny6", "::/0", "Deny", 100, **{k: v for k, v in change.items() if k != "priority"})
    if "priority" in change:
        deny["properties"]["priority"] = change["priority"]
    assert assessed([deny, rule("allow6", "::/0")]) == "FAIL"
