"""Exact destination selector unions in offline public NSG evaluation."""
import copy

import pytest

from peaso.checks.claude_azure_common import nsg_rule
from peaso.engine import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
CID = "azure.claude.nsg_internet_ssh"
CID_UDP_ANY = "azure.claude.nsg_internet_udp_any"
DESTINATIONS = ("10.0.0.1", "10.0.0.2")


def rule(name, access, priority, destinations, *, source="Internet", protocol="Tcp",
         destination_ports="22", source_ports="*"):
    item = nsg_rule(name, protocol, source, destination_ports, access=access)
    item["properties"].update(priority=priority, destinationAddressPrefixes=list(destinations),
                              sourcePortRange=source_ports)
    return item


def assessed(rules, cid=CID):
    item = {"id": SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/n",
            "properties": {"securityRules": rules}}
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "nsg", "scope": SCOPE,
                                                  "status": "collected", "items": [item]}])
    before = copy.deepcopy(snapshot)
    imported = collect_snapshot({"connector": {"provider": "azure", "scopes": [SCOPE],
                                                 "options": {"snapshot": snapshot}}, "checks": [cid]})
    findings = [f for f in evaluate_snapshot(imported, checks=[cid])["findings"] if f["check_id"] == cid]
    assert len(findings) == 1 and snapshot == before and imported == before
    return findings[0]["status"]


def test_two_exact_destination_denies_jointly_shadow_allow():
    rules = [rule("deny-one", "Deny", 100, [DESTINATIONS[0]]),
             rule("deny-two", "Deny", 110, [DESTINATIONS[1]]),
             rule("allow", "Allow", 200, DESTINATIONS)]
    assert assessed(rules) == "PASS"


def test_one_uncovered_destination_remains_exposed():
    assert assessed([rule("deny-one", "Deny", 100, [DESTINATIONS[0]]),
                     rule("allow", "Allow", 200, DESTINATIONS)]) == "FAIL"


def test_wildcard_deny_covers_each_exact_destination():
    assert assessed([rule("deny-all", "Deny", 100, ["*"]),
                     rule("allow", "Allow", 200, DESTINATIONS)]) == "PASS"


def test_destination_port_cross_product_corners_remain_exposed():
    rules = [rule("first-low", "Deny", 100, [DESTINATIONS[0]], protocol="Udp", destination_ports="100-150"),
             rule("second-high", "Deny", 110, [DESTINATIONS[1]], protocol="Udp", destination_ports="151-200"),
             rule("allow", "Allow", 200, DESTINATIONS, protocol="Udp", destination_ports="100-200")]
    assert assessed(rules, CID_UDP_ANY) == "FAIL"


def test_destination_and_port_unions_cover_every_rectangle():
    rules = [rule("first-low", "Deny", 100, [DESTINATIONS[0]], protocol="Udp", destination_ports="100-150"),
             rule("first-high", "Deny", 110, [DESTINATIONS[0]], protocol="Udp", destination_ports="151-200"),
             rule("second-low", "Deny", 120, [DESTINATIONS[1]], protocol="Udp", destination_ports="100-150"),
             rule("second-high", "Deny", 130, [DESTINATIONS[1]], protocol="Udp", destination_ports="151-200"),
             rule("allow", "Allow", 200, DESTINATIONS, protocol="Udp", destination_ports="100-200")]
    assert assessed(rules, CID_UDP_ANY) == "PASS"


def test_source_port_cross_product_corners_remain_exposed():
    rules = [rule("first-low", "Deny", 100, [DESTINATIONS[0]], source_ports="0-1023"),
             rule("second-high", "Deny", 110, [DESTINATIONS[1]], source_ports="1024-65535"),
             rule("allow", "Allow", 200, DESTINATIONS)]
    assert assessed(rules) == "FAIL"


def test_family_and_destination_unions_both_required():
    denies = [rule("v4-first", "Deny", 100, [DESTINATIONS[0]], source="0.0.0.0/0"),
              rule("v4-second", "Deny", 110, [DESTINATIONS[1]], source="0.0.0.0/0"),
              rule("v6-first", "Deny", 120, [DESTINATIONS[0]], source="::/0")]
    allow = rule("allow", "Allow", 200, DESTINATIONS, source="*")
    assert assessed([*denies, allow]) == "FAIL"
    assert assessed([*denies, rule("v6-second", "Deny", 130, [DESTINATIONS[1]], source="::/0"),
                     allow]) == "PASS"


@pytest.mark.parametrize("change", ["priority", "protocol", "source", "destination"])
def test_each_deny_must_still_match_other_fields(change):
    second = rule("deny-two", "Deny", 110, [DESTINATIONS[1]])
    if change == "priority":
        second["properties"]["priority"] = 300
    elif change == "protocol":
        second["properties"]["protocol"] = "Udp"
    elif change == "source":
        second["properties"]["sourceAddressPrefix"] = "10.0.0.0/8"
    else:
        second["properties"]["destinationAddressPrefixes"] = ["10.0.0.3"]
    assert assessed([rule("deny-one", "Deny", 100, [DESTINATIONS[0]]), second,
                     rule("allow", "Allow", 200, DESTINATIONS)]) == "FAIL"


@pytest.mark.parametrize("selected_rule", ["deny", "allow"])
def test_missing_selected_destination_remains_unknown(selected_rule):
    deny = rule("deny", "Deny", 100, [DESTINATIONS[0]])
    allow = rule("allow", "Allow", 200, DESTINATIONS)
    selected = deny if selected_rule == "deny" else allow
    selected["properties"].pop("destinationAddressPrefixes")
    assert assessed([deny, allow]) == "UNKNOWN"
