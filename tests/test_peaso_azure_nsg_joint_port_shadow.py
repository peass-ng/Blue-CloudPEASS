"""Offline NSG source/destination port rectangle shadowing through public evaluation."""
import copy

import pytest

from peaso.checks.claude_azure_common import nsg_rule
from peaso.engine import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
CID = "azure.claude.nsg_internet_udp_any"


def rule(name, access, priority, destination_ports, source_ports="*", source="Internet", destination="*"):
    item = nsg_rule(name, "Udp", source, destination_ports, access=access)
    item["properties"].update(priority=priority, sourcePortRange=source_ports,
                              destinationAddressPrefix=destination)
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


def test_adjacent_destination_denies_jointly_close_udp_range():
    rules = [rule("low", "Deny", 100, "100-150"),
             rule("high", "Deny", 110, "151-200"),
             rule("allow", "Allow", 200, "100-200")]
    assert assessed(rules) == "PASS"


def test_source_and_destination_quadrants_jointly_close_udp_range():
    rules = [rule("lower-left", "Deny", 100, "100-150", "0-1023"),
             rule("lower-right", "Deny", 110, "100-150", "1024-65535"),
             rule("upper", "Deny", 120, "151-200"),
             rule("allow", "Allow", 200, "100-200")]
    assert assessed(rules) == "PASS"


def test_diagonal_denies_leave_cross_product_corners_exposed():
    rules = [rule("lower-left", "Deny", 100, "100-150", "0-1023"),
             rule("upper-right", "Deny", 110, "151-200", "1024-65535"),
             rule("allow", "Allow", 200, "100-200")]
    assert assessed(rules) == "FAIL"


def test_ipv4_denies_cannot_complete_ipv6_destination_coverage():
    rules = [rule("v4-low", "Deny", 100, "100-150", source="0.0.0.0/0"),
             rule("v4-high", "Deny", 110, "151-200", source="0.0.0.0/0"),
             rule("v6-low", "Deny", 120, "100-150", source="::/0"),
             rule("allow", "Allow", 200, "100-200", source="*")]
    assert assessed(rules) == "FAIL"


@pytest.mark.parametrize("change", ["priority", "protocol", "destination"])
def test_each_joint_deny_must_still_match_other_rule_fields(change):
    lower = rule("low", "Deny", 100, "100-150")
    upper = rule("high", "Deny", 110, "151-200")
    if change == "priority":
        upper["properties"]["priority"] = 300
    elif change == "protocol":
        upper["properties"]["protocol"] = "Tcp"
    else:
        upper["properties"]["destinationAddressPrefix"] = "10.0.0.4"
    assert assessed([lower, upper, rule("allow", "Allow", 200, "100-200")]) == "FAIL"


def test_missing_selected_destination_port_remains_unknown():
    lower = rule("low", "Deny", 100, "100-150")
    lower["properties"].pop("destinationPortRange")
    assert assessed([lower, rule("allow", "Allow", 200, "100-200")]) == "UNKNOWN"


def test_missing_selected_source_port_remains_unknown():
    lower = rule("low", "Deny", 100, "100-150")
    lower["properties"].pop("sourcePortRange")
    assert assessed([lower, rule("allow", "Allow", 200, "100-200")]) == "UNKNOWN"
