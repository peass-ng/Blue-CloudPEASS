"""Real engine regression for unavailable or invalid NSG rule declarations; no cloud."""
import copy
import pytest
from peaso.checks.claude_azure_common import nsg_rule
from peaso.engine import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
DECLARATION = "azure.gap.nsg_declared_internet_ssh"
EXPOSURE = "azure.claude.nsg_internet_ssh"


def assessed(rules, cid=DECLARATION):
    item = {"id": SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/test", "properties": {"securityRules": rules}}
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "nsg", "scope": SCOPE, "status": "collected", "items": [item]}], metadata={"fixture": "inert ARM-shaped NSG facts"})
    before = copy.deepcopy(snapshot)
    imported = collect_snapshot({"connector": {"provider": "azure", "scopes": [SCOPE], "options": {"snapshot": snapshot}}, "checks": [cid]})
    findings = [f for f in evaluate_snapshot(imported, checks=[cid])["findings"] if f["check_id"] == cid]
    assert len(findings) == 1 and snapshot == before and imported == before
    return findings[0]["status"]


@pytest.mark.parametrize("port", ["65536", "70000-80000", "443-80", "1-65536", "+22", "-1"])
def test_invalid_port_declaration_cannot_claim_compliance(port):
    assert assessed([nsg_rule("rule", "Tcp", "Internet", port)]) == "UNKNOWN"


@pytest.mark.parametrize("field,value", [("direction", "Outbound"), ("access", "Deny"), ("protocol", "Udp"), ("sourceAddressPrefix", "10.0.0.0/8"), ("destinationPortRange", "443")])
def test_unavailable_selected_rule_field_cannot_claim_compliance(field, value):
    rule = nsg_rule("rule", "Tcp", "Internet", "22")
    rule["properties"][field] = value
    rule["properties"]["_coverage"] = {field: {"status": "denied"}}
    assert assessed([rule]) == "UNKNOWN"


@pytest.mark.parametrize("protocol", ["NotAProtocol", "", "6"])
def test_unrecognized_azure_protocol_is_not_a_safe_rule(protocol):
    assert assessed([nsg_rule("rule", protocol, "Internet", "22")]) == "UNKNOWN"


@pytest.mark.parametrize("field", ["priority", "direction", "access", "protocol", "sourceAddressPrefix", "destinationPortRange", "destinationAddressPrefix"])
def test_unavailable_deny_cannot_prove_effective_shadowing(field):
    deny = nsg_rule("deny", "*", "Internet", "*", access="Deny")
    deny["properties"].update(priority=100, destinationAddressPrefix="*")
    deny["properties"]["_coverage"] = {field: {"status": "denied"}}
    allow = nsg_rule("open", "Tcp", "Internet", "22")
    allow["properties"].update(priority=200, destinationAddressPrefix="*")
    assert assessed([deny, allow], EXPOSURE) == "UNKNOWN"


@pytest.mark.parametrize("port,expected", [("0", "PASS"), ("65535", "PASS"), ("0-65535", "FAIL"), ("22", "FAIL")])
def test_valid_azure_port_domain_keeps_original_declaration_semantics(port, expected):
    assert assessed([nsg_rule("rule", "Tcp", "Internet", port)]) == expected


def test_nullable_unused_plural_fields_preserve_valid_singular_source():
    rule = nsg_rule("trusted", "Tcp", "10.0.0.0/8", "22")
    rule["properties"].update(sourceAddressPrefixes=None, destinationPortRanges=None)
    assert assessed([rule]) == "PASS"


@pytest.mark.parametrize("cid,protocol", [(DECLARATION, "Tcp"), ("azure.gap.nsg_declared_internet_udp_any", "Udp")])
@pytest.mark.parametrize("representation", ["missing", "empty", "null"])
def test_missing_port_authority_cannot_supply_declaration_compliance(cid, protocol, representation):
    rule = nsg_rule("open", protocol, "Internet", "22")
    props = rule["properties"]
    props.pop("destinationPortRange")
    if representation == "empty":
        props["destinationPortRanges"] = []
    elif representation == "null":
        props["destinationPortRange"] = None
    assert assessed([rule], cid) == "UNKNOWN"
