"""Missing NSG source selectors are not proof of restricted ingress."""
import pytest
from peaso.checks.claude_azure_common import nsg_rule
from peaso.engine import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
CIDS = ("azure.gap.nsg_declared_internet_ssh", "azure.claude.nsg_internet_ssh")
ASG = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/applicationSecurityGroups/clients"


def assess(props, cid):
    rule = nsg_rule("open", "Tcp", "Internet", "22")
    rule["properties"].pop("sourceAddressPrefix")
    rule["properties"].update(priority=200, destinationAddressPrefix="*", **props)
    item = {"id": SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg", "properties": {"securityRules": [rule]}}
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "nsg", "scope": SCOPE, "status": "collected", "items": [item]}])
    captured = collect_snapshot({"connector": {"provider": "azure", "scopes": [SCOPE], "options": {"snapshot": snapshot}}, "checks": [cid]})
    findings = [f for f in evaluate_snapshot(captured, checks=[cid])["findings"] if f["check_id"] == cid]
    assert len(findings) == 1
    return findings[0]["status"]


@pytest.mark.parametrize("cid", CIDS)
@pytest.mark.parametrize("props", [{}, {"sourceAddressPrefixes": []}, {"sourceAddressPrefix": None}])
def test_missing_both_address_and_asg_sources_is_unknown(cid, props):
    assert assess(props, cid) == "UNKNOWN"


@pytest.mark.parametrize("cid", CIDS)
def test_explicit_valid_asg_selector_does_not_require_address_prefix(cid):
    assert assess({"sourceApplicationSecurityGroups": [{"id": ASG}]}, cid) == "PASS"


@pytest.mark.parametrize("cid", CIDS)
def test_unavailable_asg_selector_cannot_supply_source_authority(cid):
    assert assess({"sourceApplicationSecurityGroups": [{"id": ASG}], "_coverage": {"sourceApplicationSecurityGroups": {"status": "denied"}}}, cid) == "UNKNOWN"


@pytest.mark.parametrize("groups", [[{}], [{"id": "not-an-asg"}], "not-a-list"])
def test_malformed_asg_reference_is_not_safe_ingress(groups):
    assert assess({"sourceApplicationSecurityGroups": groups}, CIDS[0]) == "UNKNOWN"
