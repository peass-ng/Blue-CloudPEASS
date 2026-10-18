"""Unavailable NSG destination selectors cannot prove first-match blocking."""
import copy
import pytest
from peaso.checks.claude_azure_common import nsg_rule
from peaso.engine import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
CID = "azure.claude.nsg_internet_ssh"
ASG = SCOPE + "/resourceGroups/rg/providers/Microsoft.Network/applicationSecurityGroups/servers"


def assessed(selector):
    rules = []
    for name,access,priority in [("deny","Deny",100),("allow","Allow",200)]:
        row=nsg_rule(name,"Tcp","Internet","22",access=access)
        row["properties"].update(priority=priority, **copy.deepcopy(selector))
        rules.append(row)
    item={"id":SCOPE+"/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/n", "properties":{"securityRules":rules}}
    snapshot=make_snapshot("azure",[SCOPE],[{"type":"nsg","scope":SCOPE,"status":"collected","items":[item]}])
    before=copy.deepcopy(snapshot)
    imported=collect_snapshot({"connector":{"provider":"azure","scopes":[SCOPE],"options":{"snapshot":snapshot}},"checks":[CID]})
    findings=[f for f in evaluate_snapshot(imported,checks=[CID])["findings"] if f["check_id"]==CID]
    assert len(findings)==1 and snapshot==before and imported==before
    return findings[0]["status"]


@pytest.mark.parametrize("selector", [
    {},
    {"destinationAddressPrefixes":[]},
    {"destinationApplicationSecurityGroups":[{"id":ASG}],"_coverage":{"destinationApplicationSecurityGroups":{"status":"denied"}}},
    {"destinationApplicationSecurityGroups":[{"id":ASG,"_coverage":{"id":{"status":"denied"}}}]},
    {"destinationApplicationSecurityGroups":[{}]},
    {"destinationApplicationSecurityGroups":[{"id":"not-an-asg"}]},
    {"destinationApplicationSecurityGroups":"not-a-list"},
    {"destinationAddressPrefix":" "},
])
def test_unavailable_or_malformed_destination_cannot_prove_shadow(selector):
    assert assessed(selector)=="UNKNOWN"


@pytest.mark.parametrize("selector", [
    {"destinationApplicationSecurityGroups":[{"id":ASG}]},
    {"destinationAddressPrefix":"*"},
    {"destinationAddressPrefix":"10.0.0.4"},
    {"destinationAddressPrefix":"*","_coverage":{"destinationApplicationSecurityGroups":{"status":"denied"}}},
])
def test_authoritative_matching_destination_keeps_configuration_shadow(selector):
    assert assessed(selector)=="PASS"
