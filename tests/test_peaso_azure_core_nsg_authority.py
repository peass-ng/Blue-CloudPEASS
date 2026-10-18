"""Core NSG candidate rules require readable fields, independently of reachability."""
from copy import deepcopy
import pytest
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
CID="azure.network.restrict_internet_ingress"
SCOPE="/subscriptions/11111111-1111-1111-1111-111111111111"

def rule(source="10.0.0.0/8",direction="Inbound",access="Allow"):
    return {"name":"r1","properties":{"direction":direction,"access":access,"sourceAddressPrefix":source}}

def verdict(rules):
    snap=make_snapshot("azure",[SCOPE],[{"scope":SCOPE,"type":"nsg","status":"collected","items":[{"id":SCOPE+"/nsg/n1","properties":{"securityRules":deepcopy(rules)}}]}],created_at="2026-10-17T00:00:00Z")
    before=deepcopy(snap);rows=[f for f in evaluate_snapshot(snap,checks=[CID])["findings"] if f["check_id"]==CID]
    assert len(rows)==1 and before==snap
    return rows[0]["status"]

@pytest.mark.parametrize("field",["direction","access","sourceAddressPrefix","sourceAddressPrefixes"])
def test_unavailable_selected_field_cannot_prove_safe_rule(field):
    r=rule();r["properties"]["_coverage"]={field:{"status":"denied"}}
    assert verdict([r])=="UNKNOWN"

def test_unreadable_rule_properties_cannot_prove_safety():
    r=rule();r["_coverage"]={"properties":{"status":"denied"}}
    assert verdict([r])=="UNKNOWN"

@pytest.mark.parametrize("reverse",[False,True])
def test_independent_known_public_rule_retains_negative(reverse):
    unknown=rule();unknown["properties"]["_coverage"]={"sourceAddressPrefix":{"status":"denied"}}
    rows=[unknown,rule("Internet")]
    if reverse:rows.reverse()
    assert verdict(rows)=="FAIL"

def test_source_not_consumed_on_known_non_ingress_allow():
    r=rule(direction="Outbound");r["properties"]["_coverage"]={"sourceAddressPrefix":{"status":"denied"}}
    assert verdict([r])=="PASS"

def test_valid_asg_source_is_not_universal_internet():
    r=rule();r["properties"].pop("sourceAddressPrefix");r["properties"]["sourceApplicationSecurityGroups"]=[{"id":SCOPE+"/resourceGroups/rg/providers/Microsoft.Network/applicationSecurityGroups/a1"}]
    assert verdict([r])=="PASS"


def test_unavailable_plural_does_not_select_retained_public_singular():
    r=rule("Internet");r["properties"]["_coverage"]={"sourceAddressPrefixes":{"status":"denied"}}
    assert verdict([r])=="UNKNOWN"
    r["properties"].pop("_coverage");r["properties"]["sourceAddressPrefixes"]=["10.0.0.0/8"]
    assert verdict([r])=="PASS"
