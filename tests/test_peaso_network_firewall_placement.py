"""Documented AWS Network Firewall placements from native DescribeFirewall facts."""

from copy import deepcopy

import pytest

from peaso.analysis.network import references
from peaso.checks import CHECKS
from peaso.collectors import aws_facts_cb_ca


CHECK = next(check for check in CHECKS if check.id == "aws.claude_a.networkfirewall.in_vpc")
ARN = "arn:aws:network-firewall:us-east-1:111111111111:firewall/review"
BASE = {"FirewallArn": ARN, "FirewallPolicyArn": "arn:aws:network-firewall:us-east-1:111111111111:firewall-policy/p"}
CLASSIC = {**BASE, "VpcId": "vpc-1", "SubnetMappings": [{"SubnetId": "subnet-1"}]}
TGW = {**BASE, "TransitGatewayId": "tgw-1", "AvailabilityZoneMappings": [{"AvailabilityZone": "us-east-1a"}]}
PROXY = {**BASE, "NoSourcePreservation": True,
         "VpcEndpoint": {"VpcId": "vpc-2", "SubnetMappings": [{"SubnetId": "subnet-2"}]}}


def evaluate(item):
    original = deepcopy(item)
    status, evidence = CHECK.evaluate(item, {})
    assert item == original
    return status, evidence


def test_classic_tgw_and_proxy_placement_modes():
    assert evaluate(CLASSIC) == ("PASS", {"placement": "classic_vpc", "vpc_id": "vpc-1"})
    assert evaluate(TGW) == ("NOT_APPLICABLE", {"placement": "transit_gateway", "transit_gateway_id": "tgw-1"})
    assert evaluate(PROXY) == ("PASS", {"placement": "proxy_vpc_endpoint", "vpc_id": "vpc-2", "transit_gateway_id": None})
    combined = {**PROXY, "TransitGatewayId": "tgw-1", "AvailabilityZoneMappings": [{"AvailabilityZone": "us-east-1a"}]}
    assert evaluate(combined)[0] == "PASS"


@pytest.mark.parametrize("item", [
    BASE,
    {**BASE, "VpcId": ""},
    {**BASE, "VpcId": 1, "SubnetMappings": [{"SubnetId": "subnet-1"}]},
    {**BASE, "VpcId": "vpc-1"},
    {**CLASSIC, "SubnetMappings": []},
    {**CLASSIC, "SubnetMappings": [{"SubnetId": "not-a-subnet"}]},
    {**TGW, "AvailabilityZoneMappings": []},
    {**TGW, "AvailabilityZoneMappings": [{"AvailabilityZone": "us east 1a"}]},
    {**BASE, "TransitGatewayId": "tgw-1"},
    {**BASE, "TransitGatewayId": "not-a-tgw", "AvailabilityZoneMappings": [{"AvailabilityZone": "us-east-1a"}]},
    {**BASE, "NoSourcePreservation": True},
    {**BASE, "NoSourcePreservation": True, "VpcEndpoint": {"VpcId": "vpc-2"}},
    {**BASE, "NoSourcePreservation": False, "VpcEndpoint": PROXY["VpcEndpoint"]},
    {**CLASSIC, "TransitGatewayId": "tgw-1", "AvailabilityZoneMappings": [{"AvailabilityZone": "us-east-1a"}]},
    {**CLASSIC, "NoSourcePreservation": True, "VpcEndpoint": PROXY["VpcEndpoint"]},
    {**CLASSIC, "_coverage": {"VpcId": {"status": "denied"}}},
    {**TGW, "_coverage": {"TransitGatewayId": {"status": "denied"}}},
    {**PROXY, "_coverage": {"VpcEndpoint": {"status": "denied"}}},
    {"collection_status": "denied"},
])
def test_missing_malformed_denied_or_conflicting_placement_is_unknown(item):
    assert evaluate(item)[0] == "UNKNOWN"


def test_collector_keeps_only_describe_firewall_placement_fields():
    class Requests:
        def detail(self, _session, _service, _region, operation, **_kwargs):
            if operation == "describe_firewall":
                return {"collection_status": "collected", "Firewall": {
                    **PROXY, "TransitGatewayId": "tgw-1", "AvailabilityZoneMappings": [{"AvailabilityZone": "us-east-1a"}],
                    "TransitGatewayOwnerAccountId": "222222222222", "unrelated_private_field": "discard"}}
            return {"collection_status": "collected", "LoggingConfiguration": {"LogDestinationConfigs": []}}

    [item] = aws_facts_cb_ca.ENRICHERS["network_firewall"](Requests(), object(), "us-east-1", [{"FirewallArn": ARN}])
    assert item["VpcEndpoint"] == PROXY["VpcEndpoint"]
    assert item["NoSourcePreservation"] is True
    assert item["TransitGatewayId"] == "tgw-1"
    assert item["TransitGatewayOwnerAccountId"] == "222222222222"
    assert item["AvailabilityZoneMappings"] == [{"AvailabilityZone": "us-east-1a"}]
    assert "unrelated_private_field" not in item
    assert evaluate(item)[0] == "PASS"


def test_structural_projection_uses_only_observed_placement_references():
    scope = "111111111111/us-east-1"
    def refs(data):
        return list(references({"provider": "aws", "type": "network_firewall", "scope": scope, "data": data}))

    classic = refs(CLASSIC)
    assert ("VpcId", "vpc", "vpc-1", None, "associated_with") in classic
    assert ("SubnetMappings[0].SubnetId", "subnet", "subnet-1", None, "associated_with") in classic
    proxy = refs(PROXY)
    assert ("VpcEndpoint.VpcId", "vpc", "vpc-2", None, "associated_with") in proxy
    assert ("VpcEndpoint.SubnetMappings[0].SubnetId", "subnet", "subnet-2", None, "associated_with") in proxy
    tgw = refs({**TGW, "TransitGatewayOwnerAccountId": "222222222222"})
    assert ("TransitGatewayId", "transit_gateway", "tgw-1", "222222222222/us-east-1", "associated_with") in tgw
    assert not any(edge[1] == "vpc" for edge in tgw)
    nested = refs({"FirewallArn": ARN, "Firewall": {**PROXY, "TransitGatewayId": "tgw-1",
                                                    "AvailabilityZoneMappings": [{"AvailabilityZone": "us-east-1a"}]}})
    assert ("Firewall.VpcEndpoint.VpcId", "vpc", "vpc-2", None, "associated_with") in nested
    assert ("Firewall.TransitGatewayId", "transit_gateway", "tgw-1", f"{scope}/tgw-owner-unverified", "associated_with") in nested
    malformed_owner = refs({**TGW, "TransitGatewayOwnerAccountId": "not-an-account"})
    assert ("TransitGatewayId", "transit_gateway", "tgw-1", f"{scope}/tgw-owner-unverified", "associated_with") in malformed_owner
    incomplete_tgw = refs({**BASE, "TransitGatewayId": "tgw-1"})
    assert not any(edge[1] == "transit_gateway" for edge in incomplete_tgw)
