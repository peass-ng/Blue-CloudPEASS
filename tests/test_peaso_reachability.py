"""Configuration truth tests: no provider SDK, sockets, subprocesses, or probes."""
import copy
import json
import socket
import subprocess
import time
from pathlib import Path

import pytest

from peaso.analysis import REACHABILITY_TYPES, evaluate_reachability, network_snapshot
from peaso.snapshot import make_snapshot, resources


def sealed(provider, facts, metadata=None):
    collections = [{"type": kind, "scope": scope, "service": kind, "status": "collected" if items else "empty", "items": items}
        for (kind, scope), items in facts.items()]
    return make_snapshot(provider, sorted({scope for _, scope in facts}), collections, metadata=metadata or {},
        created_at="2026-10-01T00:00:00+00:00")


def reseal(snapshot):
    snapshot.pop("snapshot_id", None)
    return make_snapshot(snapshot["provider"], snapshot["scopes"], snapshot["collections"],
        metadata=snapshot["metadata"], created_at=snapshot["created_at"])


def native(snapshot, kind, name=None):
    matches = [r for r in resources(snapshot) if r["type"] == kind and (name is None or r["data"].get("name") == name or r["data"].get("id") == name or r["data"].get("metadata", {}).get("name") == name)]
    assert len(matches) == 1
    return matches[0]["id"]


def collection(snapshot, kind, scope=None):
    return next(c for c in snapshot["collections"] if c["type"] == kind and (scope is None or c["scope"] == scope))


def proof(**kwargs):
    return {"status": "collected", "complete": True, "source_evidence": [{"method": "read-only fixture capture", "path": "network_context"}], **kwargs}


def aws_fixture():
    scope = "111111111111/us-east-1"
    def sg_rule(prefix, ipv6prefix):
        return {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
            "IpRanges": [{"CidrIp": prefix}], "Ipv6Ranges": [{"CidrIpv6": ipv6prefix}]}
    def acl(name, subnet):
        return {"id": name, "NetworkAclId": name, "VpcId": "vpc-a", "Associations": [{"SubnetId": subnet}],
            "Entries": [{"Egress": egress, "RuleNumber": number, "Protocol": "-1", "RuleAction": action, **ranges}
                for egress in (False, True) for number, action, ranges in (
                    (100, "allow", {"CidrBlock": "0.0.0.0/0"}), (101, "allow", {"Ipv6CidrBlock": "::/0"}),
                    (32767, "deny", {"CidrBlock": "0.0.0.0/0"}), (32767, "deny", {"Ipv6CidrBlock": "::/0"}))]}
    facts = {
        ("vpc", scope): [{"id": "vpc-a", "VpcId": "vpc-a", "OwnerId": "111111111111", "CidrBlock": "10.0.0.0/16", "Ipv6CidrBlockAssociationSet": [{"Ipv6CidrBlock": "fd00::/48"}]}],
        ("subnet", scope): [{"id": f"subnet-{i}", "SubnetId": f"subnet-{i}", "VpcId": "vpc-a", "CidrBlock": f"10.0.{i}.0/24", "Ipv6CidrBlockAssociationSet": [{"Ipv6CidrBlock": f"fd00:0:0:{i}::/64"}]} for i in (1, 2)],
        ("network_interface", scope): [{"id": name, "NetworkInterfaceId": name, "SubnetId": f"subnet-{i}", "VpcId": "vpc-a", "OwnerId": "111111111111", "Region": "us-east-1",
            "PrivateIpAddress": f"10.0.{i}.10", "Ipv6Addresses": [{"Ipv6Address": f"fd00:0:0:{i}::10"}], "Groups": [{"GroupId": group}]} for i, name, group in ((1, "source", "sg-source"), (2, "destination", "sg-destination"))],
        ("security_group", scope): [{"id": "sg-source", "GroupId": "sg-source", "OwnerId": "111111111111", "VpcId": "vpc-a", "IpPermissions": [], "IpPermissionsEgress": [sg_rule("10.0.2.0/24", "fd00:0:0:2::/64")]},
            {"id": "sg-destination", "GroupId": "sg-destination", "OwnerId": "111111111111", "VpcId": "vpc-a", "IpPermissions": [sg_rule("10.0.1.0/24", "fd00:0:0:1::/64")], "IpPermissionsEgress": []}],
        ("route_table", scope): [{"id": "rt-a", "RouteTableId": "rt-a", "VpcId": "vpc-a", "Associations": [{"Main": True}],
            "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local", "State": "active"}, {"DestinationIpv6CidrBlock": "fd00::/48", "GatewayId": "local", "State": "active"}]}],
        ("network_acl", scope): [acl("acl-source", "subnet-1"), acl("acl-destination", "subnet-2")],
        ("vpc_peering", scope): [],
    }
    return sealed("aws", facts)


def azure_fixture():
    scope = "/subscriptions/a"
    vnet = scope + "/resourceGroups/r/providers/Microsoft.Network/virtualNetworks/net"
    nsg = scope + "/resourceGroups/r/providers/Microsoft.Network/networkSecurityGroups/rules"
    subnets = [vnet + f"/subnets/s{i}" for i in (1, 2)]
    def rule(direction):
        return {"name": "allow-" + direction, "properties": {"priority": 200, "direction": direction, "access": "Allow",
            "protocol": "Tcp", "sourceAddressPrefix": "*", "destinationAddressPrefix": "*", "sourcePortRange": "*", "destinationPortRange": "443"}}
    facts = {
        ("vnet", scope): [{"id": vnet, "name": "net", "properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16", "fd00::/48"]}}}],
        ("subnet", scope): [{"id": subnet, "properties": {"addressPrefixes": [f"10.0.{i}.0/24", f"fd00:0:0:{i}::/64"]}} for i, subnet in enumerate(subnets, 1)],
        ("nic", scope): [{"id": scope + f"/resourceGroups/r/providers/Microsoft.Network/networkInterfaces/{name}", "name": name,
            "properties": {"networkSecurityGroup": {"id": nsg}, "ipConfigurations": [
                {"name": "ipv4", "properties": {"privateIPAddress": f"10.0.{i}.10", "subnet": {"id": subnet}}},
                {"name": "ipv6", "properties": {"privateIPAddress": f"fd00:0:0:{i}::10", "subnet": {"id": subnet}}}]}}
            for i, name, subnet in ((1, "source", subnets[0]), (2, "destination", subnets[1]))],
        ("nsg", scope): [{"id": nsg, "properties": {"securityRules": [rule("Outbound"), rule("Inbound")]}}],
        ("route_table", scope): [], ("vnet_peering", scope): [],
    }
    return sealed("azure", facts, {"network_context": {"azure": {"routing": proof(bgp="none"), "security_admin": proof(policies=[])}}})


def gcp_fixture():
    host, service = "projects/host", "projects/service"
    network = "https://www.googleapis.com/compute/v1/projects/host/global/networks/net"
    subnets = [f"https://www.googleapis.com/compute/v1/projects/host/regions/us-east1/subnetworks/s{i}" for i in (1, 2)]
    facts = {
        ("network", host): [{"name": "net", "selfLink": network, "peerings": []}],
        ("subnetwork", host): [{"name": f"s{i}", "selfLink": subnet, "network": network, "ipCidrRange": f"10.0.{i}.0/24", "internalIpv6Prefix": f"fd00:0:0:{i}::/64", "purpose": "PRIVATE"} for i, subnet in enumerate(subnets, 1)],
        ("instance", service): [{"name": "source", "tags": {"items": ["client"]}, "serviceAccounts": [{"email": "client@host.iam.gserviceaccount.com"}],
            "networkInterfaces": [{"name": "nic0", "network": network, "subnetwork": subnets[0], "networkIP": "10.0.1.10", "ipv6Address": "fd00:0:0:1::10", "ipv6AccessType": "INTERNAL"}]}],
        ("instance", host): [{"name": "destination", "tags": {"items": ["server"]}, "serviceAccounts": [{"email": "server@host.iam.gserviceaccount.com"}],
            "networkInterfaces": [{"name": "nic0", "network": network, "subnetwork": subnets[1], "networkIP": "10.0.2.10", "ipv6Address": "fd00:0:0:2::10", "ipv6AccessType": "INTERNAL"}]}],
        ("firewall", host): [{"name": "allow", "network": network, "direction": "INGRESS", "priority": 100,
            "sourceTags": ["client"], "targetTags": ["server"], "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]},
            {"name": "deny", "network": network, "direction": "INGRESS", "priority": 200, "sourceRanges": ["0.0.0.0/0", "::/0"], "denied": [{"IPProtocol": "tcp", "ports": ["443"]}]}],
        ("route", host): [],
    }
    return sealed("gcp", facts, {"network_context": {"gcp": {"routing": proof(policy_based_routes="none", dynamic_routes="none"), "firewall_hierarchy": proof(policies=[])}}})


def k8s_fixture():
    scope = "*"
    facts = {
        ("namespace", scope): [{"metadata": {"name": name, "labels": {"team": name}}} for name in ("client", "server")],
        ("pod", scope): [{"metadata": {"name": name, "namespace": namespace, "labels": {"app": name}},
            "spec": {"containers": [{"name": "application", "ports": [{"name": "https", "protocol": "TCP", "containerPort": 443}]}]},
            "status": {"podIP": address, "podIPs": [{"ip": address}, {"ip": f"fd00::{i}"}]}, "provenance": {"cluster_id": "cluster-a"}}
            for i, name, namespace, address in ((1, "source", "client", "10.0.1.10"), (2, "destination", "server", "10.0.2.10"))],
        ("networkpolicy", scope): [
            {"metadata": {"name": "egress", "namespace": "client"}, "spec": {"podSelector": {"matchLabels": {"app": "source"}}, "policyTypes": ["Egress"],
                "egress": [{"to": [{"namespaceSelector": {"matchLabels": {"team": "server"}}, "podSelector": {"matchLabels": {"app": "destination"}}}], "ports": [{"protocol": "TCP", "port": 443}]}]}},
            {"metadata": {"name": "ingress", "namespace": "server"}, "spec": {"podSelector": {"matchLabels": {"app": "destination"}}, "policyTypes": ["Ingress"],
                "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"team": "client"}}, "podSelector": {"matchLabels": {"app": "source"}}}], "ports": [{"protocol": "TCP", "port": "https"}]}]}}],
    }
    return sealed("k8s", facts, {"cluster_id": "cluster-a", "network_context": {"k8s": {
        "cni": proof(enforces_network_policy=True, supports_end_port=True, ipblock_semantics="pod_ips_preserved"),
        "routing": proof(pod_network_connected=True)}}})


FIXTURES = {"aws": (aws_fixture, "network_interface"), "azure": (azure_fixture, "nic"), "gcp": (gcp_fixture, "instance"), "k8s": (k8s_fixture, "pod")}


def query(snapshot, port=443, source_port=54321, family="ipv4", protocol="tcp"):
    kind = FIXTURES[snapshot["provider"]][1]
    return evaluate_reachability(snapshot, native(snapshot, kind, "source"), native(snapshot, kind, "destination"), protocol, port, source_port, family)


@pytest.mark.parametrize("provider", FIXTURES)
@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
def test_complete_path_all_providers_and_families(provider, family):
    snapshot = FIXTURES[provider][0]()
    before = copy.deepcopy(snapshot)
    result = query(snapshot, family=family)
    assert result["decision"] == "allowed", result
    assert result["application_listening"] == "unknown"
    assert result["modeled_configuration"] and result["new_flow_only"]
    assert result["routes"] and result["policy_decisions"] and result["evidence_refs"]
    assert result["unresolved_dependencies"] == []
    assert snapshot == before


def test_aws_stateful_sg_return_and_stateless_nacl_return():
    snapshot = aws_fixture()
    acl = collection(snapshot, "network_acl")["items"][1]
    acl["Entries"].insert(0, {"Egress": True, "RuleNumber": 10, "Protocol": "6", "PortRange": {"From": 54321, "To": 54321}, "RuleAction": "deny", "CidrBlock": "0.0.0.0/0"})
    result = query(reseal(snapshot))
    assert result["decision"] == "blocked"
    assert any(p.get("flow") == "return" and p["decision"] == "blocked" for p in result["policy_decisions"])
    assert any("stateful" in p.get("return_behavior", "") for p in result["policy_decisions"])


def test_aws_return_source_port_required_only_when_rule_constrains_it():
    snapshot = aws_fixture()
    assert query(snapshot, source_port=None)["decision"] == "allowed"
    acl = collection(snapshot, "network_acl")["items"][1]
    acl["Entries"] = [r for r in acl["Entries"] if not r["Egress"] or r["RuleNumber"] == 32767]
    acl["Entries"].insert(0, {"Egress": True, "RuleNumber": 10, "Protocol": "6", "PortRange": {"From": 1024, "To": 65535}, "RuleAction": "allow", "CidrBlock": "0.0.0.0/0"})
    snapshot = reseal(snapshot)
    result = query(snapshot, source_port=None)
    assert result["decision"] == "unknown"
    assert any(g["code"] == "source_port_required" for g in result["unresolved_dependencies"])
    assert query(snapshot, source_port=54321)["decision"] == "allowed"
    assert query(snapshot, source_port=1000)["decision"] == "blocked"


def test_aws_disassociated_ipv6_domain_is_not_a_current_address_fact():
    snapshot = aws_fixture()
    collection(snapshot, "vpc")["items"][0]["Ipv6CidrBlockAssociationSet"][0]["Ipv6CidrBlockState"] = {"State": "disassociated"}
    assert query(reseal(snapshot), family="ipv6")["decision"] == "unknown"


def test_aws_ordered_nacl_deny_and_same_subnet_exception():
    snapshot = aws_fixture()
    acl = collection(snapshot, "network_acl")["items"][0]
    acl["Entries"].append({"Egress": True, "RuleNumber": 20, "Protocol": "-1", "RuleAction": "deny", "CidrBlock": "0.0.0.0/0"})
    snapshot = reseal(snapshot)
    result = query(snapshot)
    assert result["decision"] == "blocked"
    assert any(p.get("control") == "aws.network_acl" and p["decision"] == "blocked" and p.get("flow") == "forward" for p in result["policy_decisions"])
    destination = collection(snapshot, "network_interface")["items"][1]
    destination["SubnetId"], destination["PrivateIpAddress"] = "subnet-1", "10.0.1.20"
    groups = collection(snapshot, "security_group")["items"]
    groups[0]["IpPermissionsEgress"][0]["IpRanges"] = [{"CidrIp": "10.0.1.0/24"}]
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_aws_referenced_security_groups_are_union_not_copied_peer_rules():
    snapshot = aws_fixture()
    groups = collection(snapshot, "security_group")["items"]
    groups[0]["IpPermissionsEgress"] = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "UserIdGroupPairs": [{"GroupId": "sg-destination", "UserId": "111111111111"}]}]
    groups[1]["IpPermissions"] = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "UserIdGroupPairs": [{"GroupId": "sg-source", "UserId": "111111111111"}]}]
    assert query(reseal(snapshot))["decision"] == "allowed"
    groups[1]["IpPermissions"][0]["UserIdGroupPairs"][0]["UserId"] = "222222222222"
    assert query(reseal(snapshot))["decision"] == "blocked"


@pytest.mark.parametrize("kind", ["route_table", "network_acl", "security_group", "subnet"])
@pytest.mark.parametrize("status", ["denied", "partial", "not_collected"])
def test_aws_incomplete_dependency_never_invents_allowance(kind, status):
    snapshot = aws_fixture()
    c = collection(snapshot, kind)
    c["status"] = status
    if status != "partial":
        c["items"] = []
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert result["unresolved_dependencies"]


@pytest.mark.parametrize("component,value", [("NatGatewayId", "nat-a"), ("TransitGatewayId", "tgw-a"), ("NetworkInterfaceId", "appliance"), ("GatewayId", "igw-a")])
def test_aws_unsupported_next_hops_are_unknown(component, value):
    snapshot = aws_fixture()
    table = collection(snapshot, "route_table")["items"][0]
    table["Routes"].append({"DestinationCidrBlock": "10.0.2.10/32", component: value, "State": "active"})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert result["translations"][0]["component"] == component


def test_aws_unknown_translation_cannot_prove_downstream_cidr_deny():
    snapshot = aws_fixture()
    collection(snapshot, "route_table")["items"][0]["Routes"].append({"DestinationCidrBlock": "10.0.2.10/32", "NatGatewayId": "nat-a", "State": "active"})
    collection(snapshot, "security_group")["items"][1]["IpPermissions"][0]["IpRanges"] = [{"CidrIp": "192.168.0.0/16"}]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "blocked_candidate_not_proven" for g in result["unresolved_dependencies"])


def test_aws_explicit_source_block_is_decisive_with_route_gap():
    snapshot = aws_fixture()
    collection(snapshot, "security_group")["items"][0]["IpPermissionsEgress"] = []
    collection(snapshot, "route_table")["status"] = "denied"
    collection(snapshot, "route_table")["items"] = []
    result = query(reseal(snapshot))
    assert result["decision"] == "blocked"
    assert result["unresolved_dependencies"]


def test_azure_ordered_deny_and_default_stateful_rules():
    snapshot = azure_fixture()
    rules = collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"]
    deny = copy.deepcopy(rules[0])
    deny["properties"].update(priority=100, access="Deny")
    rules.append(deny)
    result = query(reseal(snapshot))
    assert result["decision"] == "blocked"
    assert any(p.get("control") == "azure.nsg" and p["decision"] == "blocked" for p in result["policy_decisions"])
    collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"] = []
    result = query(reseal(snapshot), source_port=None)
    assert result["decision"] == "allowed", result
    assert any(p.get("derived_default") for p in result["policy_decisions"])


def test_azure_nic_and_subnet_policy_intersection():
    snapshot = azure_fixture()
    subnet = collection(snapshot, "subnet")["items"][1]
    denied_nsg = copy.deepcopy(collection(snapshot, "nsg")["items"][0])
    denied_nsg["id"] += "-deny"
    denied_nsg["properties"]["securityRules"][1]["properties"]["access"] = "Deny"
    collection(snapshot, "nsg")["items"].append(denied_nsg)
    subnet["properties"]["networkSecurityGroup"] = {"id": denied_nsg["id"]}
    assert query(reseal(snapshot))["decision"] == "blocked"


def azure_peered_fixture():
    snapshot = azure_fixture()
    vnet = collection(snapshot, "vnet")["items"][0]
    remote = copy.deepcopy(vnet)
    remote["id"] += "-remote"
    remote["properties"]["addressSpace"]["addressPrefixes"] = ["10.1.0.0/16", "fd01::/48"]
    collection(snapshot, "vnet")["items"].append(remote)
    subnet = collection(snapshot, "subnet")["items"][1]
    old_id = subnet["id"]
    subnet["id"] = subnet["id"].replace(vnet["id"], remote["id"])
    subnet["properties"]["addressPrefixes"] = ["10.1.2.0/24", "fd01:0:0:2::/64"]
    destination = collection(snapshot, "nic")["items"][1]
    for config in destination["properties"]["ipConfigurations"]:
        props = config["properties"]
        props["subnet"]["id"] = subnet["id"]
        props["privateIPAddress"] = "10.1.2.10" if config["name"] == "ipv4" else "fd01:0:0:2::10"
    c = collection(snapshot, "vnet_peering")
    c.update(status="collected", items=[{"id": a["id"] + "/virtualNetworkPeerings/peer", "properties": {
        "remoteVirtualNetwork": {"id": b["id"]}, "remoteAddressSpace": copy.deepcopy(b["properties"]["addressSpace"]),
        "peeringState": "Connected", "peeringSyncLevel": "FullyInSync", "allowVirtualNetworkAccess": True}}
        for a, b in ((vnet, remote), (remote, vnet))])
    return reseal(snapshot)


@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
def test_azure_peered_path_requires_connected_synchronized_space(family):
    snapshot = azure_peered_fixture()
    assert query(snapshot, family=family)["decision"] == "allowed"
    collection(snapshot, "vnet_peering")["items"][0]["properties"]["peeringSyncLevel"] = "RemoteNotInSync"
    assert query(reseal(snapshot), family=family)["decision"] == "unknown"


def test_azure_missing_admin_context_can_override_even_nsg_deny():
    snapshot = azure_fixture()
    snapshot["metadata"]["network_context"]["azure"].pop("security_admin")
    collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"][0]["properties"]["access"] = "Deny"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "azure_security_admin_context_missing" for g in result["unresolved_dependencies"])


def test_azure_service_tags_and_source_port_unknown_until_resolved():
    snapshot = azure_fixture()
    rule = collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"][0]["properties"]
    rule["destinationAddressPrefix"] = "Storage"
    assert query(reseal(snapshot))["decision"] == "unknown"
    rule["destinationAddressPrefix"], rule["sourcePortRange"] = "*", "50000-60000"
    snapshot = reseal(snapshot)
    assert query(snapshot, source_port=None)["decision"] == "unknown"
    assert query(snapshot, source_port=54321)["decision"] == "allowed"


def test_azure_native_empty_plural_fields_preserve_singular_selectors():
    snapshot = azure_fixture()
    for rule in collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"]:
        rule["properties"].update(sourceAddressPrefixes=[], destinationAddressPrefixes=[], sourcePortRanges=[], destinationPortRanges=[])
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_azure_invalid_native_priority_does_not_become_a_proven_deny():
    snapshot = azure_fixture()
    p = collection(snapshot, "nsg")["items"][0]["properties"]["securityRules"][0]["properties"]
    p.update(priority=50, access="Deny")
    assert query(reseal(snapshot))["decision"] == "unknown"


@pytest.mark.parametrize("hop,expected", [("None", "blocked"), ("VirtualAppliance", "unknown"), ("Internet", "unknown")])
def test_azure_udr_longest_prefix_and_unsupported_hops(hop, expected):
    snapshot = azure_fixture()
    subnet = collection(snapshot, "subnet")["items"][0]
    scope = subnet_scope = collection(snapshot, "subnet")["scope"]
    rid = scope + "/resourceGroups/r/providers/Microsoft.Network/routeTables/rt"
    subnet["properties"]["routeTable"] = {"id": rid}
    collection(snapshot, "route_table").update(status="collected", items=[{"id": rid, "properties": {"routes": [{"name": "chosen", "properties": {"addressPrefix": "10.0.2.10/32", "nextHopType": hop}}]}}])
    result = query(reseal(snapshot))
    assert result["decision"] == expected, result


def test_gcp_priority_deny_tie_and_hierarchy_gate():
    snapshot = gcp_fixture()
    rules = collection(snapshot, "firewall")["items"]
    rules[1]["priority"] = 100
    assert query(reseal(snapshot))["decision"] == "blocked"
    snapshot["metadata"]["network_context"]["gcp"].pop("firewall_hierarchy")
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "gcp_firewall_hierarchy_missing" for g in result["unresolved_dependencies"])


def test_gcp_service_account_selectors_and_shared_global_domain():
    snapshot = gcp_fixture()
    rule = collection(snapshot, "firewall")["items"][0]
    rule.pop("sourceTags")
    rule.pop("targetTags")
    rule.update(sourceServiceAccounts=["client@host.iam.gserviceaccount.com"], targetServiceAccounts=["server@host.iam.gserviceaccount.com"])
    result = query(reseal(snapshot))
    assert result["decision"] == "allowed", result
    assert result["endpoints"]["source"]["scope"] == "projects/service"
    assert result["endpoints"]["destination"]["scope"] == "projects/host"


def test_gcp_sdk_numeric_network_id_does_not_replace_project_qualified_selflink():
    snapshot = gcp_fixture()
    collection(snapshot, "network")["items"][0]["id"] = "1234567890123"
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_gcp_service_project_firewall_inventory_cannot_prove_host_vpc_default_deny():
    snapshot = gcp_fixture()
    c = collection(snapshot, "firewall")
    c["scope"] = "projects/service"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "firewall_collection_incomplete" for g in result["unresolved_dependencies"])


def test_gcp_disabled_and_direction_rules_do_not_apply():
    snapshot = gcp_fixture()
    rules = collection(snapshot, "firewall")["items"]
    rules[0]["disabled"] = True
    assert query(reseal(snapshot))["decision"] == "blocked"
    rules[0].pop("disabled")
    rules[1]["direction"] = "EGRESS"
    assert query(reseal(snapshot))["decision"] == "blocked"


def gcp_peered_fixture():
    snapshot = gcp_fixture()
    network = collection(snapshot, "network")["items"][0]
    remote = copy.deepcopy(network)
    remote["selfLink"] = remote["selfLink"].replace("projects/host/", "projects/other/")
    network["peerings"] = [{"network": remote["selfLink"], "state": "ACTIVE", "stackType": "IPV4_IPV6"}]
    remote["peerings"] = [{"network": network["selfLink"], "state": "ACTIVE", "stackType": "IPV4_IPV6"}]
    snapshot["collections"].append({"type": "network", "scope": "projects/other", "service": "compute", "status": "collected", "items": [remote]})
    subnet = collection(snapshot, "subnetwork")["items"][1]
    collection(snapshot, "subnetwork")["items"].remove(subnet)
    subnet.update(network=remote["selfLink"], selfLink=subnet["selfLink"].replace("projects/host/", "projects/other/"), ipCidrRange="10.1.2.0/24", internalIpv6Prefix="fd01:0:0:2::/64")
    snapshot["collections"].append({"type": "subnetwork", "scope": "projects/other", "service": "compute", "status": "collected", "items": [subnet]})
    destination = collection(snapshot, "instance", "projects/host")["items"][0]
    destination["networkInterfaces"][0].update(network=remote["selfLink"], subnetwork=subnet["selfLink"], networkIP="10.1.2.10", ipv6Address="fd01:0:0:2::10")
    rule = {"name": "remote-allow", "network": remote["selfLink"], "sourceRanges": ["0.0.0.0/0", "::/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]}
    snapshot["collections"] += [{"type": "firewall", "scope": "projects/other", "service": "compute", "status": "collected", "items": [rule]},
        {"type": "route", "scope": "projects/other", "service": "compute", "status": "empty", "items": []}]
    return reseal(snapshot)


@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
def test_gcp_active_peering_subnet_path_and_inactive_unknown(family):
    snapshot = gcp_peered_fixture()
    assert query(snapshot, family=family)["decision"] == "allowed"
    collection(snapshot, "network")["items"][0]["peerings"][0]["state"] = "INACTIVE"
    assert query(reseal(snapshot), family=family)["decision"] == "unknown"


def test_gcp_egress_default_ipv4_range_does_not_admit_ipv6_specific_rule():
    snapshot = gcp_fixture()
    rules = collection(snapshot, "firewall")["items"]
    rules.append({"name": "egress-deny", "network": rules[0]["network"], "direction": "EGRESS", "priority": 50,
        "denied": [{"IPProtocol": "tcp", "ports": ["443"]}]})
    snapshot = reseal(snapshot)
    assert query(snapshot)["decision"] == "blocked"
    assert query(snapshot, family="ipv6")["decision"] == "allowed"


def test_k8s_additive_union_not_ordered_deny_and_namespaces_are_not_subnets():
    snapshot = k8s_fixture()
    policies = collection(snapshot, "networkpolicy")["items"]
    policies.append({"metadata": {"name": "default-isolation", "namespace": "server"}, "spec": {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": []}})
    result = query(reseal(snapshot))
    assert result["decision"] == "allowed"
    policies[1]["spec"]["ingress"] = []
    assert query(reseal(snapshot))["decision"] == "blocked"
    assert not any("subnet" in r.get("message", "") for r in result["routes"])


def test_k8s_cni_evidence_required_for_allow_and_block():
    snapshot = k8s_fixture()
    snapshot["metadata"]["network_context"]["k8s"].pop("cni")
    assert query(reseal(snapshot))["decision"] == "unknown"
    collection(snapshot, "networkpolicy")["items"][0]["spec"]["egress"] = []
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "cni_enforcement_unknown" for g in result["unresolved_dependencies"])


def test_k8s_custom_policy_and_malformed_cni_proof_cannot_be_ignored():
    snapshot = k8s_fixture()
    snapshot["metadata"]["network_context"]["k8s"]["cni"]["source_evidence"] = [True]
    assert query(reseal(snapshot))["decision"] == "unknown"
    snapshot = k8s_fixture()
    snapshot["collections"].append({"type": "cilium_networkpolicy", "scope": "*", "service": "cilium", "status": "collected",
        "items": [{"metadata": {"name": "custom", "namespace": "server"}, "spec": {"endpointSelector": {}, "ingressDeny": [{}]}}]})
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "cni_custom_policy_context_unknown" for g in result["unresolved_dependencies"])


def test_k8s_namespace_and_pod_selectors_are_conjunction_within_peer():
    snapshot = k8s_fixture()
    peer = collection(snapshot, "networkpolicy")["items"][1]["spec"]["ingress"][0]["from"][0]
    peer["namespaceSelector"]["matchLabels"]["team"] = "server"
    assert query(reseal(snapshot))["decision"] == "blocked"
    peer["namespaceSelector"] = {"matchExpressions": [{"key": "team", "operator": "In", "values": ["client"]}]}
    assert query(reseal(snapshot))["decision"] == "allowed"


def test_k8s_ipblock_exceptions_port_ranges_and_cni_translation_context():
    snapshot = k8s_fixture()
    rule = collection(snapshot, "networkpolicy")["items"][1]["spec"]["ingress"][0]
    rule["from"] = [{"ipBlock": {"cidr": "10.0.0.0/16", "except": ["10.0.1.0/24"]}}]
    assert query(reseal(snapshot))["decision"] == "blocked"
    rule["from"][0]["ipBlock"]["except"] = []
    rule["ports"] = [{"port": 440, "endPort": 450, "protocol": "TCP"}]
    assert query(reseal(snapshot))["decision"] == "allowed"
    snapshot["metadata"]["network_context"]["k8s"]["cni"].pop("supports_end_port")
    assert query(reseal(snapshot))["decision"] == "unknown"
    snapshot["metadata"]["network_context"]["k8s"]["cni"]["supports_end_port"] = True
    snapshot["metadata"]["network_context"]["k8s"]["cni"].pop("ipblock_semantics")
    assert query(reseal(snapshot))["decision"] == "unknown"


@pytest.mark.parametrize("provider", ["azure", "gcp", "k8s"])
def test_missing_routing_context_stays_unknown_despite_policy_allow(provider):
    snapshot = FIXTURES[provider][0]()
    snapshot["metadata"]["network_context"][provider].pop("routing")
    assert query(reseal(snapshot))["decision"] == "unknown"


def test_scoped_artifact_keeps_dependency_status_and_original_identity():
    snapshot = aws_fixture()
    snapshot["collections"].append({"type": "iam_policy", "scope": snapshot["scopes"][0], "service": "iam", "status": "collected", "items": [{"PolicyDocument": {"Statement": []}}]})
    snapshot = reseal(snapshot)
    projected = network_snapshot(snapshot)
    assert all(c["type"] in REACHABILITY_TYPES["aws"] for c in projected["collections"])
    assert projected["snapshot_id"] != snapshot["snapshot_id"]
    result = query(projected)
    assert result["decision"] == "allowed"
    assert result["snapshot_id"] == snapshot["snapshot_id"]
    assert result["scoped_snapshot_id"] == projected["snapshot_id"]
    assert query(network_snapshot(projected))["snapshot_id"] == snapshot["snapshot_id"]


def test_no_network_socket_or_subprocess_during_all_provider_evaluation(monkeypatch):
    snapshots = {p: factory() for p, (factory, _) in FIXTURES.items()}
    def fail(*args, **kwargs):
        pytest.fail("network/socket/subprocess called by pure evaluation")
    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(socket, "create_connection", fail)
    monkeypatch.setattr(subprocess, "Popen", fail)
    monkeypatch.setattr(subprocess, "run", fail)
    for snapshot in snapshots.values():
        assert query(snapshot)["decision"] == "allowed"


@pytest.mark.parametrize("port", [True, False, 0, -1, 65536, 1.0, "443"])
def test_strict_port_validation(port):
    with pytest.raises(ValueError):
        evaluate_reachability(aws_fixture(), "source", "destination", "tcp", port)


def test_missing_ids_unknown_and_bad_protocol_family_rejected():
    snapshot = aws_fixture()
    result = evaluate_reachability(snapshot, "missing", "missing", "tcp", 443)
    assert result["decision"] == "unknown"
    assert result["unresolved_dependencies"][0]["code"] == "endpoint_inventory_missing"
    with pytest.raises(ValueError):
        evaluate_reachability(snapshot, "source", "destination", "icmp", 443)
    with pytest.raises(ValueError):
        evaluate_reachability(snapshot, "source", "destination", "tcp", 443, address_family="ipvx")


def aws_peered_fixture():
    snapshot = aws_fixture()
    a, b = snapshot["scopes"][0], "222222222222/us-east-1"
    snapshot["scopes"].append(b)
    def move(kind, item):
        collection(snapshot, kind)["items"].remove(item)
        snapshot["collections"].append({"type": kind, "scope": b, "service": kind, "status": "collected", "items": [item]})
    vpc = {"id": "vpc-b", "VpcId": "vpc-b", "OwnerId": "222222222222", "CidrBlock": "10.1.0.0/16", "Ipv6CidrBlockAssociationSet": [{"Ipv6CidrBlock": "fd01::/48"}]}
    snapshot["collections"].append({"type": "vpc", "scope": b, "service": "vpc", "status": "collected", "items": [vpc]})
    subnet = collection(snapshot, "subnet")["items"][1]
    subnet.update(VpcId="vpc-b", CidrBlock="10.1.2.0/24", Ipv6CidrBlockAssociationSet=[{"Ipv6CidrBlock": "fd01:0:0:2::/64"}])
    move("subnet", subnet)
    interface = collection(snapshot, "network_interface")["items"][1]
    interface.update(VpcId="vpc-b", OwnerId="222222222222", PrivateIpAddress="10.1.2.10", Ipv6Addresses=[{"Ipv6Address": "fd01:0:0:2::10"}])
    move("network_interface", interface)
    group = collection(snapshot, "security_group")["items"][1]
    group["VpcId"] = "vpc-b"
    group["OwnerId"] = "222222222222"
    move("security_group", group)
    collection(snapshot, "security_group", a)["items"][0]["IpPermissionsEgress"][0]["IpRanges"] = [{"CidrIp": "10.1.2.0/24"}]
    collection(snapshot, "security_group", a)["items"][0]["IpPermissionsEgress"][0]["Ipv6Ranges"] = [{"CidrIpv6": "fd01:0:0:2::/64"}]
    acl = collection(snapshot, "network_acl")["items"][1]
    acl["VpcId"] = "vpc-b"
    move("network_acl", acl)
    collection(snapshot, "route_table", a)["items"][0]["Routes"] += [
        {"DestinationCidrBlock": "10.1.0.0/16", "VpcPeeringConnectionId": "pcx-a", "State": "active"},
        {"DestinationIpv6CidrBlock": "fd01::/48", "VpcPeeringConnectionId": "pcx-a", "State": "active"}]
    snapshot["collections"].append({"type": "route_table", "scope": b, "service": "ec2", "status": "collected", "items": [{"id": "rt-b", "VpcId": "vpc-b", "Associations": [{"Main": True}], "Routes": [
        {"DestinationCidrBlock": "10.1.0.0/16", "GatewayId": "local", "State": "active"}, {"DestinationIpv6CidrBlock": "fd01::/48", "GatewayId": "local", "State": "active"},
        {"DestinationCidrBlock": "10.0.0.0/16", "VpcPeeringConnectionId": "pcx-a", "State": "active"}, {"DestinationIpv6CidrBlock": "fd00::/48", "VpcPeeringConnectionId": "pcx-a", "State": "active"}]}]})
    collection(snapshot, "vpc_peering", a).update(status="collected", items=[{"id": "pcx-a", "VpcPeeringConnectionId": "pcx-a", "Status": {"Code": "active"},
        "RequesterVpcInfo": {"VpcId": "vpc-a", "OwnerId": "111111111111", "Region": "us-east-1"},
        "AccepterVpcInfo": {"VpcId": "vpc-b", "OwnerId": "222222222222", "Region": "us-east-1"}}])
    return reseal(snapshot)


@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
def test_aws_active_cross_account_peering_needs_routes_both_directions(family):
    snapshot = aws_peered_fixture()
    result = query(snapshot, family=family)
    assert result["decision"] == "allowed", result
    assert result["endpoints"]["source"]["scope"] != result["endpoints"]["destination"]["scope"]
    peer = collection(snapshot, "vpc_peering")["items"][0]
    peer["AccepterVpcInfo"]["OwnerId"] = "333333333333"
    assert query(reseal(snapshot), family=family)["decision"] == "unknown"


def test_aws_peering_same_native_vpc_name_in_wrong_region_is_not_a_join():
    snapshot = aws_peered_fixture()
    collection(snapshot, "vpc_peering")["items"][0]["AccepterVpcInfo"]["Region"] = "us-west-2"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "peering_facts_missing" for g in result["unresolved_dependencies"])


def test_aws_referenced_security_group_owner_is_not_assumed_to_be_eni_owner():
    snapshot = aws_fixture()
    groups = collection(snapshot, "security_group")["items"]
    groups[1]["OwnerId"] = "222222222222"
    groups[0]["IpPermissionsEgress"] = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "UserIdGroupPairs": [{"GroupId": "sg-destination", "UserId": "222222222222"}]}]
    result = query(reseal(snapshot))
    assert result["decision"] == "allowed", result


def test_aws_overlapping_scoped_networks_do_not_alias_even_matching_native_names():
    snapshot = aws_peered_fixture()
    b = "222222222222/us-east-1"
    collection(snapshot, "vpc", b)["items"][0]["CidrBlock"] = "10.0.0.0/16"
    collection(snapshot, "subnet", b)["items"][0]["CidrBlock"] = "10.0.2.0/24"
    collection(snapshot, "network_interface", b)["items"][0]["PrivateIpAddress"] = "10.0.2.10"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert any(g["code"] == "overlapping_address_domains" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("provider,kind", [("azure", "nsg"), ("gcp", "firewall"), ("k8s", "networkpolicy")])
@pytest.mark.parametrize("status", ["denied", "partial", "not_collected"])
def test_other_provider_incomplete_policy_union_is_unknown(provider, kind, status):
    snapshot = FIXTURES[provider][0]()
    c = collection(snapshot, kind)
    c["status"] = status
    if status != "partial":
        c["items"] = []
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown", result
    assert result["unresolved_dependencies"]


def test_azure_different_subscription_vnets_with_overlap_remain_unknown():
    snapshot = azure_fixture()
    destination = collection(snapshot, "nic")["items"][1]
    old_scope = collection(snapshot, "nic")["scope"]
    new_scope = "/subscriptions/b"
    old_vnet = collection(snapshot, "vnet")["items"][0]["id"]
    new_vnet = old_vnet.replace(old_scope, new_scope)
    copied = copy.deepcopy(collection(snapshot, "vnet")["items"][0])
    copied["id"] = new_vnet
    snapshot["collections"].append({"type": "vnet", "scope": new_scope, "service": "network", "status": "collected", "items": [copied]})
    subnet = collection(snapshot, "subnet")["items"][1]
    subnet["id"] = subnet["id"].replace(old_vnet, new_vnet)
    collection(snapshot, "subnet")["items"].remove(subnet)
    snapshot["collections"].append({"type": "subnet", "scope": new_scope, "service": "network", "status": "collected", "items": [subnet]})
    for configuration in destination["properties"]["ipConfigurations"]:
        configuration["properties"]["subnet"]["id"] = subnet["id"]
    collection(snapshot, "nic")["items"].remove(destination)
    destination["id"] = destination["id"].replace(old_scope, new_scope)
    snapshot["collections"].append({"type": "nic", "scope": new_scope, "service": "network", "status": "collected", "items": [destination]})
    snapshot["scopes"].append(new_scope)
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "overlapping_address_domains" for g in result["unresolved_dependencies"])


def test_gcp_peered_overlapping_project_domains_stay_unknown():
    snapshot = gcp_fixture()
    network = collection(snapshot, "network")["items"][0]
    remote = copy.deepcopy(network)
    remote["selfLink"] = remote["selfLink"].replace("projects/host/", "projects/other/")
    remote["peerings"] = [{"network": network["selfLink"], "state": "ACTIVE", "stackType": "IPV4_IPV6"}]
    network["peerings"] = [{"network": remote["selfLink"], "state": "ACTIVE", "stackType": "IPV4_IPV6"}]
    snapshot["collections"].append({"type": "network", "scope": "projects/other", "service": "compute", "status": "collected", "items": [remote]})
    subnet = collection(snapshot, "subnetwork")["items"][1]
    subnet["network"] = remote["selfLink"]
    subnet["selfLink"] = subnet["selfLink"].replace("projects/host/", "projects/other/")
    subnet["ipCidrRange"] = "10.0.1.0/24"
    destination = collection(snapshot, "instance", "projects/host")["items"][0]
    destination["networkInterfaces"][0].update(network=remote["selfLink"], subnetwork=subnet["selfLink"], networkIP="10.0.1.20")
    snapshot["collections"] += [{"type": "firewall", "scope": "projects/other", "service": "compute", "status": "empty", "items": []},
        {"type": "route", "scope": "projects/other", "service": "compute", "status": "empty", "items": []}]
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "overlapping_address_domains" for g in result["unresolved_dependencies"])


def test_k8s_cluster_mismatch_and_duplicate_addresses_do_not_join():
    snapshot = k8s_fixture()
    destination = collection(snapshot, "pod")["items"][1]
    destination["provenance"]["cluster_id"] = "cluster-b"
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "cluster_namespace_context_missing" for g in result["unresolved_dependencies"])
    destination["provenance"]["cluster_id"] = "cluster-a"
    destination["status"].update(podIP="10.0.1.10", podIPs=[{"ip": "10.0.1.10"}])
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "endpoint_address_collision" for g in result["unresolved_dependencies"])


def test_k8s_host_network_and_service_translation_are_explicitly_unsupported():
    snapshot = k8s_fixture()
    collection(snapshot, "pod")["items"][0]["spec"]["hostNetwork"] = True
    result = query(reseal(snapshot))
    assert result["decision"] == "unknown"
    assert any(g["code"] == "host_network_semantics_unknown" for g in result["unresolved_dependencies"])


@pytest.mark.parametrize("provider", FIXTURES)
def test_udp_new_flows_use_native_udp_rules(provider):
    snapshot = FIXTURES[provider][0]()
    for c in snapshot["collections"]:
        for item in c["items"]:
            if c["type"] == "security_group":
                for field in ("IpPermissions", "IpPermissionsEgress"):
                    for rule in item[field]:
                        rule["IpProtocol"] = "udp"
            elif c["type"] == "nsg":
                for rule in item["properties"]["securityRules"]:
                    rule["properties"]["protocol"] = "Udp"
            elif c["type"] == "firewall":
                for field in ("allowed", "denied"):
                    for rule in item.get(field, []):
                        rule["IPProtocol"] = "udp"
            elif c["type"] == "networkpolicy":
                for field in ("ingress", "egress"):
                    for rule in item["spec"].get(field, []):
                        for port in rule.get("ports", []):
                            port["protocol"] = "UDP"
            elif c["type"] == "pod":
                item["spec"]["containers"][0]["ports"][0]["protocol"] = "UDP"
    assert query(reseal(snapshot), protocol="udp")["decision"] == "allowed"


def test_earlier_unresolved_ordered_rule_cannot_be_skipped_to_allow():
    snapshot = aws_fixture()
    collection(snapshot, "network_acl")["items"][0]["Entries"].insert(0, {"Egress": True, "RuleNumber": 1, "Protocol": "6", "RuleAction": "deny", "CidrBlock": "0.0.0.0/0"})
    assert query(reseal(snapshot))["decision"] == "unknown"
    snapshot = gcp_fixture()
    collection(snapshot, "firewall")["items"].insert(0, {"name": "unknown", "network": collection(snapshot, "network")["items"][0]["selfLink"], "priority": 1,
        "sourceRanges": ["invalid-prefix"], "denied": [{"IPProtocol": "tcp", "ports": ["443"]}]})
    assert query(reseal(snapshot))["decision"] == "unknown"


def test_selected_path_benchmark_large_account_is_bounded_not_all_pairs():
    snapshot = aws_fixture()
    groups = collection(snapshot, "security_group")["items"]
    groups += [{"id": f"unrelated-{i}", "GroupId": f"unrelated-{i}", "VpcId": "vpc-a", "IpPermissions": [], "IpPermissionsEgress": []} for i in range(5000)]
    snapshot = reseal(snapshot)
    start = time.perf_counter()
    result = query(snapshot)
    elapsed = time.perf_counter() - start
    assert result["decision"] == "allowed"
    assert len(result["evidence_refs"]) < 40
    assert len(result["routes"]) == 2
    assert elapsed < 5, f"selected path evaluation unexpectedly unbounded: {elapsed:.3f}s"


@pytest.mark.parametrize("provider,path", [
    ("aws", "aws-snapshot.json"), ("azure", "azure-uncapped/azure-snapshot.json"), ("k8s", "k8s-snapshot.json")])
def test_real_captured_snapshots_have_truthful_explainable_states(provider, path):
    capture = Path(__file__).resolve().parents[1] / ".cache/peaso-qa/task_02a312b5ac1f" / path
    if not capture.is_file():
        pytest.skip("private QA capture is unavailable; no live collection attempted")
    captured = json.loads(capture.read_text())
    snapshot = network_snapshot(captured)
    kinds = {"aws": {"network_interface", "instance"}, "azure": {"nic", "vm"}, "k8s": {"pod"}}[provider]
    endpoints = [r for r in resources(snapshot) if r["type"] in kinds]
    source = endpoints[0]["id"] if endpoints else "not-collected:source"
    destination = endpoints[-1]["id"] if endpoints else "not-collected:destination"
    result = evaluate_reachability(snapshot, source, destination, "tcp", 443, 54321)
    assert result["snapshot_id"] == captured["snapshot_id"]
    assert result["decision"] in {"allowed", "blocked", "unknown"}
    if result["decision"] == "allowed":
        assert result["unresolved_dependencies"] == []
    elif result["decision"] == "unknown":
        assert result["unresolved_dependencies"]
    else:
        assert any(p["decision"] == "blocked" for p in result["policy_decisions"] + result["routes"])
