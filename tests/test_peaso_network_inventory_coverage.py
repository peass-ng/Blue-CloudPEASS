"""Collected network inventory projection: native references only, no reachability inference."""

from peaso.analysis import REQUIRED_TYPES
from peaso.analysis.common import analysis_context
from peaso.analysis.network import NETWORK_TYPES, build_network
from peaso.analysis.projection import project_graph
from peaso.collectors import supported_types
from peaso.snapshot import make_snapshot, resources


def graph(provider, facts, scope):
    aws_identity = {"vpc": "VpcId", "subnet": "SubnetId", "network_interface": "NetworkInterfaceId",
        "security_group": "GroupId", "route_table": "RouteTableId", "vpc_endpoint": "VpcEndpointId",
        "network_acl": "NetworkAclId", "transit_gateway": "TransitGatewayId",
        "transit_gateway_route_table": "TransitGatewayRouteTableId", "transit_gateway_attachment": "TransitGatewayAttachmentId",
        "vpn_gateway": "VpnGatewayId", "vpn_connection": "VpnConnectionId", "eks_cluster": "name",
        "lambda_function": "FunctionArn", "rds_instance": "DBInstanceArn", "network_firewall": "FirewallArn",
        "network_firewall_policy": "FirewallPolicyArn", "network_firewall_rule_group": "RuleGroupArn",
        "vpc_endpoint_service": "ServiceId", "load_balancer": "LoadBalancerArn"}
    # AWS collector normalization retains the API's native fields and adds id.
    if provider == "aws":
        facts = {kind: [{**item, **({"id": item[aws_identity[kind]]} if kind in aws_identity and aws_identity[kind] in item else {})}
                        for item in items] for kind, items in facts.items()}
    snap = make_snapshot(provider, [scope], [
        {"type": kind, "scope": scope, "status": "collected" if items else "denied", "items": items}
        for kind, items in facts.items()
    ], created_at="2026-10-12T00:00:00+00:00")
    with analysis_context(snap):
        return build_network(snap, resources(snap))


def item(g, kind, native):
    return next(n for n in g["nodes"] if n["type"] == kind and n.get("native_id") == native)


def links(g, source, target):
    return [e for e in g["edges"] if e["source"] == source["id"] and e["target"] == target["id"]]


def test_supported_network_collection_dependencies_cover_projected_kinds():
    from peaso.engine import plan_collection
    required = {
        "aws": {"vpc_endpoint", "network_acl", "transit_gateway_attachment", "transit_gateway_route_table", "vpn_connection", "eks_cluster", "network_firewall", "network_firewall_policy", "network_firewall_rule_group", "elastic_ip", "ec2_eip"},
        "gcp": {"firewall_policy", "router", "vpn_gateway", "vpn_tunnel", "address", "url_map", "backend_bucket", "health_check"},
        "azure": {"private_endpoint", "virtual_network_gateway", "load_balancer"},
    }
    for provider, kinds in required.items():
        assert kinds <= set(supported_types(provider))
        assert kinds <= NETWORK_TYPES
        assert kinds <= set(REQUIRED_TYPES[provider]["network"])
    for provider in ("aws", "gcp", "azure", "k8s"):
        assert (set(supported_types(provider)) & NETWORK_TYPES) <= set(REQUIRED_TYPES[provider]["network"])
    assert "firewall_policy" in plan_collection({"connector": {"provider": "azure"},
                                                  "categories": ["network"], "checks": [], "frameworks": []})
    assert {"firewall_policy", "firewall_policy_association"} <= set(plan_collection({
        "connector": {"provider": "gcp"}, "categories": ["network"], "checks": [], "frameworks": []}))
    assert {"pod", "service"} <= set(plan_collection({"connector": {"provider": "azure"},
                                                        "categories": ["network"], "checks": [], "frameworks": []}))


def test_aws_endpoints_acl_transit_vpn_and_managed_attachment_are_native_refs():
    scope = "111111111111/us-east-1"
    facts = {
        "vpc": [{"VpcId": "vpc-one", "CidrBlock": "10.0.0.0/16"}, {"VpcId": "vpc-two", "CidrBlock": "10.0.0.0/16"}],
        "subnet": [{"SubnetId": "subnet-one", "VpcId": "vpc-one"}],
        "network_interface": [{"NetworkInterfaceId": "eni-one", "SubnetId": "subnet-one", "VpcId": "vpc-one"}],
        "security_group": [{"GroupId": "sg-one", "VpcId": "vpc-one"}],
        "route_table": [{"RouteTableId": "rtb-one", "VpcId": "vpc-one"}],
        "vpc_endpoint": [{"VpcEndpointId": "vpce-one", "VpcId": "vpc-one", "SubnetIds": ["subnet-one"], "NetworkInterfaceIds": ["eni-one"], "Groups": [{"GroupId": "sg-one"}], "RouteTableIds": ["rtb-one"]}],
        "network_acl": [{"NetworkAclId": "acl-one", "VpcId": "vpc-one", "Associations": [{"SubnetId": "subnet-one"}], "Entries": [{"RuleNumber": 100, "Egress": False, "Protocol": "6", "PortRange": {"From": 443, "To": 443}, "RuleAction": "deny", "CidrBlock": "0.0.0.0/0"}]}],
        "transit_gateway": [{"TransitGatewayId": "tgw-one"}],
        "transit_gateway_route_table": [{"TransitGatewayRouteTableId": "tgw-rtb-one", "TransitGatewayId": "tgw-one"}],
        "transit_gateway_attachment": [{"TransitGatewayAttachmentId": "tgw-attach-one", "TransitGatewayId": "tgw-one", "ResourceType": "vpc", "ResourceId": "vpc-one", "Association": {"TransitGatewayRouteTableId": "tgw-rtb-one"}}],
        "vpn_gateway": [{"VpnGatewayId": "vgw-one", "VpcAttachments": [{"VpcId": "vpc-one"}]}],
        "vpn_connection": [{"VpnConnectionId": "vpn-one", "VpnGatewayId": "vgw-one", "CustomerGatewayId": "cgw-remote"}],
        "eks_cluster": [{"name": "cluster-one", "Cluster": {"cluster": {"endpoint": "https://example.invalid", "resourcesVpcConfig": {"vpcId": "vpc-one", "subnetIds": ["subnet-one"], "securityGroupIds": ["sg-one"]}}}}],
        "lambda_function": [{"FunctionArn": "arn:aws:lambda:us-east-1:111111111111:function:attached", "VpcConfig": {"VpcId": "vpc-one", "SubnetIds": ["subnet-one"], "SecurityGroupIds": ["sg-one"]}}],
        "rds_instance": [{"DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:one", "Endpoint": {"Address": "db.example.invalid"}, "DBSubnetGroup": {"VpcId": "vpc-one", "Subnets": [{"SubnetIdentifier": "subnet-one"}]}, "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-one"}]}],
    }
    g = graph("aws", facts, scope)
    assert len([n for n in g["nodes"] if n["type"] == "vpc"]) == 2  # overlapping CIDR stays distinct
    endpoint = item(g, "vpc_endpoint", "vpce-one")
    for kind, native in (("vpc", "vpc-one"), ("subnet", "subnet-one"), ("network_interface", "eni-one"), ("security_group", "sg-one"), ("route_table", "rtb-one")):
        assert links(g, endpoint, item(g, kind, native))
    assert links(g, item(g, "network_acl", "acl-one"), item(g, "subnet", "subnet-one"))
    attach = item(g, "transit_gateway_attachment", "tgw-attach-one")
    for kind, native in (("transit_gateway", "tgw-one"), ("vpc", "vpc-one"), ("transit_gateway_route_table", "tgw-rtb-one")):
        assert links(g, attach, item(g, kind, native))
    assert links(g, item(g, "vpn_connection", "vpn-one"), item(g, "vpn_gateway", "vgw-one"))
    for kind, native in (("eks_cluster", "cluster-one"), ("lambda_function", facts["lambda_function"][0]["FunctionArn"]), ("rds_instance", facts["rds_instance"][0]["DBInstanceArn"])):
        assert links(g, item(g, kind, native), item(g, "subnet", "subnet-one"))
    eks = item(g, "eks_cluster", "cluster-one")
    assert any(e["evidence"]["path"] == "Cluster.cluster.resourcesVpcConfig.subnetIds[0]" for e in links(g, eks, item(g, "subnet", "subnet-one")))
    db = item(g, "rds_instance", facts["rds_instance"][0]["DBInstanceArn"])
    assert any(e["evidence"]["path"] == "DBSubnetGroup.Subnets[0].SubnetIdentifier" for e in links(g, db, item(g, "subnet", "subnet-one")))
    assert all(e["layer"] == "structural" for e in g["edges"])
    assert any(n["type"] == "customer_gateway" and n["evidence"]["inventory_status"] == "reference_only" for n in g["nodes"])


def test_aws_collected_firewall_endpoint_service_and_remote_transit_owner():
    scope = "111111111111/us-east-1"
    policy_arn = "arn:aws:network-firewall:us-east-1:111111111111:firewall-policy/review"
    group_arn = "arn:aws:network-firewall:us-east-1:111111111111:stateful-rulegroup/review"
    lb_arn = "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/net/review/1"
    g = graph("aws", {
        "vpc": [{"VpcId": "vpc-one"}], "subnet": [{"SubnetId": "subnet-one", "VpcId": "vpc-one"}],
        "network_firewall": [{"FirewallArn": "arn:aws:network-firewall:us-east-1:111111111111:firewall/review", "Firewall": {"VpcId": "vpc-one", "SubnetMappings": [{"SubnetId": "subnet-one"}], "FirewallPolicyArn": policy_arn}}],
        "network_firewall_policy": [{"FirewallPolicyArn": policy_arn, "FirewallPolicy": {"StatefulRuleGroupReferences": [{"ResourceArn": group_arn}]}}],
        "network_firewall_rule_group": [{"RuleGroupArn": group_arn}],
        "load_balancer": [{"LoadBalancerArn": lb_arn, "VpcId": "vpc-one"}],
        "vpc_endpoint_service": [{"ServiceId": "vpce-svc-one", "NetworkLoadBalancerArns": [lb_arn]}],
        "transit_gateway_attachment": [{"TransitGatewayAttachmentId": "tgw-attach-remote", "ResourceType": "vpc", "ResourceId": "vpc-remote", "ResourceOwnerId": "222222222222", "TransitGatewayId": "tgw-one"}],
    }, scope)
    firewall = next(n for n in g["nodes"] if n["type"] == "network_firewall" and n.get("resource_id"))
    assert links(g, firewall, item(g, "vpc", "vpc-one"))
    assert links(g, firewall, item(g, "subnet", "subnet-one"))
    policy = item(g, "network_firewall_policy", policy_arn)
    assert links(g, firewall, policy)
    assert links(g, policy, item(g, "network_firewall_rule_group", group_arn))
    assert links(g, item(g, "vpc_endpoint_service", "vpce-svc-one"), item(g, "load_balancer", lb_arn))
    remote = next(n for n in g["nodes"] if n["type"] == "vpc" and n.get("native_id") == "vpc-remote")
    assert remote["scope"] == "222222222222/us-east-1" and remote["evidence"]["inventory_status"] == "reference_only"


def test_gcp_policy_associations_preserve_global_shared_and_unknown_scope():
    scope = "projects/host"
    network = "https://www.googleapis.com/compute/v1/projects/host/global/networks/main"
    g = graph("gcp", {
        "network": [{"name": "main", "selfLink": network, "IPv4Range": "10.0.0.0/16"}],
        "firewall_policy": [{"name": "organizations/42/firewallPolicies/10", "associations": [{"attachmentTarget": network}, {"attachmentTarget": "folders/77"}], "rules": [{"priority": 100, "direction": "INGRESS", "action": "deny", "match": {"srcIpRanges": ["0.0.0.0/0"], "layer4Configs": [{"ipProtocol": "tcp", "ports": ["443"]}]}}]}],
        "shared_vpc": [{"id": "host", "relationshipType": "getXpnHost"}],
    }, scope)
    policy = next(n for n in g["nodes"] if n["type"] == "firewall_policy" and n.get("resource_id"))
    assert links(g, policy, item(g, "network", network))
    assert any(e["source"] == policy["id"] and gnode["type"] == "policy_scope_reference" and gnode["scope"] == "folders/77"
               for e in g["edges"] for gnode in g["nodes"] if e["target"] == gnode["id"])
    assert item(g, "network", network)["provider_specific"]["network_scope"] == "global"


def test_hierarchical_policy_resolves_explicit_project_network_without_scope_alias():
    network = "https://www.googleapis.com/compute/v1/projects/host/global/networks/main"
    snap = make_snapshot("gcp", ["projects/host", "organizations/42"], [
        {"type": "network", "scope": "projects/host", "status": "collected", "items": [{"name": "main", "selfLink": network}]},
        {"type": "firewall_policy", "scope": "organizations/42", "status": "collected", "items": [{"name": "organizations/42/firewallPolicies/1", "associations": [{"attachmentTarget": network}]}]},
    ], created_at="2026-10-12T00:00:00+00:00")
    with analysis_context(snap):
        g = build_network(snap, resources(snap))
    policy = next(n for n in g["nodes"] if n["type"] == "firewall_policy" and n.get("resource_id"))
    target = item(g, "network", network)
    assert links(g, policy, target)
    assert not [n for n in g["nodes"] if n["type"] == "network" and n.get("scope") == "host"]


def test_collected_gcp_address_and_load_balancer_chain_remain_native_links():
    scope = "projects/host"
    prefix = "https://www.googleapis.com/compute/v1/projects/host/global/"
    ids = {kind: prefix + path for kind, path in (("forwarding_rule", "forwardingRules/front"),
        ("target_proxy", "targetHttpsProxies/proxy"), ("url_map", "urlMaps/map"),
        ("backend_service", "backendServices/backend"), ("health_check", "healthChecks/check"))}
    address_id = prefix + "addresses/address-one"
    g = graph("gcp", {
        "address": [{"selfLink": address_id, "address": "198.51.100.10", "users": [ids["forwarding_rule"]]}],
        "forwarding_rule": [{"selfLink": ids["forwarding_rule"], "target": ids["target_proxy"]}],
        "target_proxy": [{"selfLink": ids["target_proxy"], "urlMap": ids["url_map"]}],
        "url_map": [{"selfLink": ids["url_map"], "defaultService": ids["backend_service"]}],
        "backend_service": [{"selfLink": ids["backend_service"], "healthChecks": [ids["health_check"]]}],
        "health_check": [{"selfLink": ids["health_check"]}],
    }, scope)
    for first, second in (("address", "forwarding_rule"), ("forwarding_rule", "target_proxy"),
                          ("target_proxy", "url_map"), ("url_map", "backend_service"),
                          ("backend_service", "health_check")):
        assert links(g, item(g, first, address_id if first == "address" else ids[first]), item(g, second, ids[second]))
    assert all(e["layer"] == "structural" for e in g["edges"])


def test_azure_private_endpoint_and_vpn_gateway_keep_arm_attachment_and_target():
    scope = "/subscriptions/sub-one"
    base = scope + "/resourceGroups/rg/providers/Microsoft.Network"
    vnet, subnet, nic, pip = (base + suffix for suffix in ("/virtualNetworks/main", "/virtualNetworks/main/subnets/one", "/networkInterfaces/nic-one", "/publicIPAddresses/pip-one"))
    g = graph("azure", {
        "vnet": [{"id": vnet, "properties": {"subnets": [{"id": subnet}]}}],
        "subnet": [{"id": subnet}], "nic": [{"id": nic}], "public_ip": [{"id": pip}],
        "private_endpoint": [{"id": base + "/privateEndpoints/pe-one", "properties": {"subnet": {"id": subnet}, "networkInterfaces": [{"id": nic}], "privateLinkServiceConnections": [{"properties": {"privateLinkServiceId": scope + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/storage-one"}}]}}],
        "virtual_network_gateway": [{"id": base + "/virtualNetworkGateways/gw-one", "properties": {"ipConfigurations": [{"properties": {"subnet": {"id": subnet}, "publicIPAddress": {"id": pip}}}]}}],
    }, scope)
    endpoint = item(g, "private_endpoint", base + "/privateEndpoints/pe-one")
    assert links(g, endpoint, item(g, "subnet", subnet))
    assert links(g, endpoint, item(g, "nic", nic))
    assert any(n["type"] == "private_link_service_reference" and n["evidence"]["inventory_status"] == "reference_only" for n in g["nodes"])
    gateway = item(g, "virtual_network_gateway", base + "/virtualNetworkGateways/gw-one")
    assert links(g, gateway, item(g, "subnet", subnet))
    assert links(g, gateway, item(g, "public_ip", pip))


def test_azure_cross_subscription_reference_uses_collector_scope_not_local_alias():
    remote = "/subscriptions/sub-two/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/remote"
    peer = "/subscriptions/sub-one/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/local/virtualNetworkPeerings/out"
    snap = make_snapshot("azure", ["/subscriptions/sub-one", "/subscriptions/sub-two"], [
        {"type": "vnet_peering", "scope": "/subscriptions/sub-one", "status": "collected", "items": [{"id": peer, "properties": {"remoteVirtualNetwork": {"id": remote}}}]},
        {"type": "vnet", "scope": "/subscriptions/sub-two", "status": "collected", "items": [{"id": remote}]},
    ], created_at="2026-10-12T00:00:00+00:00")
    with analysis_context(snap):
        g = build_network(snap, resources(snap))
    assert links(g, item(g, "vnet_peering", peer), item(g, "vnet", remote))


def test_missing_or_malformed_attachment_never_claims_placement_or_reachability():
    scope = "111111111111/us-east-1"
    g = graph("aws", {
        "vpc": [{"VpcId": "vpc-one"}],
        "eks_cluster": [{"name": "not-described", "Cluster": {"collection_status": "denied"}}],
        "vpc_endpoint": [{"VpcEndpointId": "vpce-malformed", "VpcId": "vpc-one", "SubnetIds": {"wrong": "shape"}, "Groups": [None, {"GroupId": None}]}],
        "network_acl": [{"NetworkAclId": "acl-malformed", "VpcId": "vpc-one", "Entries": [None, "bad"]}],
        "vpn_connection": [],
    }, scope)
    cluster = item(g, "eks_cluster", "not-described")
    assert cluster["evidence"]["placement_status"] == "unknown"
    assert not [e for e in g["edges"] if e["source"] == cluster["id"]]
    assert not [e for e in g["edges"] if e["type"] == "rule_candidate"]
    assert not [n for n in g["nodes"] if n["type"] == "vpn_connection"]
    assert "reachability" in g["semantics"]


def test_large_projected_inventory_preserves_underlying_counts():
    scope = "111111111111/us-east-1"
    g = graph("aws", {"vpc": [{"VpcId": "vpc-one"}], "subnet": [{"SubnetId": f"subnet-{i}", "VpcId": "vpc-one"} for i in range(310)]}, scope)
    projected = project_graph(g, max_nodes=90)
    assert len(projected["nodes"]) <= 90
    assert projected["projection"]["collapsed"] is True
    assert sum(int(n.get("underlying_count", 1)) for n in projected["nodes"] if n["type"] == "subnet" or n.get("aggregate")) >= 310
