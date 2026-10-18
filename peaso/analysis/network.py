"""Network inventory associations and rule evidence, without all-pairs routing."""
from __future__ import annotations

import json
from urllib.parse import unquote, urlsplit

from .common import as_list, finding, gcp_interface_resource_id, native_id, node, node_id, relationship, source, stable_id

NETWORK_TYPES = {"vpc", "subnet", "security_group", "network_interface", "instance", "route_table", "network_acl",
    "internet_gateway", "nat_gateway", "vpc_endpoint", "vpc_endpoint_service", "ec2_instance_connect_endpoint",
    "ec2_client_vpn_endpoint", "vpc_peering", "transit_gateway", "transit_gateway_attachment", "transit_gateway_vpc_attachment",
    "transit_gateway_route_table", "vpn_connection", "vpn_gateway", "network_firewall", "network_firewall_policy",
    "network_firewall_rule_group", "elastic_ip", "ec2_eip", "load_balancer", "classic_load_balancer",
    "rds_instance", "rds_cluster", "lambda_function", "eks_cluster",
    "target_group", "network", "subnetwork", "firewall", "firewall_policy", "route", "forwarding_rule", "backend_service", "backend_bucket", "url_map", "health_check", "address", "target_pool", "target_proxy", "instance_group",
    "shared_vpc", "router", "vpn_tunnel", "gke_cluster", "vnet", "nsg", "nic", "vm", "public_ip", "load_balancer", "loadbalancer", "application_gateway", "private_endpoint", "virtual_network_gateway", "peering", "vnet_peering",
    "pod", "service", "networkpolicy", "namespace", "ingress", "node", "endpoint", "endpointslice"}
PUBLIC = {"0.0.0.0/0", "::/0", "*", "Internet"}


def _object(value):
    return value if isinstance(value, dict) else {}


def _ref_id(value, *keys):
    if isinstance(value, str):
        return value or None
    if isinstance(value, dict):
        return next((value[key] for key in keys if isinstance(value.get(key), str) and value[key]), None)
    return None


def _managed_network_facts(resource):
    """Only place managed workloads with an observed native VPC/subnet attachment."""
    data = _object(resource.get("data"))
    kind = resource["type"]
    if kind == "eks_cluster":
        cluster = _object(_object(data.get("Cluster")).get("cluster"))
        attachment = _object(cluster.get("resourcesVpcConfig"))
        return {"VpcId": attachment.get("vpcId"), "SubnetIds": attachment.get("subnetIds"),
                "SecurityGroupIds": as_list(attachment.get("securityGroupIds")) + as_list(attachment.get("clusterSecurityGroupId"))} if cluster.get("endpoint") and attachment.get("vpcId") and as_list(attachment.get("subnetIds")) else {}
    if kind == "lambda_function":
        attachment = _object(data.get("VpcConfig"))
        return attachment if attachment.get("VpcId") and as_list(attachment.get("SubnetIds")) else {}
    if kind in {"rds_instance", "rds_cluster"}:
        subnet_group = _object(data.get("DBSubnetGroup") if kind == "rds_instance" else data.get("DBSubnetGroupDetails"))
        # RDS clusters often expose a subnet-group name without subnet details;
        # do not place that cluster on a guessed VPC.
        endpoint = data.get("Endpoint")
        endpoint_present = isinstance(endpoint, str) and bool(endpoint) or bool(_object(endpoint).get("Address"))
        subnets = [_ref_id(x, "SubnetIdentifier") for x in as_list(subnet_group.get("Subnets"))]
        return {"VpcId": subnet_group.get("VpcId"), "SubnetIds": [x for x in subnets if x],
                "SecurityGroupIds": [_ref_id(x, "VpcSecurityGroupId") for x in as_list(data.get("VpcSecurityGroups")) if _ref_id(x, "VpcSecurityGroupId")]} if endpoint_present and subnet_group.get("VpcId") and any(subnets) else {}
    if kind == "gke_cluster":
        return data if (data.get("network") or _object(data.get("networkConfig")).get("network")) and (data.get("subnetwork") or _object(data.get("networkConfig")).get("subnetwork")) else {}
    return data


def public_rules(resource):
    """Yield native rule candidates. A candidate is never endpoint reachability."""
    data, kind = resource["data"], resource["type"]
    if kind == "security_group":
        for i, rule in enumerate(as_list(data.get("IpPermissions"))):
            if not isinstance(rule, dict):
                continue
            ranges = [x.get("CidrIp") for x in as_list(rule.get("IpRanges")) if isinstance(x, dict)]
            ranges += [x.get("CidrIpv6") for x in as_list(rule.get("Ipv6Ranges")) if isinstance(x, dict)]
            if any(x in PUBLIC for x in ranges):
                yield f"IpPermissions[{i}]", rule, "AWS security-group inbound allow; routing, NACLs, attachment, and public addressing remain unresolved"
    elif kind == "firewall":
        # GCP omitted sourceRanges defaults to 0.0.0.0/0 only for ingress;
        # source tags/serviceaccounts establish a different selector restriction.
        ingress = data.get("direction", "INGRESS") == "INGRESS"
        ranges = data.get("sourceRanges", [] if data.get("sourceTags") or data.get("sourceServiceAccounts") else ["0.0.0.0/0"])
        if ingress and data.get("disabled") is not True and data.get("allowed") and any(x in PUBLIC for x in ranges):
            yield "allowed", data, "GCP firewall allow candidate; target tags/service accounts, hierarchy, priority, denies, and routes remain unresolved"
    elif kind == "nsg":
        props = data.get("properties", data)
        for i, rule in enumerate(as_list(props.get("securityRules")) + as_list(props.get("defaultSecurityRules"))):
            if not isinstance(rule, dict):
                continue
            p = rule.get("properties", rule)
            ranges = as_list(p.get("sourceAddressPrefix")) + as_list(p.get("sourceAddressPrefixes"))
            if p.get("access") == "Allow" and p.get("direction") == "Inbound" and any(x in PUBLIC for x in ranges):
                yield f"properties.securityRules[{i}]", rule, "Azure NSG allow candidate; service tags, priority, subnet/NIC policy intersection, routes, and public IP remain unresolved"
    elif kind == "networkpolicy":
        spec = data.get("spec", {})
        types = spec.get("policyTypes", ["Ingress"] + (["Egress"] if "egress" in spec else []))
        if "Ingress" not in types:
            return
        for i, rule in enumerate(as_list(spec.get("ingress"))):
            if not isinstance(rule, dict):
                continue
            peers = rule.get("from")
            public_blocks = [x for x in as_list(peers) if isinstance(x, dict)
                             and x.get("ipBlock", {}).get("cidr") in PUBLIC]
            # Missing/empty from admits all sources at the policy layer; an
            # empty ingress LIST admits none. Except blocks are kept intact.
            if not peers or any(x == {} for x in peers) or public_blocks:
                yield f"spec.ingress[{i}]", rule, "Kubernetes additive policy allow candidate; ipBlock exceptions, pod/namespace selectors, CNI enforcement, and external routing remain unresolved"


def exposure_findings(snapshot, resources):
    findings = []
    for resource in resources:
        rules = [{"source": source(snapshot, resource, path), "native_rule": rule,
                  "semantics": semantics} for path, rule, semantics in public_rules(resource)]
        if rules:
            findings.append(finding(snapshot, resource, "exposure", "analysis.network_review",
                "Review unrestricted network rule candidates", "high",
                {"rules": rules, "risk_state": "conditional", "layer": "modeled_rule",
                 "reachability": "unknown", "telemetry": "not_collected"}))
    return findings


def references(resource):
    data, provider, kind = _object(resource.get("data")), resource["provider"], resource["type"]
    if provider == "aws":
        if kind in {"rds_instance", "rds_cluster", "lambda_function", "eks_cluster"}:
            facts = _managed_network_facts(resource)
            if not facts:
                return
            if kind == "eks_cluster":
                attachment = _object(_object(_object(data.get("Cluster")).get("cluster")).get("resourcesVpcConfig"))
                prefix = "Cluster.cluster.resourcesVpcConfig"
                for key, target in (("vpcId", "vpc"), ("clusterSecurityGroupId", "security_group")):
                    rid = attachment.get(key)
                    if isinstance(rid, str) and rid:
                        yield f"{prefix}.{key}", target, rid, None, "associated_with" if target == "vpc" else "protected_by"
                for key, target in (("subnetIds", "subnet"), ("securityGroupIds", "security_group")):
                    for i, rid in enumerate(as_list(attachment.get(key))):
                        if isinstance(rid, str) and rid:
                            yield f"{prefix}.{key}[{i}]", target, rid, None, "associated_with" if target == "subnet" else "protected_by"
            elif kind == "lambda_function":
                attachment = _object(data.get("VpcConfig"))
                rid = attachment.get("VpcId")
                if isinstance(rid, str) and rid:
                    yield "VpcConfig.VpcId", "vpc", rid, None, "associated_with"
                for key, target in (("SubnetIds", "subnet"), ("SecurityGroupIds", "security_group")):
                    for i, rid in enumerate(as_list(attachment.get(key))):
                        if isinstance(rid, str) and rid:
                            yield f"VpcConfig.{key}[{i}]", target, rid, None, "associated_with" if target == "subnet" else "protected_by"
            else:
                group = _object(data.get("DBSubnetGroup") if kind == "rds_instance" else data.get("DBSubnetGroupDetails"))
                group_path = "DBSubnetGroup" if kind == "rds_instance" else "DBSubnetGroupDetails"
                rid = group.get("VpcId")
                if isinstance(rid, str) and rid:
                    yield f"{group_path}.VpcId", "vpc", rid, None, "associated_with"
                for i, subnet in enumerate(as_list(group.get("Subnets"))):
                    rid = _ref_id(subnet, "SubnetIdentifier")
                    if rid:
                        yield f"{group_path}.Subnets[{i}].SubnetIdentifier", "subnet", rid, None, "associated_with"
                for i, group_ref in enumerate(as_list(data.get("VpcSecurityGroups"))):
                    rid = _ref_id(group_ref, "VpcSecurityGroupId")
                    if rid:
                        yield f"VpcSecurityGroups[{i}].VpcSecurityGroupId", "security_group", rid, None, "protected_by"
            return
        for key, target in (("VpcId", "vpc"), ("SubnetId", "subnet"), ("NetworkInterfaceId", "network_interface")):
            if isinstance(data.get(key), str) and data[key] and not (kind == target and str(data[key]) == str(native_id(resource))):
                yield key, target, str(data[key]), None, "associated_with"
        for key, target, relation in (("SubnetIds", "subnet", "associated_with"),
                ("NetworkInterfaceIds", "network_interface", "attached_interface"),
                ("RouteTableIds", "route_table", "associated_with"),
                ("SecurityGroupIds", "security_group", "protected_by")):
            for i, ref in enumerate(as_list(data.get(key))):
                rid = _ref_id(ref, "SubnetId", "NetworkInterfaceId", "RouteTableId", "GroupId")
                if rid:
                    yield f"{key}[{i}]", target, rid, None, relation
        for key in ("SecurityGroups", "Groups", "VpcSecurityGroupIds"):
            for i, ref in enumerate(as_list(data.get(key))):
                rid = _ref_id(ref, "GroupId", "VpcSecurityGroupId")
                if rid:
                    yield f"{key}[{i}]", "security_group", rid, None, "protected_by"
        for i, ref in enumerate(as_list(data.get("NetworkInterfaces"))):
            if isinstance(ref, dict) and ref.get("NetworkInterfaceId"):
                yield f"NetworkInterfaces[{i}]", "network_interface", ref["NetworkInterfaceId"], None, "attached_interface"
        for i, ref in enumerate(as_list(data.get("SubnetMappings"))):
            rid = _ref_id(ref, "SubnetId")
            if rid:
                yield f"SubnetMappings[{i}].SubnetId", "subnet", rid, None, "associated_with"
        if kind == "network_firewall":
            firewall = _object(data.get("Firewall"))
            for key, target in (("VpcId", "vpc"), ("FirewallPolicyArn", "network_firewall_policy")):
                if isinstance(firewall.get(key), str) and firewall[key]:
                    yield f"Firewall.{key}", target, firewall[key], None, "associated_with"
            for i, ref in enumerate(as_list(firewall.get("SubnetMappings"))):
                rid = _ref_id(ref, "SubnetId")
                if rid:
                    yield f"Firewall.SubnetMappings[{i}].SubnetId", "subnet", rid, None, "associated_with"
            placement = firewall if firewall else data
            prefix = "Firewall." if firewall else ""
            tgw = placement.get("TransitGatewayId")
            tgw_zones = as_list(placement.get("AvailabilityZoneMappings"))
            if (isinstance(tgw, str) and tgw.startswith("tgw-") and tgw[4:].isalnum()
                    and "VpcId" not in placement and "SubnetMappings" not in placement
                    and tgw_zones and all(isinstance(zone, dict) and isinstance(zone.get("AvailabilityZone"), str)
                                          and zone["AvailabilityZone"] for zone in tgw_zones)):
                owner = placement.get("TransitGatewayOwnerAccountId")
                region = str(resource["scope"]).split("/")[-1]
                # A shared gateway belongs to its owner account. Without a
                # validated owner, retain an isolated reference instead of
                # accidentally joining a same-ID gateway in this account.
                target_scope = (f"{owner}/{region}" if isinstance(owner, str) and len(owner) == 12 and owner.isdigit()
                                else f"{resource['scope']}/tgw-owner-unverified")
                yield f"{prefix}TransitGatewayId", "transit_gateway", tgw, target_scope, "associated_with"
            endpoint = _object(placement.get("VpcEndpoint")) if placement.get("NoSourcePreservation") is True else {}
            if endpoint and "VpcId" not in placement and "SubnetMappings" not in placement:
                proxy_vpc = endpoint.get("VpcId")
                if isinstance(proxy_vpc, str) and proxy_vpc.startswith("vpc-") and proxy_vpc[4:] and all(c in "0123456789abcdef" for c in proxy_vpc[4:]):
                    yield f"{prefix}VpcEndpoint.VpcId", "vpc", proxy_vpc, None, "associated_with"
                    for i, mapping in enumerate(as_list(endpoint.get("SubnetMappings"))):
                        subnet = _ref_id(mapping, "SubnetId")
                        if isinstance(subnet, str) and subnet.startswith("subnet-") and subnet[7:] and all(c in "0123456789abcdef" for c in subnet[7:]):
                            yield f"{prefix}VpcEndpoint.SubnetMappings[{i}].SubnetId", "subnet", subnet, None, "associated_with"
        if kind == "network_firewall_policy":
            policy = _object(data.get("FirewallPolicy"))
            for key in ("StatelessRuleGroupReferences", "StatefulRuleGroupReferences"):
                for i, ref in enumerate(as_list(policy.get(key))):
                    rid = _ref_id(ref, "ResourceArn")
                    if rid:
                        yield f"FirewallPolicy.{key}[{i}].ResourceArn", "network_firewall_rule_group", rid, None, "firewall_rule_group"
        if kind == "vpc_endpoint_service":
            for key, target in (("NetworkLoadBalancerArns", "load_balancer"), ("GatewayLoadBalancerArns", "load_balancer")):
                for i, rid in enumerate(as_list(data.get(key))):
                    if isinstance(rid, str) and rid:
                        yield f"{key}[{i}]", target, rid, None, "endpoint_service_load_balancer"
        if kind == "ec2_client_vpn_endpoint":
            for key, target in (("VpcId", "vpc"), ("TransitGatewayId", "transit_gateway")):
                if isinstance(data.get(key), str) and data[key]:
                    yield key, target, data[key], None, "vpn_endpoint"
            for i, ref in enumerate(as_list(data.get("AssociatedTargetNetworks"))):
                rid = _ref_id(ref, "TargetNetworkId")
                if rid:
                    yield f"AssociatedTargetNetworks[{i}].TargetNetworkId", "subnet", rid, None, "vpn_endpoint"
        if kind in {"elastic_ip", "ec2_eip"}:
            rid = data.get("InstanceId")
            if isinstance(rid, str) and rid:
                yield "InstanceId", "instance", rid, None, "address_association"
        for i, ref in enumerate(as_list(data.get("Attachments"))):
            rid = _ref_id(ref, "VpcId")
            if rid:
                yield f"Attachments[{i}].VpcId", "vpc", rid, None, "associated_with"
        for i, ref in enumerate(as_list(data.get("VpcAttachments"))):
            rid = _ref_id(ref, "VpcId")
            if rid:
                yield f"VpcAttachments[{i}].VpcId", "vpc", rid, None, "associated_with"
        for i, ref in enumerate(as_list(data.get("Associations"))):
            if isinstance(ref, dict) and ref.get("SubnetId"):
                yield f"Associations[{i}]", "subnet", ref["SubnetId"], None, "route_association"
        if kind == "transit_gateway_attachment":
            for key, target in (("TransitGatewayId", "transit_gateway"), ("ResourceId", "vpc" if data.get("ResourceType") == "vpc" else "vpn_connection" if data.get("ResourceType") == "vpn" else "network_resource_reference")):
                if isinstance(data.get(key), str) and data[key]:
                    target_scope = None
                    owner = data.get("ResourceOwnerId") if key == "ResourceId" else data.get("TransitGatewayOwnerId")
                    if isinstance(owner, str) and owner and owner != str(resource["scope"]).split("/")[0]:
                        target_scope = f"{owner}/{str(resource['scope']).split('/')[-1]}"
                    yield key, target, data[key], target_scope, "attachment_endpoint"
            association = _object(data.get("Association"))
            rid = association.get("TransitGatewayRouteTableId")
            if isinstance(rid, str) and rid:
                yield "Association.TransitGatewayRouteTableId", "transit_gateway_route_table", rid, None, "route_association"
        if kind == "transit_gateway_vpc_attachment":
            for key, target in (("TransitGatewayId", "transit_gateway"), ("VpcId", "vpc")):
                rid = data.get(key)
                if isinstance(rid, str) and rid:
                    yield key, target, rid, None, "attachment_endpoint"
            for i, rid in enumerate(as_list(data.get("SubnetIds"))):
                if isinstance(rid, str) and rid:
                    yield f"SubnetIds[{i}]", "subnet", rid, None, "attachment_subnet"
        if kind == "vpn_connection":
            for key, target in (("TransitGatewayId", "transit_gateway"), ("VpnGatewayId", "vpn_gateway"), ("CustomerGatewayId", "customer_gateway")):
                if isinstance(data.get(key), str) and data[key]:
                    yield key, target, data[key], None, "vpn_endpoint"
        if kind == "transit_gateway_route_table" and isinstance(data.get("TransitGatewayId"), str):
            yield "TransitGatewayId", "transit_gateway", data["TransitGatewayId"], None, "route_table_of"
        for i, route in enumerate(as_list(data.get("Routes"))):
            if not isinstance(route, dict):
                continue
            for key, target in (("GatewayId", "internet_gateway"), ("NatGatewayId", "nat_gateway"),
                                ("VpcPeeringConnectionId", "vpc_peering"), ("TransitGatewayId", "transit_gateway")):
                if route.get(key) and route[key] != "local":
                    yield f"Routes[{i}].{key}", target, route[key], None, "route_next_hop"
        for key in ("RequesterVpcInfo", "AccepterVpcInfo"):
            ref = _object(data.get(key))
            if ref.get("VpcId"):
                # Cross-account peers need their account+region scope. Never
                # alias an unresolved remote VPC to a same-named local one.
                scope = resource["scope"]
                if ref.get("OwnerId") and str(ref["OwnerId"]) not in scope:
                    scope = f"{ref['OwnerId']}/{ref.get('Region', 'unknown-region')}"
                yield key, "vpc", ref["VpcId"], scope, "peering_endpoint"
        for key in ("Subnets", "AvailabilityZones"):
            for i, ref in enumerate(as_list(data.get(key))):
                rid = _ref_id(ref, "SubnetId")
                if rid:
                    yield f"{key}[{i}]", "subnet", rid, None, "load_balancer_subnet"
        for i, rid in enumerate(as_list(data.get("LoadBalancerArns"))):
            if isinstance(rid, str):
                yield f"LoadBalancerArns[{i}]", "load_balancer", rid, None, "load_balancer_target_group"
        health = data.get("TargetHealth", {})
        if isinstance(health, dict):
            for i, ref in enumerate(as_list(health.get("TargetHealthDescriptions"))):
                target_id = _object(ref).get("Target")
                target_id = _object(target_id).get("Id")
                if isinstance(target_id, str) and target_id.startswith("i-"):
                    yield f"TargetHealth.TargetHealthDescriptions[{i}]", "instance", target_id, None, "registered_target"
    elif provider == "gcp":
        if kind == "gke_cluster":
            data = _managed_network_facts(resource)
        if kind == "shared_vpc":
            if data.get("relationshipType") == "getXpnHost" and data.get("id"):
                yield "id", "project_reference", f"projects/{data['id']}", f"projects/{data['id']}", "shared_vpc_host"
            for i, ref in enumerate(as_list(data.get("resources"))):
                if isinstance(ref, dict) and ref.get("id"):
                    yield f"resources[{i}]", "project_reference", f"projects/{ref['id']}", f"projects/{ref['id']}", "shared_vpc_service_project"
        def refs(value, path):
            if isinstance(value, dict):
                for key, val in value.items():
                    target_types = {"network": "network", "subnetwork": "subnetwork", "backendService": "backend_service",
                                    "targetPool": "target_pool", "target": "target_proxy", "group": "instance_group",
                                    "router": "router", "vpnGateway": "vpn_gateway", "targetVpnGateway": "vpn_gateway", "peerNetwork": "network",
                                    "urlMap": "url_map", "defaultService": "backend_service", "service": "backend_service"}
                    if key in target_types and isinstance(val, str) and (key in {"network", "subnetwork"} or "/projects/" in val):
                        target_kind = target_types[key]
                        if key in {"target", "defaultService", "service"}:
                            for fragment, resolved in (("/targetPools/", "target_pool"), ("/targetVpnGateways/", "vpn_gateway"),
                                    ("/backendBuckets/", "backend_bucket"), ("/backendServices/", "backend_service"),
                                    ("/forwardingRules/", "forwarding_rule")):
                                if fragment in val:
                                    target_kind = resolved
                                    break
                        pieces = urlsplit(val).path.split("/")
                        project = pieces[pieces.index("projects") + 1] if "projects" in pieces else None
                        scope = f"projects/{project}" if project else resource["scope"]
                        yield f"{path}.{key}", target_kind, val, scope, "associated_with"
                    elif key in {"users", "healthChecks"} and isinstance(val, list):
                        for i, rid in enumerate(val):
                            if not isinstance(rid, str) or "/projects/" not in rid:
                                continue
                            target = "forwarding_rule" if "/forwardingRules/" in rid else "health_check" if "/healthChecks/" in rid else None
                            if target:
                                pieces = urlsplit(rid).path.split("/")
                                project = pieces[pieces.index("projects") + 1]
                                yield f"{path}.{key}[{i}]", target, rid, f"projects/{project}", "address_used_by" if key == "users" else "health_check_reference"
                    elif key == "attachmentTarget" and isinstance(val, str) and val:
                        # Hierarchical policy associations can attach at an org,
                        # folder, or network. Only a network URL establishes VPC
                        # containment; the other scopes remain explicit references.
                        if "/networks/" in val:
                            pieces = urlsplit(val).path.split("/")
                            project = pieces[pieces.index("projects") + 1] if "projects" in pieces else None
                            scope = f"projects/{project}" if project else resource["scope"]
                            yield f"{path}.{key}", "network", val, scope, "policy_attachment"
                        else:
                            yield f"{path}.{key}", "policy_scope_reference", val, val, "policy_attachment"
                    elif key == "peerings" and isinstance(val, list):
                        for i, peer in enumerate(val):
                            if isinstance(peer, dict) and peer.get("network"):
                                for p, target, rid, scope, _ in refs(peer, f"{path}.peerings[{i}]"):
                                    yield p, target, rid, scope, "peering_endpoint"
                    elif isinstance(val, (dict, list)):
                        yield from refs(val, f"{path}.{key}")
            elif isinstance(value, list):
                for i, val in enumerate(value):
                    yield from refs(val, f"{path}[{i}]")
        yield from refs(data, "data")
    elif provider == "azure":
        mapping = {"subnet": "subnet", "networkSecurityGroup": "nsg", "networkInterfaces": "nic",
                   "virtualNetwork": "vnet", "remoteVirtualNetwork": "vnet", "publicIPAddress": "public_ip",
                   "routeTable": "route_table", "backendAddressPools": "load_balancer",
                   "virtualNetworkGateway": "virtual_network_gateway"}
        def refs(value, path):
            if not isinstance(value, dict):
                return
            for key, val in value.items():
                if key in mapping:
                    for i, ref in enumerate(as_list(val)):
                        if isinstance(ref, dict) and ref.get("id"):
                            rid = ref["id"]
                            if key == "backendAddressPools" and "/backendAddressPools/" in rid:
                                rid = rid.split("/backendAddressPools/", 1)[0]
                            parts = rid.lower().split("/")
                            # Preserve tenant context while replacing subscription.
                            scope = resource["scope"]
                            if "subscriptions" in parts:
                                subscription = rid.split("/")[parts.index("subscriptions") + 1]
                                if subscription.lower() not in scope.lower():
                                    scope = (f"/subscriptions/{subscription}" if scope.lower().startswith("/subscriptions/")
                                             else f"subscription:{subscription}")
                            yield f"{path}.{key}[{i}]", mapping[key], rid, scope, "associated_with"
                if key == "privateLinkServiceId" and isinstance(val, str) and val:
                    # A Private Endpoint's target may not be in the network
                    # projection. Preserve the ARM ID as an unresolved reference.
                    yield f"{path}.{key}", "private_link_service_reference", val, None, "private_link_target"
                if isinstance(val, dict):
                    yield from refs(val, f"{path}.{key}")
                elif isinstance(val, list):
                    for i, ref in enumerate(val):
                        yield from refs(ref, f"{path}.{key}[{i}]")
        yield from refs(data, "data")
        if kind == "vnet":
            for i, subnet in enumerate(as_list(_object(data.get("properties")).get("subnets"))):
                if isinstance(subnet, dict) and subnet.get("id"):
                    yield f"properties.subnets[{i}]", "subnet", subnet["id"], None, "contains"
    elif provider == "k8s":
        meta = data.get("metadata", {})
        namespace = meta.get("namespace")
        if namespace:
            yield "metadata.namespace", "namespace", namespace, None, "contained_in_namespace"
        if kind == "pod" and data.get("spec", {}).get("nodeName"):
            yield "spec.nodeName", "node", data["spec"]["nodeName"], None, "scheduled_on"


def _k8s_context(snapshot, resource):
    """Collection scope is administrative; native provenance establishes cluster/namespace."""
    data = resource["data"]
    provenance = data.get("provenance", {})
    meta = data.get("metadata", {})
    provenance = provenance if isinstance(provenance, dict) else {}
    meta = meta if isinstance(meta, dict) else {}
    parsed = urlsplit(str(native_id(resource)))
    parts = [unquote(x) for x in parsed.path.split("/") if x]
    native_cluster = unquote(parsed.netloc) if parsed.scheme == "k8s" else None
    clusters = {x for x in (provenance.get("cluster_id"), native_cluster) if isinstance(x, str) and x}
    cluster = next(iter(clusters)) if len(clusters) == 1 else None
    if not clusters:
        cluster = snapshot.get("metadata", {}).get("cluster_id")
    if not isinstance(cluster, str) or not cluster:
        cluster = None
    namespaces = {x for x in (meta.get("namespace"), provenance.get("namespace"),
                  parts[1] if native_cluster and len(parts) >= 3 else None) if isinstance(x, str) and x}
    namespace = next(iter(namespaces)) if len(namespaces) == 1 else None
    if len(namespaces) > 1:
        cluster = None  # Conflicting native/metadata context cannot establish membership.
    return cluster, namespace


def _k8s_selector_requirements(selector, kind):
    """Return validated AND requirements, or an explicit unsupported-evidence reason."""
    if not isinstance(selector, dict):
        return [], "selector_is_not_an_object"
    if kind == "service":
        labels, expressions = selector, []
    else:
        if set(selector) - {"matchLabels", "matchExpressions"}:
            return [], "unsupported_label_selector_fields"
        labels, expressions = selector.get("matchLabels", {}), selector.get("matchExpressions", [])
    if not isinstance(labels, dict) or any(not isinstance(k, str) or not k or not isinstance(v, str)
                                           for k, v in labels.items()):
        return [], "malformed_match_labels"
    if not isinstance(expressions, list):
        return [], "malformed_match_expressions"
    requirements = [(k, "In", [v]) for k, v in labels.items()]
    for expression in expressions:
        if not isinstance(expression, dict) or set(expression) - {"key", "operator", "values"}:
            return [], "malformed_match_expression"
        key, operator, values = expression.get("key"), expression.get("operator"), expression.get("values", [])
        if not isinstance(key, str) or not key or not isinstance(operator, str) or operator not in {"In", "NotIn", "Exists", "DoesNotExist"}:
            return [], "unsupported_match_expression"
        if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
            return [], "malformed_match_expression_values"
        if (operator in {"In", "NotIn"} and not values) or (operator in {"Exists", "DoesNotExist"} and values):
            return [], "invalid_match_expression_values"
        requirements.append((key, operator, values))
    return requirements, None


def _k8s_matches(labels, requirements):
    for key, operator, values in requirements:
        if operator == "In" and (key not in labels or labels[key] not in values):
            return False
        if operator == "NotIn" and key in labels and labels[key] in values:
            return False
        if operator == "Exists" and key not in labels:
            return False
        if operator == "DoesNotExist" and key in labels:
            return False
    return True


def _k8s_workload_selector(snapshot, resource, pods, nodes, edges, pod_status, pod_context_gaps):
    spec = resource["data"].get("spec", {})
    key = "selector" if resource["type"] == "service" else "podSelector"
    if not isinstance(spec, dict) or key not in spec:
        return
    selector = spec[key]
    cluster, namespace = _k8s_context(snapshot, resource)
    # Service equality maps and NetworkPolicy LabelSelectors have different
    # empty-selector semantics and must never share one selector node.
    dst = stable_id("k8s", resource["scope"], cluster, namespace, resource["type"], "workload_selector", selector)
    selector_source = source(snapshot, resource, f"spec.{key}")
    edges.append(relationship(node_id(resource), dst, "declared_selector", selector_source))
    if dst in nodes:
        return  # Expand a shared selector only once, including its pod edges.
    requirements, reason = _k8s_selector_requirements(selector, resource["type"])
    if cluster is None or namespace is None:
        reason = reason or "cluster_or_namespace_context_unavailable_or_conflicting"
    automatic = not (resource["type"] == "service" and selector == {})
    evidence = {"namespace": namespace, "cluster_id": cluster, "selector": selector,
        "selector_kind": resource["type"], "source": selector_source, "matched_pod_count": 0,
        "matching_workloads": "unknown" if reason else "expanded" if automatic else "no_automatic_selection",
        "pod_inventory_status": pod_status.get(resource["scope"], "not_collected"),
        "reachability": "unknown",
        "semantics": "Service nonempty equality map" if resource["type"] == "service" else "NetworkPolicy AND LabelSelector; empty selects all namespace pods",
        "uncertainty": "Label membership is structural; readiness, endpoints, ports, additive policies, CNI enforcement, and routed reachability are unresolved"}
    if reason:
        evidence["reason"] = reason
    elif not automatic:
        evidence["reason"] = "empty_service_selector_has_no_automatic_pod_selection"
    description = json.dumps(selector, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    nodes[dst] = {"id": dst, "label": f"{resource['type']} selector in {namespace or 'unknown namespace'}: {description}",
        "type": "workload_selector", "provider": "k8s", "scope": resource["scope"],
        "evidence": evidence, "card": {"namespace": namespace, "cluster_id": cluster,
                                       "selector_kind": resource["type"], "selector": selector}}
    if reason or not automatic:
        return
    if evidence["pod_inventory_status"] not in {"collected", "empty"}:
        evidence["matching_workloads"] = "partial" if pods.get((resource["scope"], cluster, namespace)) else "unknown"
        evidence["reason"] = "pod_inventory_incomplete"
    if resource["scope"] in pod_context_gaps:
        evidence["matching_workloads"] = "partial"
        evidence["reason"] = "some_pod_context_is_unavailable_or_conflicting"
    for pod in pods.get((resource["scope"], cluster, namespace), []):
        labels = pod["data"].get("metadata", {}).get("labels", {})
        if not isinstance(labels, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in labels.items()):
            evidence["matching_workloads"] = "partial"
            evidence["reason"] = "some_pod_labels_are_malformed"
            continue
        if _k8s_matches(labels, requirements):
            evidence["matched_pod_count"] += 1
            edges.append(relationship(dst, node_id(pod), "matches_pod", {
                "source": selector_source, "pod_source": source(snapshot, pod, "metadata.labels"),
                "selector": selector, "labels": labels, "cluster_id": cluster,
                "namespace": namespace, "reachability": "unknown", "uncertainty": evidence["uncertainty"]}))


def _k8s_interface(snapshot, resource, owners, nodes, edges):
    data = resource["data"]
    cluster, namespace = _k8s_context(snapshot, resource)
    ref = data.get("resource_id")
    candidates = owners.get((resource["scope"], cluster, ref), []) if isinstance(ref, str) and cluster else []
    candidates = [r for r in candidates if namespace is None or _k8s_context(snapshot, r)[1] == namespace]
    attachment = {"status": "unresolved", "owner_native_id": ref}
    if cluster is None:
        attachment["reason"] = "cluster_context_unavailable_or_conflicting"
    elif not isinstance(ref, str) or not ref:
        attachment["reason"] = "owner_native_id_missing"
    elif len(candidates) != 1:
        attachment["reason"] = "owner_not_collected_in_exact_scope_cluster_namespace" if not candidates else "owner_native_id_ambiguous"
    else:
        owner = candidates[0]
        attachment.update(status="resolved", owner_node_id=node_id(owner))
        edges.append(relationship(node_id(owner), node_id(resource), "attached_interface", {
            "source": source(snapshot, resource, "resource_id"), "owner_source": source(snapshot, owner, "id"),
            "owner_native_id": ref, "reachability": "unknown",
            "uncertainty": "Observed object.status addresses; authoritative CNI interface inventory and routed reachability are not established"}))
    current = nodes[node_id(resource)]
    current["evidence"].update(attachment=attachment, addresses=data.get("addresses", []),
        cluster_id=cluster, authoritative_interface_inventory=False, reachability="unknown",
        uncertainty="Observed addresses retain overlaps, IPv4/IPv6, and hostnames; no IP-based owner inference")
    current["card"] = {"attachment": attachment, "addresses": data.get("addresses", [])}


def build_network(snapshot, resources):
    selected = [r for r in resources if r["type"] in NETWORK_TYPES]
    nodes = {node_id(r): node(r) for r in selected}
    lookup = {}
    k8s_pods, k8s_owners, pod_context_gaps = {}, {}, set()
    pod_status = {c["scope"]: c["status"] for c in snapshot["collections"] if c["type"] == "pod"}
    for resource in selected:
        data = _object(resource["data"])
        if resource["type"] in {"rds_instance", "rds_cluster", "lambda_function", "eks_cluster", "gke_cluster"} and not _managed_network_facts(resource):
            nodes[node_id(resource)]["evidence"]["placement_status"] = "unknown"
            nodes[node_id(resource)]["evidence"]["placement_reason"] = "native_network_attachment_or_endpoint_facts_missing"
        if resource["provider"] == "k8s":
            cluster, namespace = _k8s_context(snapshot, resource)
            if resource["type"] == "pod" and cluster and namespace:
                k8s_pods.setdefault((resource["scope"], cluster, namespace), []).append(resource)
            elif resource["type"] == "pod":
                pod_context_gaps.add(resource["scope"])
            if cluster and (resource["type"] == "node" or resource["type"] == "pod" and namespace):
                for alias in {str(native_id(resource)), data.get("id") if isinstance(data.get("id"), str) else None} - {None}:
                    k8s_owners.setdefault((resource["scope"], cluster, alias), []).append(resource)
        aliases = [native_id(resource), data.get("id"), data.get("selfLink"), data.get("name"),
                   _object(data.get("metadata")).get("name")]
        for alias in aliases:
            if alias:
                lookup[(resource["scope"], resource["type"], str(alias).casefold() if resource["provider"] == "azure" else str(alias))] = node_id(resource)
    edges = []
    for resource in selected:
        src = node_id(resource)
        if resource["provider"] == "gcp" and resource["type"] == "instance":
            for i, interface in enumerate(as_list(resource["data"].get("networkInterfaces"))):
                if not isinstance(interface, dict):
                    continue
                rid = f"{native_id(resource)}/networkInterfaces/{i}"
                dst = stable_id("gcp", resource["scope"], "network_interface", rid)
                nodes[dst] = {"id": dst, "native_id": rid, "resource_id": gcp_interface_resource_id(resource, i),
                    "label": str(interface.get("name", f"interface {i}")), "type": "network_interface",
                    "provider": "gcp", "scope": resource["scope"],
                    "evidence": {"native_resource": interface, "source": source(snapshot, resource, f"networkInterfaces[{i}]")}}
                edges.append(relationship(src, dst, "attached_interface", source(snapshot, resource, f"networkInterfaces[{i}]")))
                embedded = {**resource, "type": "network_interface", "native_id": rid, "data": interface}
                for path, kind, ref, scope, relation in references(embedded):
                    scope = scope or resource["scope"]
                    target = lookup.get((scope, kind, str(ref))) or stable_id("gcp", scope, kind, ref)
                    nodes.setdefault(target, {"id": target, "label": str(ref), "native_id": str(ref), "resource_id": None,
                        "type": kind, "provider": "gcp", "scope": scope, "evidence": {"inventory_status": "reference_only"}})
                    edges.append(relationship(dst, target, relation, source(snapshot, resource, f"networkInterfaces[{i}].{path}")))
        for path, kind, rid, scope, relation in references(resource):
            scope = scope or resource["scope"]
            key = (scope, kind, str(rid).casefold() if resource["provider"] == "azure" else str(rid))
            dst = lookup.get(key)
            if dst is None:
                dst = stable_id(resource["provider"], scope, kind, rid)
                nodes.setdefault(dst, {"id": dst, "label": str(rid), "resource_id": None,
                    "native_id": str(rid), "type": kind, "provider": resource["provider"], "scope": scope,
                    "evidence": {"inventory_status": "reference_only", "uncertainty": "Referenced resource was not collected in this scope"}})
            if dst != src:
                edges.append(relationship(src, dst, relation, source(snapshot, resource, path)))
        if resource["provider"] == "k8s" and resource["type"] in {"service", "networkpolicy"}:
            _k8s_workload_selector(snapshot, resource, k8s_pods, nodes, edges, pod_status, pod_context_gaps)
        if resource["provider"] == "k8s" and resource["type"] == "network_interface":
            _k8s_interface(snapshot, resource, k8s_owners, nodes, edges)
        for path, rule, semantics in public_rules(resource):
            dst = stable_id(resource["provider"], resource["scope"], "internet_source")
            nodes.setdefault(dst, {"id": dst, "label": "Unrestricted source selector", "type": "internet_source",
                "provider": resource["provider"], "scope": resource["scope"], "evidence": {"reachability": "unknown"}})
            edges.append(relationship(dst, src, "rule_candidate", {"source": source(snapshot, resource, path),
                "native_rule": rule, "uncertainty": semantics,
                "reachability": "unknown", "telemetry": "not_collected"}, layer="modeled_rule", confidence="low"))
    # Parent IDs are layout hints derived from observed containment only.
    # Policies/peering/route adjacency cannot establish workload containment.
    parent_ranks = {"subnet": 0, "subnetwork": 0, "namespace": 0, "vpc": 1, "vnet": 1, "network": 1}
    candidates = {}
    for edge in edges:
        if edge["type"] == "contains":
            candidates.setdefault(edge["target"], []).append((0, edge["source"], edge["id"]))
        elif edge["type"] in {"associated_with", "contained_in_namespace"}:
            target = nodes[edge["target"]]
            if target["type"] in parent_ranks:
                candidates.setdefault(edge["source"], []).append((parent_ranks[target["type"]], target["id"], edge["id"]))
    for nid, current in nodes.items():
        # Synthetic selector nodes have no native cloud identity.
        current.setdefault("native_id", None)
        current.setdefault("native_kind", current["type"])
        current.setdefault("provider_specific", {"native_kind": current["type"]})
        current["display_group"] = "namespace" if current["type"] == "namespace" else "network" if current["type"] in {"vpc", "vnet", "network"} else "resource"
        parents = candidates.get(nid, [])
        if parents:
            best_rank = min(x[0] for x in parents)
            best = {parent for rank, parent, _ in parents if rank == best_rank}
            if len(best) == 1:
                current["parent_id"] = next(iter(best))
                current["parent_edge_refs"] = sorted(eid for rank, parent, eid in parents if rank == best_rank)
            else:
                current["parent_candidates"] = sorted(best)
        if current["provider"] == "gcp" and current["type"] == "network":
            current["provider_specific"]["network_scope"] = "global"
    return {"nodes": sorted(nodes.values(), key=lambda row: row["id"]),
            "edges": sorted(edges, key=lambda row: row["id"]),
            "semantics": "Structural inventory and conditional rule candidates; telemetry and routed reachability are not inferred"}
