"""Network inventory associations and rule evidence, without all-pairs routing."""
from __future__ import annotations

import copy
from urllib.parse import urlsplit

from .common import as_list, finding, native_id, node, node_id, relationship, source, stable_id

NETWORK_TYPES = {"vpc", "subnet", "security_group", "network_interface", "instance", "route_table",
    "internet_gateway", "nat_gateway", "vpc_peering", "transit_gateway", "load_balancer", "classic_load_balancer",
    "target_group", "network", "subnetwork", "firewall", "route", "forwarding_rule", "backend_service", "target_pool", "target_proxy", "instance_group",
    "shared_vpc", "vnet", "nsg", "nic", "vm", "public_ip", "loadbalancer", "application_gateway", "peering", "vnet_peering",
    "pod", "service", "networkpolicy", "namespace", "ingress", "node", "endpoint", "endpointslice"}
PUBLIC = {"0.0.0.0/0", "::/0", "*", "Internet"}


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
        rules = [{"source": source(snapshot, resource, path), "native_rule": copy.deepcopy(rule),
                  "semantics": semantics} for path, rule, semantics in public_rules(resource)]
        if rules:
            findings.append(finding(snapshot, resource, "exposure", "analysis.network_review",
                "Review unrestricted network rule candidates", "high",
                {"rules": rules, "risk_state": "conditional", "layer": "modeled_rule",
                 "reachability": "unknown", "telemetry": "not_collected"}))
    return findings


def references(resource):
    data, provider, kind = resource["data"], resource["provider"], resource["type"]
    if provider == "aws":
        for key, target in (("VpcId", "vpc"), ("SubnetId", "subnet"), ("NetworkInterfaceId", "network_interface")):
            if data.get(key) and not (kind == target and str(data[key]) == str(native_id(resource))):
                yield key, target, str(data[key]), None, "associated_with"
        for key in ("SecurityGroups", "Groups"):
            for i, ref in enumerate(as_list(data.get(key))):
                rid = ref.get("GroupId") if isinstance(ref, dict) else ref
                if rid:
                    yield f"{key}[{i}]", "security_group", rid, None, "protected_by"
        for i, ref in enumerate(as_list(data.get("NetworkInterfaces"))):
            if isinstance(ref, dict) and ref.get("NetworkInterfaceId"):
                yield f"NetworkInterfaces[{i}]", "network_interface", ref["NetworkInterfaceId"], None, "attached_interface"
        for i, ref in enumerate(as_list(data.get("Associations"))):
            if isinstance(ref, dict) and ref.get("SubnetId"):
                yield f"Associations[{i}]", "subnet", ref["SubnetId"], None, "route_association"
        for i, route in enumerate(as_list(data.get("Routes"))):
            if not isinstance(route, dict):
                continue
            for key, target in (("GatewayId", "internet_gateway"), ("NatGatewayId", "nat_gateway"),
                                ("VpcPeeringConnectionId", "vpc_peering"), ("TransitGatewayId", "transit_gateway")):
                if route.get(key) and route[key] != "local":
                    yield f"Routes[{i}].{key}", target, route[key], None, "route_next_hop"
        for key in ("RequesterVpcInfo", "AccepterVpcInfo"):
            ref = data.get(key, {})
            if ref.get("VpcId"):
                # Cross-account peers need their account+region scope. Never
                # alias an unresolved remote VPC to a same-named local one.
                scope = resource["scope"]
                if ref.get("OwnerId") and str(ref["OwnerId"]) not in scope:
                    scope = f"{ref['OwnerId']}/{ref.get('Region', 'unknown-region')}"
                yield key, "vpc", ref["VpcId"], scope, "peering_endpoint"
        for key in ("Subnets", "AvailabilityZones"):
            for i, ref in enumerate(as_list(data.get(key))):
                rid = ref.get("SubnetId") if isinstance(ref, dict) else ref
                if rid:
                    yield f"{key}[{i}]", "subnet", rid, None, "load_balancer_subnet"
        for i, rid in enumerate(as_list(data.get("LoadBalancerArns"))):
            if isinstance(rid, str):
                yield f"LoadBalancerArns[{i}]", "load_balancer", rid, None, "load_balancer_target_group"
        health = data.get("TargetHealth", {})
        if isinstance(health, dict):
            for i, ref in enumerate(as_list(health.get("TargetHealthDescriptions"))):
                if isinstance(ref, dict) and str(ref.get("Target", {}).get("Id", "")).startswith("i-"):
                    yield f"TargetHealth.TargetHealthDescriptions[{i}]", "instance", ref["Target"]["Id"], None, "registered_target"
    elif provider == "gcp":
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
                                    "targetPool": "target_pool", "target": "target_proxy", "group": "instance_group"}
                    if key in target_types and isinstance(val, str) and (key in {"network", "subnetwork"} or "/projects/" in val):
                        pieces = urlsplit(val).path.split("/")
                        project = pieces[pieces.index("projects") + 1] if "projects" in pieces else None
                        scope = (f"projects/{project}" if resource["scope"].startswith("projects/") else project) if project else resource["scope"]
                        yield f"{path}.{key}", target_types[key], val, scope, "associated_with"
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
                   "routeTable": "route_table", "backendAddressPools": "loadbalancer"}
        def refs(value, path):
            if not isinstance(value, dict):
                return
            for key, val in value.items():
                if key in mapping:
                    for i, ref in enumerate(as_list(val)):
                        if isinstance(ref, dict) and ref.get("id"):
                            rid = ref["id"]
                            parts = rid.lower().split("/")
                            # Preserve tenant context while replacing subscription.
                            scope = resource["scope"]
                            if "subscriptions" in parts:
                                subscription = rid.split("/")[parts.index("subscriptions") + 1]
                                if subscription.lower() not in scope.lower():
                                    scope = f"subscription:{subscription}"
                            yield f"{path}.{key}[{i}]", mapping[key], rid, scope, "associated_with"
                if isinstance(val, dict):
                    yield from refs(val, f"{path}.{key}")
                elif isinstance(val, list):
                    for i, ref in enumerate(val):
                        yield from refs(ref, f"{path}.{key}[{i}]")
        yield from refs(data, "data")
        if kind == "vnet":
            for i, subnet in enumerate(as_list(data.get("properties", {}).get("subnets"))):
                if isinstance(subnet, dict) and subnet.get("id"):
                    yield f"properties.subnets[{i}]", "subnet", subnet["id"], None, "contains"
    elif provider == "k8s":
        meta = data.get("metadata", {})
        namespace = meta.get("namespace")
        if namespace:
            yield "metadata.namespace", "namespace", namespace, None, "contained_in_namespace"
        if kind == "pod" and data.get("spec", {}).get("nodeName"):
            yield "spec.nodeName", "node", data["spec"]["nodeName"], None, "scheduled_on"


def build_network(snapshot, resources):
    selected = [r for r in resources if r["type"] in NETWORK_TYPES]
    nodes = {node_id(r): node(r) for r in selected}
    lookup = {}
    for resource in selected:
        data = resource["data"]
        aliases = [native_id(resource), data.get("id"), data.get("selfLink"), data.get("name"),
                   data.get("metadata", {}).get("name")]
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
                rid = f"{native_id(resource)}/networkInterfaces/{interface.get('name', i)}"
                dst = stable_id("gcp", resource["scope"], "network_interface", rid)
                nodes[dst] = {"id": dst, "native_id": rid, "resource_id": resource.get("id"),
                    "label": str(interface.get("name", f"interface {i}")), "type": "network_interface",
                    "provider": "gcp", "scope": resource["scope"],
                    "evidence": {"native_resource": copy.deepcopy(interface), "source": source(snapshot, resource, f"networkInterfaces[{i}]")}}
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
            spec = resource["data"].get("spec", {})
            key = "selector" if resource["type"] == "service" else "podSelector"
            if key in spec:
                namespace = resource["data"].get("metadata", {}).get("namespace", "default")
                selector = copy.deepcopy(spec[key])
                dst = stable_id(resource["provider"], resource["scope"], namespace, "workload_selector", selector)
                nodes.setdefault(dst, {"id": dst, "label": f"Workload selector in {namespace}", "type": "workload_selector",
                    "provider": resource["provider"], "scope": resource["scope"],
                    "evidence": {"namespace": namespace, "selector": selector, "matching_workloads": "not_expanded"}})
                edges.append(relationship(src, dst, "declared_selector", source(snapshot, resource, f"spec.{key}")))
        for path, rule, semantics in public_rules(resource):
            dst = stable_id(resource["provider"], resource["scope"], "internet_source")
            nodes.setdefault(dst, {"id": dst, "label": "Unrestricted source selector", "type": "internet_source",
                "provider": resource["provider"], "scope": resource["scope"], "evidence": {"reachability": "unknown"}})
            edges.append(relationship(dst, src, "rule_candidate", {"source": source(snapshot, resource, path),
                "native_rule": copy.deepcopy(rule), "uncertainty": semantics,
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
        current.setdefault("native_kind", current["type"])
        current.setdefault("provider_specific", {"native_kind": current["type"]})
        current["display_group"] = "namespace" if current["type"] == "namespace" else "network" if current["type"] in {"vpc", "vnet", "network"} else "resource"
        parents = candidates.get(nid, [])
        if parents:
            best_rank = min(x[0] for x in parents)
            best = {parent for rank, parent, _ in parents if rank == best_rank}
            if len(best) == 1:
                current["parent_id"] = next(iter(best))
                current["parent_edge_refs"] = [eid for rank, parent, eid in parents if rank == best_rank]
            else:
                current["parent_candidates"] = sorted(best)
        if current["provider"] == "gcp" and current["type"] == "network":
            current["provider_specific"]["network_scope"] = "global"
    return {"nodes": list(nodes.values()), "edges": edges,
            "semantics": "Structural inventory and conditional rule candidates; telemetry and routed reachability are not inferred"}
