"""Selected-flow native configuration model, never a probe or a path explorer.

Only TCP/UDP new flows between explicit private endpoints are supported. Every
allowance needs complete associations, policy/routing context, and address domain
evidence; unknown is a first-class result. Provider documentation is linked in
docs/peaso-reachability.md beside each supported case.
"""
from __future__ import annotations

import copy
import ipaddress
from collections import defaultdict

from peaso.snapshot import make_snapshot, resources, validate

REACHABILITY_TYPES = {
    "aws": frozenset({"instance", "network_interface", "vpc", "subnet", "security_group", "network_acl",
        "route_table", "vpc_peering", "nat_gateway", "transit_gateway", "vpc_endpoint", "load_balancer"}),
    "azure": frozenset({"vm", "nic", "vnet", "subnet", "nsg", "route_table", "vnet_peering", "service_tag",
        "effective_route", "security_admin_rule", "public_ip", "nat_gateway", "load_balancer", "application_gateway"}),
    "gcp": frozenset({"instance", "network", "subnetwork", "firewall", "route", "shared_vpc", "router",
        "firewall_policy", "hierarchical_firewall_policy", "network_firewall_policy", "policy_based_route",
        "forwarding_rule", "backend_service"}),
    "k8s": frozenset({"pod", "namespace", "networkpolicy", "node", "service", "ingress", "daemonset",
        "cni_configuration", "cilium_networkpolicy", "calico_networkpolicy"}),
}


def network_snapshot(snapshot):
    """Seal a small native-network artifact without inventing collection coverage.

    Whole dependency collections and their original statuses remain intact. IDs
    continue to refer to the original source snapshot, whose digest is disclosed
    separately from this derived artifact's digest.
    """
    snapshot = validate(snapshot)
    metadata = {k: copy.deepcopy(v) for k, v in snapshot.get("metadata", {}).items()
        if k in {"network_context", "cluster_id", "account_id", "account_ids", "tenant_id", "requested_scopes",
                 "resolved_scopes", "scope_coverage", "collection", "collector", "limits", "budget"}}
    metadata["original_snapshot_id"] = snapshot.get("metadata", {}).get("original_snapshot_id", snapshot["snapshot_id"])
    metadata["projection"] = "complete native network dependency collections; unrelated identity inventory omitted"
    return make_snapshot(snapshot["provider"], snapshot["scopes"],
        [c for c in snapshot["collections"] if c["type"] in REACHABILITY_TYPES[snapshot["provider"]]],
        created_at=snapshot["created_at"], metadata=metadata)


def _all(values):
    values = list(values)
    return False if False in values else None if None in values else True


def _any(values):
    values = list(values)
    return True if True in values else None if None in values else False


def _cidr(value, address):
    if not isinstance(value, str):
        return None
    try:
        network = ipaddress.ip_network(value, strict=False)
        return address.version == network.version and address in network
    except (ValueError, TypeError):
        return None


def _ports(value, port):
    if value in ("*", "Any", "any"):
        return True
    if isinstance(value, bool):
        return None
    try:
        if isinstance(value, int) or str(value).isdigit():
            low = high = int(value)
        else:
            low, high = (int(p) for p in str(value).split("-"))
        if not 0 <= low <= high <= 65535:
            return None
        if port is None:
            return True if low <= 1 and high == 65535 else None
        return low <= port <= high
    except (ValueError, TypeError):
        return None


def _protocol(native, requested):
    text = str(native).lower()
    if text in {"-1", "*", "all", "any"}:
        return True
    if text in {"tcp", "6", "udp", "17", "icmp", "1", "icmpv6", "58", "sctp", "132", "esp", "50", "ah", "51"}:
        return text in {requested, "6" if requested == "tcp" else "17"}
    return None


class _Model:
    def __init__(self, snapshot, query):
        self.snapshot = snapshot
        self.provider = snapshot["provider"]
        self.items = resources(snapshot)
        self.by_id = {r["id"]: r for r in self.items}
        self.kinds = defaultdict(list)
        self.native = defaultdict(list)
        self.collections = defaultdict(list)
        for resource in self.items:
            self.kinds[resource["type"]].append(resource)
            aliases = {str(resource["native_id"]), str(resource["data"].get("id", "")), str(resource["data"].get("selfLink", ""))}
            for alias in aliases - {""}:
                alias = alias.lower() if self.provider == "azure" else _gcp_id(alias) if self.provider == "gcp" else alias
                self.native[(resource["type"], resource["scope"], alias)].append(resource)
                self.native[(resource["type"], None, alias)].append(resource)
        for collection in snapshot["collections"]:
            self.collections[(collection["type"], collection["scope"])].append(collection)
        self.result = {"decision": "unknown", "provider": self.provider,
            "snapshot_id": snapshot.get("metadata", {}).get("original_snapshot_id", snapshot["snapshot_id"]),
            "scoped_snapshot_id": snapshot["snapshot_id"], "query": query, "endpoints": {},
            "routes": [], "policy_decisions": [], "translations": [], "unresolved_dependencies": [],
            "evidence_refs": [], "context_evidence": [], "modeled_configuration": True, "application_listening": "unknown",
            "new_flow_only": True, "semantics": "A configuration allowance is not listening, packet delivery, or live telemetry"}
        self._evidence = set()
        self._context_seen = set()

    def ref(self, resource, path):
        ref = {"snapshot_id": self.result["snapshot_id"], "scoped_snapshot_id": self.snapshot["snapshot_id"],
            "resource_id": resource["id"], "native_id": resource["native_id"], "type": resource["type"],
            "scope": resource["scope"], "path": path}
        collections = self.collections.get((resource["type"], resource["scope"]), [])
        ref["collection_status"] = collections[0]["status"] if len(collections) == 1 else "unknown"
        key = (resource["id"], path)
        if key not in self._evidence:
            self.result["evidence_refs"].append(ref)
            self._evidence.add(key)
        return ref

    def gap(self, code, message, refs=()):
        value = {"code": code, "message": message, "evidence_refs": list(refs)}
        if value not in self.result["unresolved_dependencies"]:
            self.result["unresolved_dependencies"].append(value)
        return "unknown"

    def step(self, layer, decision, message, refs=(), **details):
        step = {"decision": decision, "message": message, "evidence_refs": list(refs), **details}
        self.result["routes" if layer == "route" else "policy_decisions"].append(step)
        return decision

    def complete(self, kind, scope):
        collections = self.collections.get((kind, scope), [])
        return len(collections) == 1 and collections[0]["status"] in {"collected", "empty"}

    def find(self, kind, native, scope=None):
        expected = str(native).lower() if self.provider == "azure" else _gcp_id(str(native)) if self.provider == "gcp" else str(native)
        # Multiple textual aliases may normalize to one provider identifier.
        matches = {r["id"]: r for r in self.native.get((kind, scope, expected), [])}
        matches = list(matches.values())
        return matches[0] if len(matches) == 1 else None

    def context(self, name):
        context = self.snapshot.get("metadata", {}).get("network_context", {}).get(self.provider, {}).get(name, {})
        context = context if isinstance(context, dict) else {}
        if name not in self._context_seen:
            self._context_seen.add(name)
            self.result["context_evidence"].append({"path": f"metadata.network_context.{self.provider}.{name}",
                "snapshot_id": self.result["snapshot_id"], "scoped_snapshot_id": self.snapshot["snapshot_id"],
                "status": context.get("status", "unknown"), "complete": context.get("complete", False),
                "source_evidence": copy.deepcopy(context.get("source_evidence", []))})
        return context

    def context_complete(self, name):
        value = self.context(name)
        evidence = value.get("source_evidence")
        return value.get("status") == "collected" and value.get("complete") is True and isinstance(evidence, list) and bool(evidence) and all(isinstance(e, dict) for e in evidence)


def _gcp_id(value):
    return "projects/" + value.split("/projects/", 1)[1] if "/projects/" in value else value.lstrip("/")


def _gcp_network_id(resource):
    # Native SDK objects often have a numeric id in addition to selfLink.
    # The network reference is project-qualified; a numeric id is not that URL.
    return _gcp_id(resource["data"].get("selfLink", resource["data"].get("_resource_id", resource["native_id"])))


def _gcp_owner_scope(model, kind, network):
    identity = _gcp_network_id(network)
    parts = identity.split("/")
    if len(parts) < 2 or parts[0] != "projects":
        return None
    aliases = {"/".join(parts[:2]), parts[1]}
    scopes = {scope for (actual_kind, scope) in model.collections if actual_kind == kind and scope in aliases}
    return next(iter(scopes)) if len(scopes) == 1 else None


def _address(model, candidates, family, resource):
    addresses = set()
    for candidate in candidates:
        if candidate is None:
            continue
        if not isinstance(candidate, str):
            model.gap("malformed_endpoint_address", "Native endpoint addresses must be strings", [model.ref(resource, "addresses")])
            return None
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            model.gap("malformed_endpoint_address", "A native endpoint address is malformed", [model.ref(resource, "addresses")])
            return None
        if address.version == (4 if family == "ipv4" else 6):
            addresses.add(address)
    if len(addresses) != 1:
        model.gap("endpoint_address_missing" if not addresses else "endpoint_address_ambiguous",
            "The selected family requires exactly one native private endpoint address", [model.ref(resource, "addresses")])
        return None
    return addresses.pop()


def _aws_endpoint(model, resource, family):
    data = resource["data"]
    if resource["type"] not in {"instance", "network_interface"}:
        model.gap("unsupported_endpoint_type", "AWS selected endpoints must be an instance or network interface", [model.ref(resource, "data")])
        return None
    if resource["type"] == "instance" and len(data.get("NetworkInterfaces", [])) > 1:
        model.gap("endpoint_interface_ambiguous", "Select a specific interface for a multi-interface instance", [model.ref(resource, "NetworkInterfaces")])
        return None
    endpoint = resource
    if resource["type"] == "instance" and data.get("NetworkInterfaces"):
        declared = data["NetworkInterfaces"][0]
        collected = model.find("network_interface", declared.get("NetworkInterfaceId"), resource["scope"])
        if collected:
            endpoint, data = collected, collected["data"]
        else:
            data = declared
    if data.get("InterfaceType", "interface") not in {"interface"}:
        model.gap("unsupported_interface_type", "Appliance, endpoint, and managed interface translations are not modeled", [model.ref(endpoint, "InterfaceType")])
        return None
    candidates = [data.get("PrivateIpAddress")]
    candidates += [p.get("PrivateIpAddress") for p in data.get("PrivateIpAddresses", [])]
    candidates += [p.get("Ipv6Address") for p in data.get("Ipv6Addresses", [])]
    address = _address(model, candidates, family, endpoint)
    groups = data.get("Groups", data.get("SecurityGroups"))
    if groups is None:
        model.gap("security_group_association_missing", "Endpoint security-group associations were not collected", [model.ref(endpoint, "Groups")])
    subnet = model.find("subnet", data.get("SubnetId"), resource["scope"])
    vpc = model.find("vpc", data.get("VpcId"), resource["scope"])
    if subnet is None or vpc is None:
        model.gap("network_domain_missing", "Selected subnet and VPC facts are required in their exact account/region scope", [model.ref(endpoint, "SubnetId/VpcId")])
    elif subnet["data"].get("VpcId") != data.get("VpcId"):
        model.gap("network_domain_mismatch", "Endpoint and subnet VPC associations disagree", [model.ref(subnet, "VpcId")])
        subnet = None
    if address is not None and subnet:
        ranges = [subnet["data"].get("CidrBlock")] + [v.get("Ipv6CidrBlock") for v in subnet["data"].get("Ipv6CidrBlockAssociationSet", [])
            if v.get("Ipv6CidrBlockState", {}).get("State", "associated") == "associated"]
        matches = [_cidr(value, address) for value in ranges if value]
        if not matches or True not in matches:
            model.gap("endpoint_outside_subnet", "Private endpoint address is not proven inside the selected subnet address family", [model.ref(subnet, "CidrBlock/Ipv6CidrBlockAssociationSet")])
    if address is not None and vpc and not any(_cidr(p, address) is True for p in _aws_vpc_ranges(vpc["data"])):
        model.gap("network_domain_missing", "Selected address is not proven inside the native VPC address family", [model.ref(vpc, "CidrBlock/CidrBlockAssociationSet/Ipv6CidrBlockAssociationSet")])
    for dependency in (endpoint, subnet, vpc):
        if dependency and not model.complete(dependency["type"], dependency["scope"]):
            model.gap("endpoint_association_incomplete", "Native endpoint/subnet/VPC association collection is missing or partial", [model.ref(dependency, "data")])
    return {"resource": endpoint, "selected": resource, "address": address, "scope": resource["scope"],
            "subnet": subnet, "vpc": vpc, "group_ids": list(dict.fromkeys(g.get("GroupId") for g in groups)) if isinstance(groups, list) else None}


def _aws_sg(model, endpoint, peer, direction, query):
    groups = endpoint["group_ids"]
    if not groups:
        return model.gap("security_group_association_missing", "The selected endpoint lacks a complete nonempty security-group association")
    known = []
    uncertain = False
    potential_translated_allow = False
    refs = []
    key = "IpPermissionsEgress" if direction == "egress" else "IpPermissions"
    for group_id in groups:
        group = model.find("security_group", group_id, endpoint["scope"])
        if group is None or key not in group["data"] or not model.complete("security_group", endpoint["scope"]):
            uncertain = True
            continue
        if endpoint["vpc"] is None or group["data"].get("VpcId") != endpoint["vpc"]["data"].get("VpcId"):
            uncertain = True
            continue
        refs.append(model.ref(group, key))
        for index, rule in enumerate(group["data"][key]):
            proto = _protocol(rule.get("IpProtocol"), query["protocol"])
            port = True if str(rule.get("IpProtocol")) == "-1" else _all([
                _ports(f"{rule.get('FromPort')}-{rule.get('ToPort')}", query["destination_port"])])
            if _all([proto, port]) is not False:
                potential_translated_allow = True
            selectors = [_cidr(r.get("CidrIp"), peer["address"]) for r in rule.get("IpRanges", [])]
            selectors += [_cidr(r.get("CidrIpv6"), peer["address"]) for r in rule.get("Ipv6Ranges", [])]
            if rule.get("PrefixListIds"):
                selectors.append(None)
            for pair in rule.get("UserIdGroupPairs", []):
                selected = pair.get("GroupId") in (peer["group_ids"] or [])
                if selected and pair.get("VpcId") and peer["vpc"] and pair["VpcId"] != peer["vpc"]["data"].get("VpcId"):
                    selected = False
                peer_group = model.find("security_group", pair.get("GroupId"), peer["scope"])
                # A shared security group may belong to a different account
                # than its attached ENI. UserId is the SG owner, not ENI owner.
                peer_account = peer_group["data"].get("OwnerId") if peer_group else None
                if peer_group:
                    refs.append(model.ref(peer_group, "OwnerId/VpcId"))
                if selected and pair.get("UserId") and str(pair["UserId"]) != str(peer_account):
                    selected = None if peer_account is None else False
                if selected and endpoint["vpc"] and peer["vpc"] and endpoint["vpc"]["id"] != peer["vpc"]["id"]:
                    # SG references across peering only work within one Region.
                    regions = [e["resource"]["data"].get("Region") or e["scope"].split("/")[-1] for e in (endpoint, peer)]
                    if regions[0] != regions[1]:
                        selected = None
                    if endpoint["scope"] != peer["scope"] and (not pair.get("UserId") or peer_account is None):
                        selected = None
                selectors.append(selected)
            matched = _all([proto, port, _any(selectors)])
            if matched is True:
                known.append(model.ref(group, f"{key}[{index}]"))
            elif matched is None:
                uncertain = True
    if known:
        return model.step("policy", "allowed", "Aggregated attached security-group allow matches this new flow", known,
            control="aws.security_group", direction=direction, return_behavior="stateful: matching response allowed without reverse SG rule")
    if uncertain:
        return model.gap("security_group_rules_incomplete", "Missing SG rules, prefix lists, or unresolved referenced-group membership prevent a definitive union result", refs)
    return model.step("policy", "blocked", "No allow in the complete attached security-group rule union", refs,
        control="aws.security_group", direction=direction, pre_route=direction == "egress",
        address_translation_invariant=not potential_translated_allow)


def _aws_route_table(model, endpoint):
    if not endpoint["subnet"] or not endpoint["vpc"]:
        return None
    if not model.complete("route_table", endpoint["scope"]):
        model.gap("route_collection_incomplete", "Route-table association inventory is missing, denied, or incomplete")
        return None
    subnet_id = endpoint["subnet"]["data"].get("SubnetId")
    explicit, main = [], []
    for table in model.kinds["route_table"]:
        if table["scope"] != endpoint["scope"] or table["data"].get("VpcId") != endpoint["vpc"]["data"].get("VpcId"):
            continue
        for association in table["data"].get("Associations", []):
            if association.get("AssociationState", {}).get("State", "associated") != "associated":
                continue
            if association.get("SubnetId") == subnet_id:
                explicit.append(table)
            if association.get("Main") is True:
                main.append(table)
    choices = explicit or main
    if len(choices) != 1:
        model.gap("route_association_missing", "Exactly one explicit subnet route table or proven VPC main table is required")
        return None
    return choices[0]


def _aws_route(model, endpoint, peer, direction):
    table = _aws_route_table(model, endpoint)
    if table is None or "Routes" not in table["data"]:
        return model.gap("route_rules_missing", "Associated native route entries are not available")
    choices = []
    for i, route in enumerate(table["data"]["Routes"]):
        prefix = route.get("DestinationCidrBlock", route.get("DestinationIpv6CidrBlock"))
        if route.get("DestinationPrefixListId"):
            return model.gap("route_prefix_list_unresolved", "Managed prefix-list route specificity is not resolved", [model.ref(table, f"Routes[{i}]")])
        match = _cidr(prefix, peer["address"])
        if match is None:
            return model.gap("route_rule_malformed", "A route prefix is missing or malformed", [model.ref(table, f"Routes[{i}]")])
        if match:
            choices.append((ipaddress.ip_network(prefix, strict=False).prefixlen, i, route))
    if not choices:
        return model.step("route", "blocked", "No route covers the selected private destination address", [model.ref(table, "Routes")], direction=direction)
    longest = max(c[0] for c in choices)
    choices = [c for c in choices if c[0] == longest]
    if len(choices) != 1:
        return model.gap("route_priority_ambiguous", "Equal-prefix route alternatives require native route-priority context", [model.ref(table, "Routes")])
    _, i, route = choices[0]
    refs = [model.ref(table, f"Routes[{i}]")]
    if route.get("State") == "blackhole":
        return model.step("route", "blocked", "The longest-prefix selected route is a blackhole", refs, direction=direction)
    if route.get("State") != "active":
        return model.gap("route_state_unknown", "The selected route is not proven active", refs)
    if route.get("GatewayId") == "local":
        if endpoint["vpc"] and peer["vpc"] and endpoint["vpc"]["id"] == peer["vpc"]["id"]:
            return model.step("route", "allowed", "Active longest-prefix local route remains inside the same scoped VPC", refs, direction=direction)
        return model.gap("address_domain_collision", "A local route cannot establish connectivity to another account/VPC with overlapping address space", refs)
    peering_id = route.get("VpcPeeringConnectionId")
    if peering_id:
        peers = [r for r in model.kinds["vpc_peering"] if r["data"].get("VpcPeeringConnectionId", r["native_id"]) == peering_id]
        compatible = []
        for peering in peers:
            info = [peering["data"].get("RequesterVpcInfo", {}), peering["data"].get("AccepterVpcInfo", {})]
            target_ids = {e["vpc"]["data"].get("VpcId") for e in (endpoint, peer) if e["vpc"]}
            if len(target_ids) == 2 and {x.get("VpcId") for x in info} == target_ids:
                owners = {e["vpc"]["data"].get("VpcId"): e["vpc"]["data"].get("OwnerId", e["vpc"]["data"].get("AccountId")) for e in (endpoint, peer) if e["vpc"]}
                if any(owners.get(x.get("VpcId")) is not None and str(owners[x["VpcId"]]) != str(x.get("OwnerId")) for x in info):
                    continue
                if endpoint["scope"] != peer["scope"] and any(owners.get(x.get("VpcId")) is None or not x.get("OwnerId") for x in info):
                    continue
                regions = {e["vpc"]["data"].get("VpcId"): e["resource"]["data"].get("Region", e["vpc"]["data"].get("Region", e["scope"].rsplit("/", 1)[-1])) for e in (endpoint, peer) if e["vpc"]}
                if any(x.get("Region") and x["Region"] != regions.get(x.get("VpcId")) for x in info):
                    continue
                if endpoint["scope"] != peer["scope"] and any(not x.get("Region") for x in info):
                    continue
                if not model.complete("vpc_peering", peering["scope"]):
                    continue
                compatible.append(peering)
        if not compatible:
            return model.gap("peering_facts_missing", "A route references peering without compatible scoped native endpoint facts", refs)
        statuses = {r["data"].get("Status", {}).get("Code") for r in compatible}
        refs += [model.ref(r, "Status/RequesterVpcInfo/AccepterVpcInfo") for r in compatible]
        if statuses != {"active"}:
            return model.step("route", "blocked" if len(statuses) == 1 and None not in statuses else "unknown",
                "The referenced peering is not consistently proven active", refs, direction=direction)
        return model.step("route", "allowed", "Active selected route and peering join these two native VPC domains", refs, direction=direction)
    component = next((key for key in ("NatGatewayId", "TransitGatewayId", "NetworkInterfaceId", "InstanceId", "GatewayId", "VpcEndpointId") if route.get(key)), "unknown_next_hop")
    model.result["translations"].append({"decision": "unknown", "component": component, "evidence_refs": refs})
    return model.gap("unsupported_route_component", "NAT, transit, Internet, VPN, endpoint, and appliance route transformations are not modeled", refs)


def _aws_acl(model, endpoint, other, egress, port, protocol, flow):
    if not endpoint["subnet"]:
        return model.gap("nacl_association_missing", "Subnet context is missing for the stateless NACL stage")
    if not model.complete("network_acl", endpoint["scope"]):
        return model.gap("nacl_collection_incomplete", "NACL association inventory is missing, denied, or incomplete")
    subnet_id = endpoint["subnet"]["data"].get("SubnetId")
    acls = [r for r in model.kinds["network_acl"] if r["scope"] == endpoint["scope"] and
        any(a.get("SubnetId") == subnet_id for a in r["data"].get("Associations", []))]
    if len(acls) != 1 or not isinstance(acls[0]["data"].get("Entries"), list):
        return model.gap("nacl_association_missing", "Exactly one associated native NACL with entries is required")
    acl = acls[0]
    if any(not isinstance(r.get("Egress"), bool) or ("CidrBlock" not in r and "Ipv6CidrBlock" not in r) for r in acl["data"]["Entries"]):
        return model.gap("nacl_rule_unresolved", "Native NACL direction or address-family matching data is missing", [model.ref(acl, "Entries")])
    rules = [(r.get("RuleNumber"), i, r) for i, r in enumerate(acl["data"]["Entries"]) if r.get("Egress") is egress
             and ("Ipv6CidrBlock" in r if other["address"].version == 6 else "CidrBlock" in r)]
    if any(isinstance(n, bool) or not isinstance(n, int) for n, _, _ in rules):
        return model.gap("nacl_order_malformed", "NACL order contains missing rule numbers", [model.ref(acl, "Entries")])
    if len({n for n, _, _ in rules}) != len(rules):
        return model.gap("nacl_order_ambiguous", "Duplicate NACL rule numbers prevent ordered matching", [model.ref(acl, "Entries")])
    for _, i, rule in sorted(rules):
        proto = _protocol(rule.get("Protocol"), protocol)
        network = rule.get("CidrBlock", rule.get("Ipv6CidrBlock"))
        ports = True if str(rule.get("Protocol")) == "-1" else _ports(
            f"{rule.get('PortRange', {}).get('From')}-{rule.get('PortRange', {}).get('To')}", port)
        matched = _all([proto, _cidr(network, other["address"]), ports])
        refs = [model.ref(acl, f"Entries[{i}]")]
        if matched is None:
            if port is None:
                return model.gap("source_port_required", "Stateless NACL return rules require the exact initiating source port", refs)
            return model.gap("nacl_rule_unresolved", "An earlier NACL rule cannot be definitively matched", refs)
        if matched:
            action = rule.get("RuleAction")
            if action not in {"allow", "deny"}:
                return model.gap("nacl_action_unknown", "Matching NACL action is not recognized", refs)
            return model.step("policy", "allowed" if action == "allow" else "blocked", "First ordered matching stateless NACL rule", refs,
                control="aws.network_acl", direction="egress" if egress else "ingress", flow=flow,
                pre_route=egress and flow == "forward")
    return model.step("policy", "blocked", "Native NACL implicit deny after no matching rule", [model.ref(acl, "Entries")],
        control="aws.network_acl", direction="egress" if egress else "ingress", flow=flow,
        pre_route=egress and flow == "forward")


def _aws(model, source, destination, query):
    endpoints = [_aws_endpoint(model, r, query["address_family"]) for r in (source, destination)]
    if not all(e and e["address"] for e in endpoints):
        return []
    src, dst = endpoints
    model.result["endpoints"] = _endpoint_details(src, dst)
    checks = [_aws_sg(model, src, dst, "egress", query), _aws_sg(model, dst, src, "ingress", query)]
    if src["vpc"] and dst["vpc"] and src["vpc"]["id"] != dst["vpc"]["id"]:
        ranges = [[ipaddress.ip_network(v, strict=False) for v in _aws_vpc_ranges(e["vpc"]["data"]) if _cidr(v, e["address"]) is not None] for e in (src, dst)]
        if any(a.version == b.version and a.overlaps(b) for a in ranges[0] for b in ranges[1]):
            checks.append(model.gap("overlapping_address_domains", "Cross-VPC overlap cannot be resolved into the selected resource path by address alone"))
    checks += [_aws_route(model, src, dst, "forward"), _aws_route(model, dst, src, "return")]
    if src["subnet"] and dst["subnet"] and src["subnet"]["id"] == dst["subnet"]["id"]:
        model.step("policy", "allowed", "NACLs do not filter traffic routed within the same subnet", [model.ref(src["subnet"], "SubnetId")], control="aws.network_acl")
    else:
        checks += [_aws_acl(model, src, dst, True, query["destination_port"], query["protocol"], "forward"),
            _aws_acl(model, dst, src, False, query["destination_port"], query["protocol"], "forward"),
            _aws_acl(model, dst, src, True, query["source_port"], query["protocol"], "return"),
            _aws_acl(model, src, dst, False, query["source_port"], query["protocol"], "return")]
    return checks


def _aws_vpc_ranges(data):
    return ([data["CidrBlock"]] if data.get("CidrBlock") else []) + [a["CidrBlock"] for a in data.get("CidrBlockAssociationSet", [])
        if a.get("CidrBlock") and a.get("CidrBlockState", {}).get("State", "associated") == "associated"] + [a["Ipv6CidrBlock"] for a in data.get("Ipv6CidrBlockAssociationSet", [])
        if a.get("Ipv6CidrBlock") and a.get("Ipv6CidrBlockState", {}).get("State", "associated") == "associated"]


def _endpoint_details(source, destination):
    return {key: {"resource_id": endpoint["selected"]["id"], "native_id": endpoint["selected"]["native_id"],
                  "scope": endpoint["scope"], "address": str(endpoint["address"]),
                  "interface_resource_id": endpoint["resource"]["id"]}
            for key, endpoint in (("source", source), ("destination", destination))}


def _azure_endpoint(model, resource, family):
    selected = resource
    if resource["type"] == "vm":
        interfaces = resource["data"].get("properties", {}).get("networkProfile", {}).get("networkInterfaces")
        if not isinstance(interfaces, list) or len(interfaces) != 1:
            model.gap("endpoint_interface_ambiguous", "Azure VM needs exactly one collected selected network interface", [model.ref(resource, "properties.networkProfile.networkInterfaces")])
            return None
        resource = model.find("nic", interfaces[0].get("id"))
        if resource is None:
            model.gap("interface_inventory_missing", "The declared VM NIC was not collected")
            return None
    elif resource["type"] != "nic":
        model.gap("unsupported_endpoint_type", "Azure selected endpoints must be a VM or NIC", [model.ref(resource, "data")])
        return None
    props = resource["data"].get("properties", {})
    configs = props.get("ipConfigurations")
    if not isinstance(configs, list):
        model.gap("endpoint_ip_configuration_missing", "Native NIC IP configurations are missing", [model.ref(resource, "properties.ipConfigurations")])
        return None
    address = _address(model, [c.get("properties", {}).get("privateIPAddress") for c in configs], family, resource)
    if address is None:
        return None
    matching = [c for c in configs if c.get("properties", {}).get("privateIPAddress") == str(address)]
    subnets = {c.get("properties", {}).get("subnet", {}).get("id") for c in matching}
    subnet = model.find("subnet", next(iter(subnets))) if len(subnets) == 1 else None
    vnet = model.find("vnet", subnet["native_id"].rsplit("/subnets/", 1)[0]) if subnet else None
    if subnet is None or vnet is None:
        model.gap("network_domain_missing", "NIC address needs exact native subnet/VNet identity, not a same-name network", [model.ref(resource, "properties.ipConfigurations")])
    else:
        prefixes = subnet["data"].get("properties", {}).get("addressPrefixes", [])
        prefix = subnet["data"].get("properties", {}).get("addressPrefix")
        if prefix:
            prefixes = prefixes + [prefix]
        if not any(_cidr(p, address) is True for p in prefixes):
            model.gap("endpoint_outside_subnet", "Private NIC address is not proven inside its selected native subnet", [model.ref(subnet, "properties.addressPrefix/addressPrefixes")])
    for dependency in (resource, subnet, vnet):
        if dependency and not model.complete(dependency["type"], dependency["scope"]):
            model.gap("endpoint_association_incomplete", "Native endpoint/subnet/VNet association collection is incomplete", [model.ref(dependency, "properties")])
    return {"resource": resource, "selected": selected, "address": address, "scope": resource["scope"], "subnet": subnet, "vnet": vnet}


def _azure_address_selector(model, value, address, endpoint):
    if value in {"*", "Any"}:
        return True
    direct = _cidr(value, address)
    if direct is not None:
        return direct
    if value == "VirtualNetwork" and endpoint["vnet"]:
        prefixes = endpoint["vnet"]["data"].get("properties", {}).get("addressSpace", {}).get("addressPrefixes", [])
        if any(_cidr(p, address) is True for p in prefixes):
            return True
    # Tags may contain BGP, peering, or dynamically maintained service ranges.
    # Never decide membership by a public/private-address naming heuristic.
    tags = [r for r in model.kinds["service_tag"] if r["data"].get("name") == value]
    if len(tags) == 1 and model.complete("service_tag", tags[0]["scope"]):
        prefixes = tags[0]["data"].get("properties", {}).get("addressPrefixes")
        if isinstance(prefixes, list):
            model.ref(tags[0], "properties.addressPrefixes")
            return _any(_cidr(p, address) for p in prefixes)
    return None


def _azure_defaults():
    def rule(name, direction, priority, source, destination, access):
        return {"name": name, "properties": {"direction": direction, "priority": priority,
            "sourceAddressPrefix": source, "destinationAddressPrefix": destination,
            "sourcePortRange": "*", "destinationPortRange": "*", "protocol": "*", "access": access}}
    return [rule("AllowVNetInBound", "Inbound", 65000, "VirtualNetwork", "VirtualNetwork", "Allow"),
        rule("AllowAzureLoadBalancerInBound", "Inbound", 65001, "AzureLoadBalancer", "*", "Allow"),
        rule("DenyAllInBound", "Inbound", 65500, "*", "*", "Deny"),
        rule("AllowVNetOutBound", "Outbound", 65000, "VirtualNetwork", "VirtualNetwork", "Allow"),
        rule("AllowInternetOutBound", "Outbound", 65001, "*", "Internet", "Allow"),
        rule("DenyAllOutBound", "Outbound", 65500, "*", "*", "Deny")]


def _azure_nsg(model, nsg, endpoint, source, destination, direction, query, admin_complete):
    if not model.complete("nsg", nsg["scope"]):
        return model.gap("nsg_rules_incomplete", "The attached NSG rule collection is unavailable or incomplete", [model.ref(nsg, "properties")])
    props = nsg["data"].get("properties", {})
    if not isinstance(props.get("securityRules"), list):
        return model.gap("nsg_rules_missing", "Custom NSG rules must be explicitly collected, including an empty list", [model.ref(nsg, "properties.securityRules")])
    rules = [(r.get("properties", {}).get("priority"), i, r, "securityRules") for i, r in enumerate(props["securityRules"])]
    defaults = props.get("defaultSecurityRules", _azure_defaults())
    rules += [(r.get("properties", {}).get("priority"), i, r, "defaultSecurityRules") for i, r in enumerate(defaults)]
    rules = [r for r in rules if r[2].get("properties", {}).get("direction") == direction]
    if any(isinstance(priority, bool) or not isinstance(priority, int) for priority, _, _, _ in rules) or len({r[0] for r in rules}) != len(rules):
        return model.gap("nsg_order_ambiguous", "NSG rules require unique native priorities per direction", [model.ref(nsg, "properties.securityRules")])
    if any(not (100 <= priority <= 4096 if origin == "securityRules" else 65000 <= priority <= 65535) for priority, _, _, origin in rules):
        return model.gap("nsg_order_malformed", "NSG custom/default priorities are outside their native supported ranges", [model.ref(nsg, "properties.securityRules/defaultSecurityRules")])
    for _, i, rule, origin in sorted(rules):
        p = rule["properties"]
        def addresses(singular, plural, address):
            if p.get(plural) and p.get(singular):
                return None
            values = p.get(plural) or ([p[singular]] if p.get(singular) else [])
            if p.get("sourceApplicationSecurityGroups") or p.get("destinationApplicationSecurityGroups"):
                return None
            return _any(_azure_address_selector(model, v, address, endpoint) for v in values) if values else None
        def ports(singular, plural, port):
            if p.get(plural) and p.get(singular):
                return None
            values = p.get(plural) or ([p[singular]] if p.get(singular) else [])
            # Azure augmented ranges can use commas; other native provider
            # port fields cannot silently acquire this syntax.
            return _any(_ports(part.strip(), port) for v in values for part in str(v).split(",")) if values else None
        matched = _all([_protocol(p.get("protocol"), query["protocol"]),
            addresses("sourceAddressPrefix", "sourceAddressPrefixes", source["address"]),
            addresses("destinationAddressPrefix", "destinationAddressPrefixes", destination["address"]),
            ports("sourcePortRange", "sourcePortRanges", query["source_port"]),
            ports("destinationPortRange", "destinationPortRanges", query["destination_port"])])
        refs = [model.ref(nsg, f"properties.{origin}[{i}]")]
        if matched is None:
            return model.gap("nsg_selector_unresolved", "An earlier NSG source port, service tag, ASG, or selector could change the ordered decision", refs)
        if matched:
            action = p.get("access")
            if action not in {"Allow", "Deny"}:
                return model.gap("nsg_action_unknown", "Native matching NSG action is unrecognized", refs)
            decision = "allowed" if action == "Allow" else "blocked"
            return model.step("policy", decision if admin_complete else "unknown",
                "First ordered matching NSG rule" if admin_complete else "NSG candidate cannot decide before missing overriding security-admin policy context",
                refs, control="azure.nsg", direction=direction, candidate_decision=decision,
                pre_route=direction == "Outbound",
                return_behavior="stateful: established response does not require a reverse NSG allow",
                **({"derived_default": True} if origin == "defaultSecurityRules" and "defaultSecurityRules" not in props else {}))
    return model.gap("nsg_default_rules_unresolved", "No native/default NSG decision is proven", [model.ref(nsg, "properties")])


def _azure_policy(model, endpoint, source, destination, direction, query, admin_complete):
    holders = [endpoint["resource"], endpoint["subnet"]] if direction == "Outbound" else [endpoint["subnet"], endpoint["resource"]]
    decisions = []
    for holder in holders:
        if holder is None or not model.complete(holder["type"], holder["scope"]):
            decisions.append(model.gap("nsg_association_incomplete", "Both NIC and subnet NSG association states must be collected"))
            continue
        reference = holder["data"].get("properties", {}).get("networkSecurityGroup")
        if reference is None:
            decisions.append(model.step("policy", "allowed" if admin_complete else "unknown",
                "Native NIC/subnet has no attached NSG; higher policy context is assessed separately", [model.ref(holder, "properties.networkSecurityGroup")],
                control="azure.nsg", direction=direction))
            continue
        nsg = model.find("nsg", reference.get("id"))
        if nsg is None:
            decisions.append(model.gap("nsg_inventory_missing", "A declared NSG was not collected", [model.ref(holder, "properties.networkSecurityGroup")]))
        else:
            decisions.append(_azure_nsg(model, nsg, endpoint, source, destination, direction, query, admin_complete))
    return decisions


def _azure_route(model, endpoint, peer, direction):
    if not endpoint["subnet"] or not endpoint["vnet"] or not peer["vnet"]:
        return model.gap("route_domain_missing", "Native Azure subnet/VNet context is missing")
    if not model.context_complete("routing") or model.context("routing").get("bgp") != "none":
        return model.gap("azure_route_context_missing", "User routes do not establish effective routing without complete system/BGP context")
    same = endpoint["vnet"]["id"] == peer["vnet"]["id"]
    custom = []
    table_ref = endpoint["subnet"]["data"].get("properties", {}).get("routeTable")
    if table_ref:
        table = model.find("route_table", table_ref.get("id"))
        if table is None or not model.complete("route_table", table["scope"]) or not isinstance(table["data"].get("properties", {}).get("routes"), list):
            return model.gap("route_table_incomplete", "The explicitly associated Azure route table is missing or incomplete", [model.ref(endpoint["subnet"], "properties.routeTable")])
        for i, r in enumerate(table["data"]["properties"]["routes"]):
            p = r.get("properties", {})
            match = _cidr(p.get("addressPrefix"), peer["address"])
            if match is None:
                return model.gap("route_selector_unresolved", "Azure UDR address tags/prefixes are not resolved", [model.ref(table, f"properties.routes[{i}]")])
            if match:
                custom.append((ipaddress.ip_network(p["addressPrefix"], strict=False).prefixlen, p.get("nextHopType"), model.ref(table, f"properties.routes[{i}]")))
    system = []
    if same:
        for prefix in endpoint["vnet"]["data"].get("properties", {}).get("addressSpace", {}).get("addressPrefixes", []):
            if _cidr(prefix, peer["address"]) is True:
                system.append((ipaddress.ip_network(prefix, strict=False).prefixlen, "VnetLocal", model.ref(endpoint["vnet"], "properties.addressSpace.addressPrefixes")))
    else:
        peerings = [r for r in model.kinds["vnet_peering"] if r["data"].get("properties", {}).get("remoteVirtualNetwork", {}).get("id", "").lower() == peer["vnet"]["native_id"].lower()
            and r["native_id"].lower().startswith(endpoint["vnet"]["native_id"].lower() + "/virtualnetworkpeerings/")]
        if len(peerings) == 1:
            if not model.complete("vnet_peering", peerings[0]["scope"]):
                return model.gap("peering_collection_incomplete", "Native peering collection is unavailable or partial", [model.ref(peerings[0], "properties")])
            p = peerings[0]["data"].get("properties", {})
            refs = model.ref(peerings[0], "properties")
            if p.get("peeringState") != "Connected" or p.get("allowVirtualNetworkAccess") is not True:
                return model.gap("peering_context_missing", "Declared peering is disconnected or access-disabled; unsupported alternate gateway/appliance routes are not ruled out", [refs])
            if p.get("peeringSyncLevel", "FullyInSync") != "FullyInSync":
                return model.gap("peering_context_missing", "Peering address-space synchronization is not complete", [refs])
            prefixes = p.get("remoteAddressSpace", {}).get("addressPrefixes", peer["vnet"]["data"].get("properties", {}).get("addressSpace", {}).get("addressPrefixes", []))
            for prefix in prefixes:
                if _cidr(prefix, peer["address"]) is True:
                    system.append((ipaddress.ip_network(prefix, strict=False).prefixlen, "VnetPeering", refs))
        else:
            return model.gap("peering_context_missing", "Cross-VNet routing requires native connected access-enabled peering in each direction")
    choices = [(prefix, 1, hop, ref) for prefix, hop, ref in custom] + [(prefix, 0, hop, ref) for prefix, hop, ref in system]
    if not choices:
        return model.gap("route_not_proven", "No supported local/peered system route reaches the selected private endpoint")
    best = max((c[0], c[1]) for c in choices)
    choices = [c for c in choices if c[:2] == best]
    if len(choices) != 1:
        return model.gap("route_priority_ambiguous", "Azure equal-prefix route alternatives need effective-route evidence")
    _, _, hop, ref = choices[0]
    if hop == "None":
        return model.step("route", "blocked", "Selected longest-prefix UDR has the None drop next hop", [ref], direction=direction)
    if hop in {"VnetLocal", "VnetPeering"}:
        return model.step("route", "allowed", "Selected native/system private-network route", [ref], direction=direction, next_hop=hop)
    model.result["translations"].append({"decision": "unknown", "component": hop, "evidence_refs": [ref]})
    return model.gap("unsupported_route_component", "Azure Internet, NAT, VPN gateway, and virtual-appliance routing are not modeled", [ref])


def _azure(model, source, destination, query):
    endpoints = [_azure_endpoint(model, r, query["address_family"]) for r in (source, destination)]
    if not all(e and e["address"] for e in endpoints):
        return []
    src, dst = endpoints
    model.result["endpoints"] = _endpoint_details(src, dst)
    admin = model.context_complete("security_admin") and model.context("security_admin").get("policies") == []
    if not admin:
        model.gap("azure_security_admin_context_missing", "Higher-priority security-admin AlwaysAllow/Deny policies can bypass NSGs; absence is not assumed")
    checks = _azure_policy(model, src, src, dst, "Outbound", query, admin) + _azure_policy(model, dst, src, dst, "Inbound", query, admin)
    if src["vnet"] and dst["vnet"] and src["vnet"]["id"] != dst["vnet"]["id"]:
        a = src["vnet"]["data"].get("properties", {}).get("addressSpace", {}).get("addressPrefixes", [])
        b = dst["vnet"]["data"].get("properties", {}).get("addressSpace", {}).get("addressPrefixes", [])
        if any(ipaddress.ip_network(x, strict=False).version == ipaddress.ip_network(y, strict=False).version and
               ipaddress.ip_network(x, strict=False).overlaps(ipaddress.ip_network(y, strict=False)) for x in a for y in b):
            checks.append(model.gap("overlapping_address_domains", "Peering does not establish an unambiguous path across overlapping VNet address domains"))
    checks += [_azure_route(model, src, dst, "forward"), _azure_route(model, dst, src, "return")]
    return checks


def _gcp_endpoint(model, resource, family):
    if resource["type"] != "instance":
        model.gap("unsupported_endpoint_type", "GCP selected endpoints must be collected VM instances", [model.ref(resource, "data")])
        return None
    interfaces = resource["data"].get("networkInterfaces")
    if not isinstance(interfaces, list) or len(interfaces) != 1:
        model.gap("endpoint_interface_ambiguous", "A selected VM needs exactly one native network interface for this endpoint model", [model.ref(resource, "networkInterfaces")])
        return None
    interface = interfaces[0]
    if family == "ipv6" and interface.get("ipv6AccessType") != "INTERNAL":
        model.gap("unsupported_external_ipv6", "GCP IPv6 modeling requires an observed internal IPv6 interface; external addressing is not a private-route assumption", [model.ref(resource, "networkInterfaces[0].ipv6AccessType")])
        return None
    address = _address(model, [interface.get("networkIP"), interface.get("ipv6Address")], family, resource)
    network = model.find("network", interface.get("network"))
    subnet = model.find("subnetwork", interface.get("subnetwork"))
    if network is None or subnet is None:
        model.gap("network_domain_missing", "Full host-project global network and regional subnetwork facts must be collected", [model.ref(resource, "networkInterfaces[0]")])
    elif _gcp_id(subnet["data"].get("network", "")) != _gcp_id(interface.get("network", "")):
        model.gap("network_domain_mismatch", "Interface and subnet network references disagree", [model.ref(subnet, "network")])
        subnet = None
    if address and subnet:
        prefixes = [subnet["data"].get("ipCidrRange"), subnet["data"].get("internalIpv6Prefix")]
        if not any(_cidr(p, address) is True for p in prefixes if p):
            model.gap("endpoint_outside_subnet", "The selected primary address is not proven inside its native subnet family", [model.ref(subnet, "ipCidrRange/internalIpv6Prefix")])
    for dependency in (resource, network, subnet):
        if dependency and not model.complete(dependency["type"], dependency["scope"]):
            model.gap("endpoint_association_incomplete", "VM/global-network/subnetwork collection visibility is incomplete", [model.ref(dependency, "data")])
    return {"resource": resource, "selected": resource, "address": address, "scope": resource["scope"],
            "network": network, "subnet": subnet, "interface": interface,
            "tags": resource["data"].get("tags", {}).get("items", []),
            "service_accounts": [s.get("email") for s in resource["data"].get("serviceAccounts", [])]}


def _gcp_sa_match(model, values, endpoint):
    matched = set(values).intersection(endpoint["service_accounts"])
    if not matched:
        return False
    network_project = _gcp_network_id(endpoint["network"]).split("/")[1]
    vm_project = endpoint["scope"].split("/")[-1]
    # Native shared-VPC interface evidence establishes the selected VM's service
    # project. Arbitrary third-project service-account criteria stay unresolved.
    for email in matched:
        if email and "@" in email and email.endswith(".iam.gserviceaccount.com"):
            project = email.split("@", 1)[1].removesuffix(".iam.gserviceaccount.com")
            if project in {network_project, vm_project}:
                return True
    return None


def _gcp_rule_match(model, rule, endpoint, peer, direction, query):
    if rule.get("disabled") is True or rule.get("direction", "INGRESS") != direction:
        return False
    if _gcp_id(rule.get("network", "")) != _gcp_network_id(endpoint["network"]):
        return False
    if (rule.get("targetTags") and rule.get("targetServiceAccounts")) or (rule.get("sourceTags") and rule.get("sourceServiceAccounts")) or (rule.get("targetTags") and rule.get("sourceServiceAccounts")) or (rule.get("targetServiceAccounts") and rule.get("sourceTags")):
        return None
    target = bool(set(rule["targetTags"]).intersection(endpoint["tags"])) if rule.get("targetTags") else _gcp_sa_match(model, rule["targetServiceAccounts"], endpoint) if rule.get("targetServiceAccounts") else True
    actions = rule.get("denied", rule.get("allowed"))
    if not isinstance(actions, list) or ("allowed" in rule and "denied" in rule):
        return None
    ports = _any(_all([_protocol(a.get("IPProtocol"), query["protocol"]),
        _any(_ports(p, query["destination_port"]) for p in a["ports"]) if a.get("ports") else True]) for a in actions)
    if direction == "INGRESS":
        source = []
        if "sourceRanges" in rule:
            source += [_cidr(p, peer["address"]) for p in rule["sourceRanges"]]
        same_network = peer["network"] and peer["network"]["id"] == endpoint["network"]["id"]
        if rule.get("sourceTags"):
            source.append(same_network and bool(set(rule["sourceTags"]).intersection(peer["tags"])))
        if rule.get("sourceServiceAccounts"):
            source.append(_gcp_sa_match(model, rule["sourceServiceAccounts"], peer) if same_network else False)
        if not any(k in rule for k in ("sourceRanges", "sourceTags", "sourceServiceAccounts")):
            source = [_cidr("0.0.0.0/0", peer["address"])]
        destination = _any(_cidr(p, endpoint["address"]) for p in rule["destinationRanges"]) if "destinationRanges" in rule else True
        return _all([target, ports, _any(source), destination])
    destination = _any(_cidr(p, peer["address"]) for p in rule.get("destinationRanges", ["0.0.0.0/0"]))
    source = _any(_cidr(p, endpoint["address"]) for p in rule["sourceRanges"]) if "sourceRanges" in rule else True
    return _all([target, ports, source, destination])


def _gcp_firewall(model, endpoint, peer, direction, query, hierarchy_complete):
    owner_scope = _gcp_owner_scope(model, "firewall", endpoint["network"]) if endpoint["network"] else None
    if owner_scope is None or not model.complete("firewall", owner_scope):
        return model.gap("firewall_collection_incomplete", "Host-project network firewall collection is missing, denied, or partial")
    candidates = []
    for resource in model.kinds["firewall"]:
        if resource["scope"] != owner_scope:
            continue
        rule = resource["data"]
        match = _gcp_rule_match(model, rule, endpoint, peer, direction, query)
        if match is False:
            continue
        priority = rule.get("priority", 1000)
        if isinstance(priority, bool) or not isinstance(priority, int) or not 0 <= priority <= 65535:
            return model.gap("firewall_order_malformed", "A potentially matching firewall priority is invalid", [model.ref(resource, "priority")])
        action = "blocked" if "denied" in rule else "allowed"
        candidates.append((priority, resource, match, action))
    for priority in sorted({c[0] for c in candidates}):
        peers = [c for c in candidates if c[0] == priority]
        denied = [c for c in peers if c[2] is True and c[3] == "blocked"]
        allowed = [c for c in peers if c[2] is True and c[3] == "allowed"]
        uncertain = [c for c in peers if c[2] is None]
        refs = [model.ref(c[1], "data") for c in peers]
        decision = "blocked" if denied else "allowed" if allowed and not any(c[3] == "blocked" for c in uncertain) else None
        if decision is None:
            return model.gap("firewall_selector_unresolved", "A higher/equal-priority tag, service-account, or rule selector could alter the ordered result", refs)
        return model.step("policy", decision if hierarchy_complete else "unknown",
            "Highest-priority matching VPC firewall rule; deny wins an equal-priority tie" if hierarchy_complete else
            "VPC firewall candidate cannot decide before missing hierarchy/network-firewall policy context", refs,
            control="gcp.firewall", direction=direction, priority=priority, candidate_decision=decision,
            pre_route=direction == "EGRESS",
            return_behavior="stateful: matching response traffic does not require reverse firewall allowance")
    decision = "blocked" if direction == "INGRESS" else "allowed"
    return model.step("policy", decision if hierarchy_complete else "unknown", "Native implied ingress deny / egress allow after complete VPC rule evaluation",
        [model.ref(endpoint["network"], "network")], control="gcp.firewall", direction=direction, candidate_decision=decision, implied_default=True,
        pre_route=direction == "EGRESS")


def _gcp_route(model, endpoint, peer, direction):
    if not endpoint["network"] or not peer["network"] or not endpoint["subnet"] or not peer["subnet"]:
        return model.gap("route_domain_missing", "Native host-project network/subnet context is missing")
    context = model.context("routing")
    if not model.context_complete("routing") or context.get("policy_based_routes") != "none" or context.get("dynamic_routes") != "none":
        return model.gap("gcp_route_context_missing", "Policy-based, dynamic, and special routing context must be collected before a subnet path is modeled")
    route_scope = _gcp_owner_scope(model, "route", endpoint["network"])
    if route_scope is None or not model.complete("route", route_scope):
        return model.gap("route_collection_incomplete", "Native selected-network route visibility is incomplete")
    if peer["subnet"]["data"].get("purpose", "PRIVATE") != "PRIVATE":
        return model.gap("unsupported_subnet_purpose", "Proxy, hybrid, private-service-connect, and special-purpose subnet routing is not modeled", [model.ref(peer["subnet"], "purpose")])
    if endpoint["network"]["id"] == peer["network"]["id"]:
        return model.step("route", "allowed", "Native regular subnet route within one global host-project VPC takes precedence over custom static routes",
            [model.ref(peer["subnet"], "ipCidrRange/internalIpv6Prefix"), model.ref(endpoint["network"], "selfLink")], direction=direction)
    peers = [p for p in endpoint["network"]["data"].get("peerings", []) if _gcp_id(p.get("network", "")) == _gcp_network_id(peer["network"])]
    if len(peers) != 1:
        return model.gap("peering_context_missing", "Cross-network subnet routing needs native peering to the exact host-project network in each direction")
    peering = peers[0]
    refs = [model.ref(endpoint["network"], "peerings")]
    if peering.get("state") != "ACTIVE":
        return model.gap("peering_context_missing", "Native peering is not proven active; unsupported static next-hop alternatives are not modeled", refs)
    if peer["address"].version == 6 and peering.get("stackType") != "IPV4_IPV6":
        return model.gap("peering_ipv6_context_missing", "Peering does not prove IPv6 subnet route exchange", refs)
    if peer["subnet"]["data"].get("ipCidrRange") and endpoint["subnet"]["data"].get("ipCidrRange"):
        if ipaddress.ip_network(peer["subnet"]["data"]["ipCidrRange"]).overlaps(ipaddress.ip_network(endpoint["subnet"]["data"]["ipCidrRange"])):
            return model.gap("overlapping_address_domains", "Overlapping cross-project subnet domains cannot establish the selected peer resource path", refs)
    return model.step("route", "allowed", "Active native peering exchanges the selected regular private subnet route", refs, direction=direction)


def _gcp(model, source, destination, query):
    endpoints = [_gcp_endpoint(model, r, query["address_family"]) for r in (source, destination)]
    if not all(e and e["address"] for e in endpoints):
        return []
    src, dst = endpoints
    model.result["endpoints"] = _endpoint_details(src, dst)
    hierarchy = model.context_complete("firewall_hierarchy") and model.context("firewall_hierarchy").get("policies") == []
    if not hierarchy:
        model.gap("gcp_firewall_hierarchy_missing", "Hierarchical/global/regional firewall policy precedence or absence is not verified")
    checks = [_gcp_firewall(model, src, dst, "EGRESS", query, hierarchy), _gcp_firewall(model, dst, src, "INGRESS", query, hierarchy)]
    checks += [_gcp_route(model, src, dst, "forward"), _gcp_route(model, dst, src, "return")]
    return checks


def _selector(selector, labels):
    if not isinstance(selector, dict):
        return None
    if set(selector) - {"matchLabels", "matchExpressions"}:
        return None
    if not selector.get("matchLabels") and not selector.get("matchExpressions"):
        return True
    if not isinstance(labels, dict):
        return None
    decisions = []
    if not isinstance(selector.get("matchLabels", {}), dict) or not isinstance(selector.get("matchExpressions", []), list):
        return None
    decisions += [labels.get(key) == value for key, value in selector.get("matchLabels", {}).items()]
    for expression in selector.get("matchExpressions", []):
        key, operation, values = expression.get("key"), expression.get("operator"), expression.get("values", [])
        if not isinstance(key, str) or not isinstance(values, list):
            decisions.append(None)
        elif operation == "In":
            decisions.append(key in labels and labels[key] in values if values else None)
        elif operation == "NotIn":
            decisions.append(key not in labels or labels[key] not in values if values else None)
        elif operation == "Exists":
            decisions.append(key in labels if not values else None)
        elif operation == "DoesNotExist":
            decisions.append(key not in labels if not values else None)
        else:
            decisions.append(None)
    return _all(decisions)


def _k8s_endpoint(model, resource, family):
    if resource["type"] != "pod":
        model.gap("unsupported_endpoint_type", "Kubernetes selected endpoints must be direct pods; Service/LB address translations are not inferred", [model.ref(resource, "data")])
        return None
    data = resource["data"]
    if data.get("spec", {}).get("hostNetwork") is True:
        model.gap("host_network_semantics_unknown", "Host-network pod policy and node-source exceptions depend on the enforcing CNI", [model.ref(resource, "spec.hostNetwork")])
        return None
    status = data.get("status", {})
    address = _address(model, [status.get("podIP")] + [p.get("ip") for p in status.get("podIPs", [])], family, resource)
    namespace = data.get("metadata", {}).get("namespace")
    cluster = model.snapshot.get("metadata", {}).get("cluster_id")
    observed_cluster = data.get("provenance", {}).get("cluster_id", cluster)
    if not cluster or observed_cluster != cluster or not namespace:
        model.gap("cluster_namespace_context_missing", "Native cluster identity and namespace must be explicit; namespace is not a subnet", [model.ref(resource, "metadata.namespace/provenance.cluster_id")])
    namespace_resources = [r for r in model.kinds["namespace"] if r["data"].get("metadata", {}).get("name") == namespace]
    namespace_resource = namespace_resources[0] if len(namespace_resources) == 1 else None
    return {"resource": resource, "selected": resource, "address": address, "scope": resource["scope"],
        "namespace": namespace, "cluster": cluster, "namespace_resource": namespace_resource,
        "labels": data.get("metadata", {}).get("labels", {})}


def _k8s_peer(model, policy_namespace, peer, other):
    if not isinstance(peer, dict) or set(peer) - {"podSelector", "namespaceSelector", "ipBlock"}:
        return None
    if not peer:
        return True
    if "ipBlock" in peer:
        if len(peer) != 1:
            return None
        block = peer["ipBlock"]
        if model.context("cni").get("ipblock_semantics") != "pod_ips_preserved":
            return None
        base = _cidr(block.get("cidr"), other["address"])
        excluded = _any(_cidr(cidr, other["address"]) for cidr in block.get("except", []))
        return _all([base, None if excluded is None else not excluded])
    namespace = other["namespace_resource"]
    labels = namespace["data"].get("metadata", {}).get("labels", {}) if namespace and model.complete("namespace", namespace["scope"]) else None
    matches = [_selector(peer["namespaceSelector"], labels)] if "namespaceSelector" in peer else [other["namespace"] == policy_namespace]
    if "podSelector" in peer:
        matches.append(_selector(peer["podSelector"], other["labels"]))
    if namespace:
        model.ref(namespace, "metadata.labels")
    return _all(matches)


def _k8s_ports(model, rule, destination, query):
    ports = rule.get("ports")
    if not ports:
        return True
    matches = []
    for port in ports:
        proto = _protocol(port.get("protocol", "TCP"), query["protocol"])
        value = port.get("port")
        if value is None:
            matches.append(proto)
        elif isinstance(value, int) and not isinstance(value, bool):
            end = port.get("endPort", value)
            if end != value and query["destination_port"] != value and model.context("cni").get("supports_end_port") is not True:
                match = False if model.context("cni").get("supports_end_port") is False else None
            else:
                match = _ports(f"{value}-{end}", query["destination_port"])
            matches.append(_all([proto, match]))
        elif isinstance(value, str) and "endPort" not in port:
            spec = destination["resource"]["data"].get("spec", {})
            containers = spec.get("containers", []) + spec.get("initContainers", []) + spec.get("ephemeralContainers", [])
            defined = {p.get("containerPort") for container in containers for p in container.get("ports", [])
                if p.get("name") == value and str(p.get("protocol", "TCP")).lower() == query["protocol"]}
            match = query["destination_port"] in defined if len(defined) <= 1 else None
            matches.append(_all([proto, match]))
            model.ref(destination["resource"], "spec.containers[*].ports")
        else:
            matches.append(None)
    return _any(matches)


def _k8s_policy(model, endpoint, other, destination, direction, query, enforced):
    if not model.complete("networkpolicy", endpoint["scope"]):
        return model.gap("network_policy_collection_incomplete", "Additive policy union needs complete policy inventory for the selected namespace scope")
    selectors_unknown, selected = [], []
    for policy in model.kinds["networkpolicy"]:
        data = policy["data"]
        if data.get("metadata", {}).get("namespace") != endpoint["namespace"]:
            continue
        spec = data.get("spec", {})
        types = spec.get("policyTypes", ["Ingress"] + (["Egress"] if "egress" in spec else []))
        if direction not in types:
            continue
        match = _selector(spec.get("podSelector"), endpoint["labels"])
        if match is None:
            selectors_unknown.append(policy)
        elif match:
            selected.append(policy)
    key, peers_key = ("ingress", "from") if direction == "Ingress" else ("egress", "to")
    allow_refs, uncertain, selected_refs = [], bool(selectors_unknown), []
    for policy in selected:
        selected_refs.append(model.ref(policy, "spec.podSelector/policyTypes"))
        for i, rule in enumerate(policy["data"]["spec"].get(key, [])):
            if not isinstance(rule, dict):
                uncertain = True
                continue
            peers = rule.get(peers_key)
            peer_match = _any(_k8s_peer(model, endpoint["namespace"], peer, other) for peer in peers) if peers else True
            port_match = _k8s_ports(model, rule, destination, query)
            match = _all([peer_match, port_match])
            if match:
                allow_refs.append(model.ref(policy, f"spec.{key}[{i}]"))
            elif match is None:
                uncertain = True
    if source_same := endpoint["resource"]["id"] == other["resource"]["id"]:
        decision, reason = "allowed", "A standard pod policy cannot block the pod's own loopback traffic"
    elif allow_refs:
        decision, reason = "allowed", "An allow in the additive union admits this flow; another standard policy cannot subtract it"
    elif uncertain:
        return model.gap("network_policy_selector_unresolved", "Namespace labels, CNI IP-block/port behavior, or a policy selector could alter the additive union",
            selected_refs + [model.ref(p, "spec") for p in selectors_unknown])
    elif not selected:
        decision, reason = "allowed", "No standard NetworkPolicy isolates this pod in this direction after complete enumeration"
    else:
        decision, reason = "blocked", "The complete additive policy union isolates this direction and contains no matching allow"
    return model.step("policy", decision if enforced else "unknown", reason if enforced else "Policy intent is modeled but enforcing CNI evidence is missing",
        allow_refs or selected_refs or [model.ref(endpoint["resource"], "metadata.namespace/labels")],
        control="k8s.networkpolicy", direction=direction, candidate_decision=decision,
        pre_route=direction == "Egress",
        return_behavior="Responses to admitted TCP/UDP connections are implicitly admitted", self_traffic=source_same)


def _k8s(model, source, destination, query):
    endpoints = [_k8s_endpoint(model, r, query["address_family"]) for r in (source, destination)]
    if not all(e and e["address"] for e in endpoints):
        return []
    src, dst = endpoints
    model.result["endpoints"] = _endpoint_details(src, dst)
    cni = model.context("cni")
    enforced = cni.get("status") == "collected" and cni.get("enforces_network_policy") is True and isinstance(cni.get("source_evidence"), list) and bool(cni["source_evidence"]) and all(isinstance(e, dict) for e in cni["source_evidence"])
    if not enforced:
        model.gap("cni_enforcement_unknown", "NetworkPolicy objects alone do not establish an enforcing CNI")
    custom = [c for c in model.snapshot["collections"] if c["type"] in {"cilium_networkpolicy", "calico_networkpolicy"} and c["status"] != "empty"]
    if custom:
        enforced = False
        model.gap("cni_custom_policy_context_unknown", "Observed or unavailable nonstandard CNI policy collections can change the standard additive union")
    if src["cluster"] != dst["cluster"]:
        return [model.gap("cluster_domain_mismatch", "Native pod IPs from distinct cluster address domains cannot be joined by namespace or CIDR")]
    routing = model.context_complete("routing") and model.context("routing").get("pod_network_connected") is True
    if not routing:
        model.gap("pod_routing_context_missing", "Direct pod network routing is not proven by namespace/policy inventory")
    checks = [_k8s_policy(model, src, dst, dst, "Egress", query, enforced),
              _k8s_policy(model, dst, src, dst, "Ingress", query, enforced)]
    checks.append(model.step("route", "allowed" if routing else "unknown", "Observed enforcing pod-network routing context" if routing else "No route proof for direct pod-network traffic",
        [model.ref(src["resource"], "status.podIPs"), model.ref(dst["resource"], "status.podIPs")], direction="forward_and_return"))
    return checks


def evaluate_reachability(snapshot, source_resource_id, destination_resource_id, protocol,
                          destination_port, source_port=None, address_family="ipv4"):
    """Evaluate one new selected private TCP/UDP flow, offline and bounded by facts."""
    if not isinstance(source_resource_id, str) or not isinstance(destination_resource_id, str):
        raise ValueError("source and destination resource IDs must be strings")
    protocol = protocol.lower() if isinstance(protocol, str) else ""
    if protocol not in {"tcp", "udp"}:
        raise ValueError("only tcp and udp new-flow modeling is supported")
    for name, value in (("destination_port", destination_port), ("source_port", source_port)):
        if name == "source_port" and value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
            raise ValueError(f"{name} must be an integer from 1 to 65535")
    if address_family not in {"ipv4", "ipv6"}:
        raise ValueError("address_family must be ipv4 or ipv6")
    snapshot = validate(snapshot)
    query = {"source_resource_id": source_resource_id, "destination_resource_id": destination_resource_id,
             "protocol": protocol, "destination_port": destination_port, "source_port": source_port,
             "address_family": address_family}
    model = _Model(snapshot, query)
    source, destination = model.by_id.get(source_resource_id), model.by_id.get(destination_resource_id)
    if source is None or destination is None:
        model.gap("endpoint_inventory_missing", "Both selected globally scoped IDs must exist in this immutable network inventory")
        return model.result
    try:
        evaluators = {"aws": _aws, "azure": _azure, "gcp": _gcp, "k8s": _k8s}
        evaluator = evaluators.get(model.provider)
        checks = evaluator(model, source, destination, query) if evaluator else [model.gap("provider_model_pending", "Provider selected-flow model is not yet available")]
        endpoints = model.result["endpoints"]
        if source_resource_id != destination_resource_id and endpoints.get("source", {}).get("address") == endpoints.get("destination", {}).get("address") and endpoints.get("source"):
            model.gap("endpoint_address_collision", "Distinct selected resources share an address; overlapping scoped identities must not be merged")
        critical = {"network_domain_missing", "network_domain_mismatch", "endpoint_outside_subnet", "endpoint_association_incomplete",
                    "endpoint_address_collision", "overlapping_address_domains", "cluster_namespace_context_missing", "cluster_domain_mismatch"}
        domain_valid = not any(g["code"] in critical for g in model.result["unresolved_dependencies"])
        forward = [r for r in model.result["routes"] if r.get("direction") in {"forward", "forward_and_return"}]
        direct = bool(forward) and all(r["decision"] == "allowed" for r in forward)
        decisive = domain_valid and (any(r["decision"] == "blocked" and r.get("direction") == "forward" for r in model.result["routes"]) or
            any(p["decision"] == "blocked" and (direct or p.get("pre_route") or p.get("address_translation_invariant")) for p in model.result["policy_decisions"]) or
            direct and any(r["decision"] == "blocked" for r in model.result["routes"]))
        if "blocked" in checks and not decisive:
            model.gap("blocked_candidate_not_proven", "A downstream denial cannot be decisive before its scoped path/translation assumptions are proven")
        model.result["decision"] = "blocked" if decisive else "unknown" if not checks or any(c != "allowed" for c in checks) or model.result["unresolved_dependencies"] else "allowed"
    except (TypeError, ValueError, KeyError, AttributeError, IndexError):
        model.gap("malformed_native_facts", "Malformed native relationships or rules cannot establish a selected configuration path")
        model.result["decision"] = "unknown"
    return model.result
