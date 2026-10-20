"""Unregistered exact inline-WAF successor proposal for the existing edge ID.

Frozen predecessor remains unchanged; root alone admits this reviewed delta.
"""
from ._bulk_pending_compliance_new_sw22 import (_subscription,_by_id,_inventory,_EDGE_TYPES,
    _full,_arm,_text,_coverage,_waf)
from .facts import get,list_of_objects,omitted,Unavailable
from . import result

CHECK='azure_application_gateway_11_5_1_1_1_f56bdc2'

def evaluate(item, index):
    _, scope = _subscription(index)
    inventories = {kind: _by_id(_inventory(index, kind), scope, resource_type)
                   for kind, resource_type in _EDGE_TYPES.items()}
    all_resources = {rid: (kind, row) for kind, rows in inventories.items() for rid, row in rows.items()}
    bindings = {}
    for row in _inventory(index, "public_edge_binding"):
        _full(row, "Azure.publicEdgeProtection:resolve")
        rid = _arm(get(row, "resource_id", str), scope)
        if rid not in all_resources or rid in bindings or get(row, "resource_kind", str) != all_resources[rid][0]:
            raise Unavailable("edge binding identity unresolved")
        if get(row, "resource_etag", str) != _text(all_resources[rid][1], "etag"):
            raise Unavailable("edge binding refers to a different resource version")
        bindings[rid] = row
    if set(bindings) != set(all_resources):
        raise Unavailable("complete public frontend and effective protection resolution required")
    public, failed = [], []
    vn = None
    plans = None
    waf = None
    for rid, (kind, resource) in all_resources.items():
        binding = bindings[rid]
        is_public = get(binding, "public", bool)
        _coverage(binding, "frontends", rid)
        frontends = get(binding, "public_frontend_ids", list)
        if any(not isinstance(value, str) for value in frontends) or len(frontends) != len({value.casefold() for value in frontends}):
            raise Unavailable("malformed public frontend bindings")
        if (get(binding, "_coverage.frontends.status", str) == "empty") != (not frontends):
            raise Unavailable("public frontend coverage contradicts its inventory")
        if kind == "public_ip":
            if not is_public or frontends != [get(resource, "id", str)]:
                raise Unavailable("Public IP applicability incorrectly resolved")
        elif kind in {"application_gateway", "load_balancer"}:
            _full(resource)
            actual, seen_frontends = [], set()
            for frontend in list_of_objects(get(resource, "properties.frontendIPConfigurations", list)):
                fid = _arm(get(frontend, "id", str), scope)
                prefix = rid + "/frontendipconfigurations/"
                if (not fid.startswith(prefix) or "/" in fid[len(prefix):]
                        or fid in seen_frontends):
                    raise Unavailable("foreign public frontend identity")
                seen_frontends.add(fid)
                props = get(frontend, "properties", dict)
                ref = omitted({**props, "_provenance": resource["_provenance"]}, "publicIPAddress", None)
                if ref is not None:
                    ip_id = _arm(get(ref, "id", str), scope, _EDGE_TYPES["public_ip"])
                    if ip_id not in inventories["public_ip"]:
                        raise Unavailable("public frontend IP join unresolved")
                    actual.append(fid)
            if {value.casefold() for value in frontends} != set(actual) or is_public != bool(actual):
                raise Unavailable("public frontend evidence conflicts with native resource")
        else:
            _full(resource)
            if kind == "frontdoor":
                endpoints = list_of_objects(get(resource, "properties.frontendEndpoints", list))
                child_type = "/frontendendpoints/"
            else:
                if get(resource, "sku.name", str) not in {"Standard_AzureFrontDoor", "Premium_AzureFrontDoor"}:
                    raise Unavailable("unsupported Front Door profile product")
                _coverage(resource, "endpoints", rid)
                endpoints = list_of_objects(get(resource, "endpoints", list))
                if (get(resource, "_coverage.endpoints.status", str) == "empty") != (not endpoints):
                    raise Unavailable("inconsistent Front Door endpoint paging coverage")
                child_type = "/afdendpoints/"
            actual = []
            for endpoint in endpoints:
                eid = _arm(get(endpoint, "id", str), scope)
                if not eid.startswith(rid + child_type) or "/" in eid[len(rid + child_type):]:
                    raise Unavailable("foreign Front Door endpoint identity")
                _text(endpoint, "properties.hostName")
                if eid in actual:
                    raise Unavailable("duplicate Front Door endpoint")
                actual.append(eid)
            if (is_public != bool(actual)
                    or {value.casefold() for value in frontends} != set(actual)):
                raise Unavailable("Front Door public endpoint scope unresolved")
        if not is_public:
            continue
        public.append(rid)
        if kind in {"frontdoor", "frontdoor_profile"}:
            _coverage(binding, "ddos", rid)
            ddos = get(binding, "ddos", dict)
            if get(ddos, "resource_id", str).casefold() != rid:
                raise Unavailable("foreign Front Door DDoS product mapping")
            _text(ddos, "mapping_ref")
            _text(ddos, "evidence_ref")
            state = get(ddos, "state", str)
            if state not in {"Protected", "Unprotected"}:
                raise Unavailable("unsupported Front Door DDoS product mapping")
            if state == "Unprotected":
                failed.append((rid, "ddos"))
        # Every Public IP is assessed separately; gateway/LB exact bindings
        # are validated here so protection cannot be borrowed from another IP.
        elif kind == "public_ip":
            _full(resource, "Microsoft.Network/publicIPAddresses:GET")
            settings = get(resource, "properties.ddosSettings", dict)
            mode = get(settings, "protectionMode", str)
            if mode == "Disabled":
                failed.append((rid, "ddos"))
            elif mode == "Enabled":
                plan = omitted({**settings, "_provenance": resource["_provenance"]}, "ddosProtectionPlan", None)
                if plan is not None:
                    plan_id = _arm(get(plan, "id", str), scope, "Microsoft.Network/ddosProtectionPlans")
                    if plans is None:
                        plans = _by_id(_inventory(index, "ddos_plan"), scope, "Microsoft.Network/ddosProtectionPlans")
                    if plan_id not in plans or get(plans[plan_id], "properties.provisioningState", str) != "Succeeded":
                        raise Unavailable("Public IP DDoS plan not resolved or provisioned")
            elif mode == "VirtualNetworkInherited":
                _coverage(binding, "inherited_vnet", rid)
                vnet_id = _arm(get(binding, "inherited_vnet_id", str), scope, "Microsoft.Network/virtualNetworks")
                _text(binding, "vnet_association_evidence_ref")
                if vn is None:
                    vn = _by_id(_inventory(index, "vnet"), scope, "Microsoft.Network/virtualNetworks")
                if vnet_id not in vn:
                    raise Unavailable("inherited VNet exact association unresolved")
                vnet = vn[vnet_id]
                enabled = get(vnet, "properties.enableDdosProtection", bool)
                if not enabled:
                    failed.append((rid, "ddos"))
                else:
                    plan_id = _arm(get(vnet, "properties.ddosProtectionPlan.id", str), scope, "Microsoft.Network/ddosProtectionPlans")
                    if plans is None:
                        plans = _by_id(_inventory(index, "ddos_plan"), scope, "Microsoft.Network/ddosProtectionPlans")
                    if plan_id not in plans or get(plans[plan_id], "properties.provisioningState", str) != "Succeeded":
                        raise Unavailable("inherited DDoS plan not resolved or provisioned")
            else:
                raise Unavailable("unrecognized public IP DDoS protection mode")
        if kind in {"application_gateway", "frontdoor", "frontdoor_profile"}:
            if "inlineWafConfiguration" in binding.get("_coverage", {}):
                _coverage(binding, "inlineWafConfiguration", rid)
                selections = get(binding, "declared_waf_selections", list)
                if not selections:
                    raise Unavailable("declared inline WAF selection empty")
                for selection in selections:
                    if isinstance(selection, dict):
                        if (kind != "application_gateway" or selection.get("source") != "inline"
                                or str(selection.get("parent_id", "")).casefold() != rid
                                or selection.get("native_field") != "properties.webApplicationFirewallConfiguration"
                                or selection.get("source_resource_etag") != resource.get("etag")
                                or selection.get("configuration") != resource.get("properties", {}).get("webApplicationFirewallConfiguration")):
                            raise Unavailable("inline WAF native parent/field/source mismatch")
                        _full(resource, "Microsoft.Network/applicationGateways:GET")
                        if get(resource, "properties.provisioningState", str) != "Succeeded":
                            raise Unavailable("inline WAF provisioning unresolved")
                        config = get(selection, "configuration", dict)
                        enabled = get(config, "enabled", bool)
                        mode = get(config, "firewallMode", str)
                        if mode not in {"Prevention", "Detection"}:
                            raise Unavailable("inline WAF mode unrecognized")
                        if not enabled or mode != "Prevention":
                            failed.append((rid, "waf"))
                    elif selection is None:
                        failed.append((rid, "waf"))
                    else:
                        pid = _arm(selection, scope, "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies")
                        declared = _by_id(_inventory(index, "waf_policy"), scope)
                        if pid not in declared:
                            raise Unavailable("declared WAF policy reference unresolved")
                        if not _waf(declared[pid]):
                            failed.append((rid, "waf"))
                continue
            _coverage(binding, "effective_waf", rid)
            _text(binding, "waf_linkage_evidence_ref")
            policies = get(binding, "effective_waf_policy_ids", list)
            # An explicit null represents a fully resolved route/domain with
            # no WAF. [] is an unresolved public route set, never a PASS.
            if not policies:
                raise Unavailable("effective public WAF route/domain coverage empty")
            for policy_id in policies:
                if policy_id is None:
                    failed.append((rid, "waf"))
                    continue
                pid = _arm(policy_id, scope)
                if waf is None:
                    waf = _by_id(_inventory(index, "waf_policy"), scope)
                if pid not in waf:
                    raise Unavailable("effective WAF policy reference unresolved")
                expected_type = ("Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies"
                                 if kind == "application_gateway" else
                                 "Microsoft.Network/FrontDoorWebApplicationFirewallPolicies")
                _arm(policy_id, scope, expected_type)
                if not _waf(waf[pid]):
                    failed.append((rid, "waf"))
    if not public:
        return "NOT_APPLICABLE", {"reason": "Complete inventories and frontend resolution prove no public resources"}
    return result(bool(failed), public_resource_count=len(public), missing_protections=failed[:20],
                  semantics="Exact configured IP/VNet/plan and complete effective WAF bindings; traffic and mitigation efficacy untested")
