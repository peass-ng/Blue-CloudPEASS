"""claude2_azure NETWORK group: NSG / VNet flow logs, Service Health alerts, DDoS, NIC forwarding, Application Gateway,
API Management and AKS (Prowler) predicates.

Flow logs are the Network Watcher ``flow_log`` inventory (Microsoft.Network/networkWatchers/flowLogs) collected per
subscription; NSG and VNet joins compare ARM ids case-insensitively. Every absence-based FAIL requires the complete
dependency inventory (``scoped``), otherwise the result is UNKNOWN.
"""
from __future__ import annotations
from .claude2_azure_common import *  # noqa: F401,F403
from .claude2_azure_common import CHECK_IDS
from .claude_azure_network import _conditions, _has, _alert

_START = len(CHECK_IDS)

RG = SUB + "/resourceGroups/rg/providers/Microsoft.Network/"
NSG_ID = RG + "networkSecurityGroups/nsg1"
VNET_ID = RG + "virtualNetworks/vnet1"
FLOW_REMEDIATION = ("Create a Network Watcher flow log for the target (prefer virtual network flow logs, since NSG flow log "
                    "creation is retired) with retention of at least 90 days and Traffic Analytics to a Log Analytics workspace.")


def _flow_log(target=NSG_ID, enabled=True, days=90, workspace="ws", name="fl"):
    props = {"targetResourceId": target, "enabled": enabled, "retentionPolicy": {"days": days, "enabled": True}}
    if workspace is not None:
        props["flowAnalyticsConfiguration"] = {"networkWatcherFlowAnalyticsConfiguration": {"enabled": True, "workspaceId": workspace}}
    return {"id": SUB + "/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/w/flowLogs/" + name,
            "name": name, "properties": props}


def _targets(index, item):
    wanted = lower_id(get(item, "id", str))
    return [f for f in scoped(index, "flow_log") if lower_id(get(f, "properties.targetResourceId", str)) == wanted]


def _target_type(flow_log):
    return "/" + get(flow_log, "properties.targetResourceId", str).lower().split("/providers/", 1)[-1]


VNET_TYPE = "/microsoft.network/virtualnetworks/"
VNET_TYPES = (VNET_TYPE, "/microsoft.network/networkinterfaces/")  # VNet flow log targets: VNet, subnet, NIC
NSG_TYPE = "/microsoft.network/networksecuritygroups/"


# --- NSG flow logs ---------------------------------------------------------------------------------------------
# VNet flow logs (target: virtual network, subnet or NIC) are the supported successor of retired NSG flow logs, so an NSG
# covered by a VNet flow log is never failed for lacking an NSG flow log.

_NSG = {"id": NSG_ID, "name": "nsg1", "properties": {"securityRules": [], "subnets": [{"id": VNET_ID + "/subnets/s1"}]}}


def _is_vnet_flow_log(flow_log):
    return any(t in _target_type(flow_log) for t in VNET_TYPES)


def _ids(container, key):
    return {lower_id(get(row, "id", str)) for row in list_of_objects(optional(container, key, [], list))}


def _attachments(item):
    props = get(item, "properties", dict)
    return _ids(props, "subnets"), _ids(props, "networkInterfaces")


def _nic_subnets(index, nics):
    subnets = set()
    by_id = {lower_id(get(nic, "id", str)): nic for nic in scoped(index, "nic")}
    for nic_id in nics:
        if nic_id not in by_id:
            raise Unavailable("NSG references a network interface missing from the NIC inventory")
        for config in list_of_objects(get(by_id[nic_id], "properties.ipConfigurations", list)):
            subnet = optional(get(config, "properties", dict), "subnet", None, dict)
            if subnet is not None:
                subnets.add(lower_id(get(subnet, "id", str)))
    return subnets


def _vnet_coverage(index, item):
    """Enabled-or-not VNet flow logs targeting a subnet, VNet or NIC the NSG is attached to (directly or via its NICs)."""
    subnets, nics = _attachments(item)
    vnet_logs = [f for f in scoped(index, "flow_log") if _is_vnet_flow_log(f)]
    if not vnet_logs:
        return []
    targets = subnets | nics | {s.split("/subnets/", 1)[0] for s in subnets}
    covering = [f for f in vnet_logs if lower_id(get(f, "properties.targetResourceId", str)) in targets]
    if covering or not nics:
        return covering
    nic_subnets = _nic_subnets(index, nics)
    targets = nic_subnets | {s.split("/subnets/", 1)[0] for s in nic_subnets}
    return [f for f in vnet_logs if lower_id(get(f, "properties.targetResourceId", str)) in targets]


def _nsg_flow_logs(index, item):
    return [f for f in _targets(index, item) if NSG_TYPE in _target_type(f)]


@claude2("nsg_flow_log_configured", "nsg", "Network security group traffic is captured by an NSG or VNet flow log", control="AU-12",
         dependencies=["nsg", "flow_log", "nic"], remediation=FLOW_REMEDIATION)
def nsg_flow_log(item, index):
    subnets, nics = _attachments(item)
    if not subnets and not nics:
        return na("NSG is not attached to any subnet or network interface")
    refs = list_of_objects(optional(get(item, "properties", dict), "flowLogs", [], list))
    logs = _nsg_flow_logs(index, item)
    if refs or logs:
        return result(False, nsg_flow_logs=[r.get("id") for r in refs] + [f.get("name") for f in logs])
    covering = [f for f in _vnet_coverage(index, item) if get(f, "properties.enabled", bool)]
    return result(not covering, vnet_flow_logs=[f.get("name") for f in covering],
                  semantics="An enabled VNet flow log on an attached subnet, its VNet or an attached NIC (the supported "
                            "successor of NSG flow logs) also satisfies the control")
CASES[cid("nsg_flow_log_configured")] = {"pass": _NSG, "pass_index": scope_index({"flow_log": [_flow_log(VNET_ID)]}),
                                        "fail": _NSG, "fail_index": scope_index({"flow_log": [_flow_log(VNET_ID.replace("vnet1", "other"))]}),
                                        "na": {"id": NSG_ID, "name": "nsg1", "properties": {"securityRules": []}}}


@claude2("nsg_flow_log_retention_90", "nsg", "Network security group flow log is enabled with retention of at least 90 days",
         control="AU-11", dependencies=["nsg", "flow_log", "nic"], remediation=FLOW_REMEDIATION)
def nsg_flow_retention(item, index):
    logs = _nsg_flow_logs(index, item)
    if not logs:
        covering = _vnet_coverage(index, item)
        if not covering:
            return na("No NSG flow log targets the NSG and no VNet flow log covers its subnets, VNets or NICs; NSG flow log creation is "
                      "retired, so flow logging coverage is evaluated by the VNet flow log checks")
        rows = [(f.get("name"), get(f, "properties.enabled", bool), get(f, "properties.retentionPolicy.days", int)) for f in covering]
        bad = [{"flow_log": n, "enabled": e, "retention_days": d} for n, e, d in rows if not (e and (d >= 90 or d == 0))]
        return result(bool(bad), vnet_flow_logs=bad or [n for n, _, _ in rows],
                      semantics="Covered by VNet flow logs (supported successor); 0 days means indefinite retention")
    rows = [(f.get("name"), get(f, "properties.enabled", bool), get(f, "properties.retentionPolicy.days", int)) for f in logs]
    bad = [{"flow_log": n, "enabled": e, "retention_days": d} for n, e, d in rows if not e or d < 90]
    return result(bool(bad), flow_logs=bad or [n for n, _, _ in rows],
                  semantics="Literal upstream for NSG flow logs: retention days below 90 (including 0) fail")
CASES[cid("nsg_flow_log_retention_90")] = {"pass": _NSG, "pass_index": scope_index({"flow_log": [_flow_log(days=90)]}),
                                          "fail": _NSG, "fail_index": scope_index({"flow_log": [_flow_log(days=30)]})}


@claude2("vnet_flow_log_retention_90", "flow_log", "Virtual network flow log is enabled with 90+ days (or indefinite) retention",
         control="AU-11", remediation=FLOW_REMEDIATION)
def vnet_flow_retention(item, index):
    if not _is_vnet_flow_log(item):
        return na("Flow log does not target a virtual network, subnet or network interface")
    enabled = get(item, "properties.enabled", bool)
    days = get(item, "properties.retentionPolicy.days", int)
    return result(not (enabled and (days >= 90 or days == 0)), enabled=enabled, retention_days=days)
CASES[cid("vnet_flow_log_retention_90")] = {"pass": _flow_log(VNET_ID, days=0), "fail": _flow_log(VNET_ID, days=30),
                                           "na": _flow_log(NSG_ID, days=30)}


def _analytics_count(index, target_types):
    hits = []
    for flow_log in scoped(index, "flow_log"):
        if not any(t in _target_type(flow_log) for t in target_types):
            continue
        analytics = optional(get(flow_log, "properties", dict), "flowAnalyticsConfiguration", {}, dict)
        config = optional(analytics, "networkWatcherFlowAnalyticsConfiguration", {}, dict)
        if config.get("workspaceId") is not None:
            hits.append(flow_log.get("name"))
    return hits


def _analytics_scope(slug, target_types, label, network_kinds):
    @scope_check(slug, "flow_log", "Subscription has a " + label + " flow log sent to Log Analytics (Traffic Analytics workspace)",
                 dependencies=["flow_log", *network_kinds], control="AU-6", remediation=FLOW_REMEDIATION)
    def evaluate(item, index):
        # A subscription without any flow-log target has no traffic to capture.
        if not any(scoped(index, kind) for kind in network_kinds):
            return na("Subscription has no " + label + " to capture flow logs for")
        hits = _analytics_count(index, target_types)
        return result(not hits, flow_logs=hits)
    evaluate.__name__ = "claude2_" + slug


_VNET = {"id": SUB + "/resourceGroups/r/providers/Microsoft.Network/virtualNetworks/v"}
_analytics_scope("vnet_flow_logs_to_log_analytics", VNET_TYPES, "virtual network", ("vnet",))
CASES[cid("vnet_flow_logs_to_log_analytics")] = {"pass": SCOPE, "pass_index": scope_index({"flow_log": [_flow_log(VNET_ID)], "vnet": [_VNET]}),
                                                "fail": SCOPE, "fail_index": scope_index({"flow_log": [_flow_log(VNET_ID, workspace=None)], "vnet": [_VNET]}),
                                                "not_applicable": SCOPE, "not_applicable_index": scope_index({"flow_log": [], "vnet": []})}
# CIS NSG rows: VNet flow logs with Traffic Analytics (the supported migration path) also satisfy the control; it fails only
# when neither NSG nor VNet flow logs reach a Log Analytics workspace.
_analytics_scope("nsg_flow_logs_to_log_analytics", (NSG_TYPE,) + VNET_TYPES, "network security group or virtual network", ("nsg", "vnet"))
CASES[cid("nsg_flow_logs_to_log_analytics")] = {"pass": SCOPE, "pass_index": scope_index({"flow_log": [_flow_log(VNET_ID)], "nsg": [], "vnet": [_VNET]}),
                                               "fail": SCOPE, "fail_index": scope_index({"flow_log": [_flow_log(workspace=None), _flow_log(VNET_ID, workspace=None, name="v")],
                                                                                         "nsg": [{"id": NSG_ID}], "vnet": [_VNET]}),
                                               "not_applicable": SCOPE, "not_applicable_index": scope_index({"flow_log": [], "nsg": [], "vnet": []})}


# --- Service Health activity log alert ---------------------------------------------------------------------------

@scope_check("activity_log_alert_service_health", "activity_log_alert",
             "Subscription has an enabled global activity log alert for Service Health or Resource Health events",
             dependencies=["activity_log_alert", "resource_group"], control="IR-6", remediation="Create a Service Health (or Resource Health) activity log alert scoped to the "
                                         "subscription with an action group that notifies operations staff.")
def service_health_alert(item, index):
    scope = get(item, "scope", str).rstrip("/").lower()
    if not scoped(index, "resource_group"):
        return na("Subscription has no resource groups, so no deployed service can raise health events")
    hits, malformed = [], 0
    for alert in scoped(index, "activity_log_alert"):
        try:
            if not ieq(get(alert, "location", str), "global") or get(alert, "properties.enabled", bool) is not True:
                continue
            scopes = [s.rstrip("/").lower() for s in get(alert, "properties.scopes", list) if isinstance(s, str)]
            conditions = _conditions(alert)
            if scope in scopes and (_has(conditions, "category", "ServiceHealth") or _has(conditions, "category", "ResourceHealth")):
                hits.append(alert.get("id") or alert.get("name"))
        except Unavailable:
            malformed += 1
    if not hits and malformed:
        return unknown("no matching alert and some alert rules are malformed", malformed_alerts=malformed)
    return result(not hits, alerts=hits)
_RG = [{"id": SUB + "/resourceGroups/r", "name": "r"}]
CASES[cid("activity_log_alert_service_health")] = {
    "pass": SCOPE, "pass_index": scope_index({"activity_log_alert": [_alert([("category", "ServiceHealth")])], "resource_group": _RG}),
    "fail": SCOPE, "fail_index": scope_index({"activity_log_alert": [_alert([("category", "ServiceHealth")], enabled=False)], "resource_group": _RG}),
    "not_applicable": SCOPE, "not_applicable_index": scope_index({"activity_log_alert": [], "resource_group": []})}


# --- DDoS protection for VNets hosting an Application Gateway ------------------------------------------------------

def _gateway_vnets(index):
    vnets = set()
    for gateway in scoped(index, "application_gateway"):
        for config in list_of_objects(optional(get(gateway, "properties", dict), "gatewayIPConfigurations", [], list)):
            subnet = lower_id(get(config, "properties.subnet.id", str))
            if "/subnets/" not in subnet:
                raise Unavailable("malformed gateway subnet id")
            vnets.add(subnet.split("/subnets/", 1)[0])
    return vnets


@claude2("vnet_with_app_gateway_ddos_protection", "vnet", "Virtual network hosting an Application Gateway has DDoS Network Protection",
         control="SC-5", dependencies=["vnet", "application_gateway"],
         remediation="Associate an Azure DDoS Network Protection plan with virtual networks that host Application Gateways.")
def vnet_ddos(item, index):
    if lower_id(get(item, "id", str)) not in _gateway_vnets(index):
        return na("No Application Gateway is deployed in this virtual network (upstream: DDoS protection not required)")
    enabled = omitted(item, "properties", "enableDdosProtection", "subnets", False)
    if not isinstance(enabled, bool):
        raise Unavailable("malformed enableDdosProtection")
    return result(not enabled, enable_ddos_protection=enabled)
_GW = {"id": RG + "applicationGateways/agw", "properties": {"gatewayIPConfigurations": [{"properties": {"subnet": {"id": VNET_ID + "/subnets/agw"}}}]}}
CASES[cid("vnet_with_app_gateway_ddos_protection")] = {
    "pass": {"id": VNET_ID, "properties": {"subnets": [], "enableDdosProtection": True}}, "pass_index": scope_index({"application_gateway": [_GW]}),
    "fail": {"id": VNET_ID, "properties": {"subnets": []}}, "fail_index": scope_index({"application_gateway": [_GW]})}


# --- VM network interfaces ----------------------------------------------------------------------------------------------

NIC_ID = RG + "networkInterfaces/nic1"


@claude2("vm_nic_ip_forwarding_disabled", "vm", "Virtual machine network interfaces have IP forwarding disabled", control="SC-7",
         dependencies=["vm", "nic"], remediation="Disable IP forwarding on VM NICs that are not network virtual appliances.")
def vm_ip_forwarding(item, index):
    refs = list_of_objects(get(item, "properties.networkProfile.networkInterfaces", list))
    wanted = {lower_id(get(ref, "id", str)) for ref in refs}
    found = {}
    for nic in scoped(index, "nic"):
        nic_id = nic.get("id")
        if isinstance(nic_id, str) and nic_id.lower() in wanted:
            found[nic_id.lower()] = optional(get(nic, "properties", dict), "enableIPForwarding", False, bool)
    if set(found) != wanted:
        raise Unavailable("VM network interface not in the collected NIC inventory")
    forwarding = sorted(k for k, v in found.items() if v)
    return result(bool(forwarding), ip_forwarding_nics=forwarding)
_VM = {"id": "/vm1", "properties": {"networkProfile": {"networkInterfaces": [{"id": NIC_ID}]}}}
CASES[cid("vm_nic_ip_forwarding_disabled")] = {
    "pass": _VM, "pass_index": scope_index({"nic": [{"id": NIC_ID, "properties": {"enableIPForwarding": False}}]}),
    "fail": _VM, "fail_index": scope_index({"nic": [{"id": NIC_ID, "properties": {"enableIPForwarding": True}}]})}


# --- Application Gateway -------------------------------------------------------------------------------------------------

def _agw(**properties):
    return {"id": RG + "applicationGateways/agw", "properties": {"provisioningState": "Succeeded", "sku": {"name": "WAF_v2"}, **properties}}


@claude2("app_gateway_http2_enabled", "application_gateway", "Application Gateway enables HTTP/2", severity="low", control="SC-8",
         remediation="Enable HTTP/2 on the Application Gateway listeners (enableHttp2).")
def agw_http2(item, index):
    enabled = omitted(item, "properties", "enableHttp2", "provisioningState", False)
    if not isinstance(enabled, bool):
        raise Unavailable("malformed enableHttp2")
    return result(not enabled, enable_http2=enabled)
CASES[cid("app_gateway_http2_enabled")] = {"pass": _agw(enableHttp2=True), "fail": _agw(enableHttp2=False)}

PREDEFINED_TLS = {"AppGwSslPolicy20150501": False, "AppGwSslPolicy20170401": False, "AppGwSslPolicy20170401S": True,
                  "AppGwSslPolicy20220101": True, "AppGwSslPolicy20220101S": True}


@claude2("app_gateway_min_tls_12", "application_gateway", "Application Gateway TLS policy requires TLS 1.2 or later", severity="high",
         control="SC-8", remediation="Use the AppGwSslPolicy20220101(S) predefined policy or a CustomV2 policy with minimum TLSv1_2.")
def agw_tls(item, index):
    policy = omitted(item, "properties", "sslPolicy", "provisioningState", None)
    if policy is None:
        return result(False, ssl_policy=None, semantics="Upstream treats an unset sslPolicy as compliant (service default policy)")
    if not isinstance(policy, dict):
        raise Unavailable("malformed sslPolicy")
    minimum = policy.get("minProtocolVersion")
    if minimum is not None:
        if minimum in ("TLSv1_2", "TLSv1_3"):
            return result(False, min_protocol_version=minimum)
        if minimum in ("TLSv1_0", "TLSv1_1"):
            return result(True, min_protocol_version=minimum)
        return unknown("unrecognized minProtocolVersion", min_protocol_version=minimum)
    name = policy.get("policyName")
    if name in PREDEFINED_TLS:
        return result(not PREDEFINED_TLS[name], policy_name=name)
    return unknown("TLS policy minimum version cannot be resolved", policy=policy)
CASES[cid("app_gateway_min_tls_12")] = {
    "pass": _agw(sslPolicy={"policyType": "Predefined", "policyName": "AppGwSslPolicy20220101"}),
    "fail": _agw(sslPolicy={"policyType": "Custom", "minProtocolVersion": "TLSv1_0"})}


@claude2("app_gateway_waf_enabled", "application_gateway", "Application Gateway has a Web Application Firewall enabled", severity="high",
         control="SC-7", remediation="Use the WAF_v2 SKU and associate an enabled WAF policy with the Application Gateway.")
def agw_waf(item, index):
    props = get(item, "properties", dict)
    policy = omitted(item, "properties", "firewallPolicy", "provisioningState", None)
    if isinstance(policy, dict) and isinstance(policy.get("id"), str) and policy["id"]:
        return result(False, firewall_policy=policy["id"])
    config = omitted(item, "properties", "webApplicationFirewallConfiguration", "provisioningState", None)
    if config is None:
        return result(True, reason="no WAF configuration or WAF policy")
    if not isinstance(config, dict):
        raise Unavailable("malformed webApplicationFirewallConfiguration")
    enabled = get(config, "enabled", bool)
    return result(not enabled, waf_configuration_enabled=enabled, sku=props.get("sku"))
CASES[cid("app_gateway_waf_enabled")] = {"pass": _agw(firewallPolicy={"id": RG + "ApplicationGatewayWebApplicationFirewallPolicies/p"}),
                                        "fail": _agw(sku={"name": "Standard_v2"})}

WAF_MODES = ("Prevention", "Detection")


@claude2("app_gateway_waf_mode_specified", "application_gateway", "Application Gateway WAF runs in Prevention or Detection mode",
         control="SC-7", dependencies=["application_gateway", "web_application_firewall_policy"],
         remediation="Attach a WAF policy (mode Prevention once tuned) to the Application Gateway.")
def agw_waf_mode(item, index):
    policy = omitted(item, "properties", "firewallPolicy", "provisioningState", None)
    if isinstance(policy, dict) and isinstance(policy.get("id"), str) and policy["id"]:
        wanted = lower_id(policy["id"])
        rows = [p for p in scoped(index, "web_application_firewall_policy") if lower_id(get(p, "id", str)) == wanted]
        if len(rows) != 1:
            raise Unavailable("associated WAF policy not in the collected inventory")
        mode = get(rows[0], "properties.policySettings.mode", str)
    else:
        config = omitted(item, "properties", "webApplicationFirewallConfiguration", "provisioningState", None)
        if config is None:
            return result(True, reason="no WAF configuration or WAF policy")
        mode = get(config, "firewallMode", str)
    if mode not in WAF_MODES:
        return unknown("unrecognized WAF mode", mode=mode)
    return result(False, mode=mode, semantics="Upstream reads a non-existent PolicySettings key; native ARM mode fields are used")
_WAFP = RG + "ApplicationGatewayWebApplicationFirewallPolicies/p"
CASES[cid("app_gateway_waf_mode_specified")] = {
    "pass": _agw(firewallPolicy={"id": _WAFP}),
    "pass_index": scope_index({"web_application_firewall_policy": [{"id": _WAFP, "properties": {"policySettings": {"mode": "Prevention"}}}]}),
    "fail": _agw(sku={"name": "Standard_v2"}), "fail_index": scope_index({"web_application_firewall_policy": []})}


# --- API Management ---------------------------------------------------------------------------------------------------

@claude2("apim_consumption_client_certificate", "api_management", "API Management (Consumption tier) requests client certificates",
         control="IA-3", remediation="Enable 'Request client certificate' (enableClientCertificate) on Consumption-tier API Management.")
def apim_client_cert(item, index):
    sku = get(item, "sku.name", str)
    if sku != "Consumption":
        return na("enableClientCertificate is only meant for the Consumption SKU; other tiers negotiate client certificates per hostname",
                  sku=sku)
    enabled = omitted(item, "properties", "enableClientCertificate", "provisioningState", False)
    if not isinstance(enabled, bool):
        raise Unavailable("malformed enableClientCertificate")
    return result(not enabled, enable_client_certificate=enabled)
CASES[cid("apim_consumption_client_certificate")] = {
    "pass": {"sku": {"name": "Consumption"}, "properties": {"provisioningState": "Succeeded", "enableClientCertificate": True}},
    "fail": {"sku": {"name": "Consumption"}, "properties": {"provisioningState": "Succeeded"}},
    "na": {"sku": {"name": "Developer"}, "properties": {"provisioningState": "Succeeded"}}}


# --- AKS (Prowler) ------------------------------------------------------------------------------------------------------

@claude2("aks_azure_monitor_metrics_enabled", "aks_cluster", "AKS cluster has Azure Monitor managed Prometheus metrics enabled",
         severity="low", control="SI-4", remediation="Enable Azure Monitor managed service for Prometheus on the cluster.")
def aks_monitor(item, index):
    profile = omitted(item, "properties", "azureMonitorProfile", "provisioningState", None)
    if profile is None:
        return result(True, azure_monitor_profile=None)
    if not isinstance(profile, dict):
        raise Unavailable("malformed azureMonitorProfile")
    metrics = optional(profile, "metrics", None)
    if metrics is None:
        return result(True, metrics=None)
    enabled = get(metrics, "enabled", bool)
    return result(not enabled, metrics_enabled=enabled)
CASES[cid("aks_azure_monitor_metrics_enabled")] = {
    "pass": {"properties": {"provisioningState": "Succeeded", "azureMonitorProfile": {"metrics": {"enabled": True}}}},
    "fail": {"properties": {"provisioningState": "Succeeded"}}}


@claude2("aks_private_cluster_nodes_without_public_ip", "aks_cluster", "AKS cluster is private and has a node pool without public node IPs",
         severity="high", control="SC-7", category="exposure",
         remediation="Use a private cluster (private API server FQDN) and disable node public IPs on every node pool.")
def aks_public_access(item, index):
    fqdn = omitted(item, "properties", "privateFQDN", "provisioningState", None)
    pools = list_of_objects(get(item, "properties.agentPoolProfiles", list))
    public = [optional(p, "enableNodePublicIP", False, bool) for p in pools]
    ok = bool(fqdn) and any(not value for value in public)
    return result(not ok, private_fqdn=fqdn, node_public_ip=public,
                  semantics="Literal Prowler: private FQDN and at least one node pool without node public IPs")
CASES[cid("aks_private_cluster_nodes_without_public_ip")] = {
    "pass": {"properties": {"provisioningState": "Succeeded", "privateFQDN": "x.privatelink.eastus.azmk8s.io",
                            "agentPoolProfiles": [{"name": "p", "enableNodePublicIP": False}]}},
    "fail": {"properties": {"provisioningState": "Succeeded", "fqdn": "x.hcp.eastus.azmk8s.io",
                            "agentPoolProfiles": [{"name": "p", "enableNodePublicIP": False}]}}}


NETWORK_IDS = tuple(CHECK_IDS[_START:])
