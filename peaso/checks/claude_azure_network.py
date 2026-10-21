"""Claude-ported Azure predicates, group NETWORK: NSG exposure, network watcher/flow logs, monitor
activity-log alerts and diagnostic settings, Log Analytics, Logic Apps, Machine Learning, SQL Managed
Instance, MySQL/PostgreSQL flexible servers, Azure Policy and Recovery Services.

Every predicate reads ARM-native shapes. Missing, denied, malformed or uncollected facts are UNKNOWN;
resource-type skip branches are NOT_APPLICABLE. Single Server / MariaDB / log-profile rows are rejected
in the review shard (retired services), so no predicate exists for them here.
"""
from __future__ import annotations

import re

from .claude_azure_common import *  # noqa: F401,F403
from .claude_azure_common import _strings, nsg_protocol, nsg_sources

_START = len(CHECK_IDS)
SUB = "/subscriptions/s"


def _norm(value):
    return value.replace(" ", "").lower() if isinstance(value, str) else value


def _ieq(a, b):
    return isinstance(a, str) and isinstance(b, str) and a.lower() == b.lower()


# --- NSG exposure (priority-aware, first-match Azure NSG semantics) ---------------------------------------

_FAMILIES = frozenset(("ipv4", "ipv6"))
_INTERNET = {source.lower(): _FAMILIES for source in INTERNET_SOURCES}
_INTERNET.update({"0.0.0.0": frozenset(("ipv4",)),
                  "0.0.0.0/0": frozenset(("ipv4",)),
                  "::/0": frozenset(("ipv6",))})


def _rules(item):
    properties = get(item, "properties", dict)
    raw = list(list_of_objects(get(item, "properties.securityRules", list)))
    raw = raw + list(list_of_objects(optional(properties, "defaultSecurityRules", [], list)))
    rules = []
    for rule in raw:
        p = get(rule, "properties", dict)
        direction, access, protocol, priority = (get(p, "direction", str), get(p, "access", str),
                                                nsg_protocol(p), get(p, "priority", int))
        if direction not in ("Inbound", "Outbound") or access not in ("Allow", "Deny") or not isinstance(protocol, str):
            raise Unavailable("malformed NSG rule direction, access or protocol")
        if type(priority) is not int:
            raise Unavailable("missing or malformed NSG rule priority")
        ports = [port_range(spec) for spec in _strings(p, "destinationPortRanges", "destinationPortRange")]
        if not ports:
            raise Unavailable("NSG rule without destination ports")
        source_ports = [port_range(spec) for spec in _strings(p, "sourcePortRanges", "sourcePortRange")]
        if not source_ports:
            raise Unavailable("NSG rule without source ports")
        dests = _strings(p, "destinationAddressPrefixes", "destinationAddressPrefix")
        if not dests:
            asgs = list_of_objects(optional(p, "destinationApplicationSecurityGroups", [], list))
            if not asgs:
                raise Unavailable("NSG destination selector unavailable")
            ids = [get(asg, "id", str) for asg in asgs]
            if any(not re.fullmatch(
                    r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/applicationSecurityGroups/[^/]+",
                    identifier, re.IGNORECASE) for identifier in ids):
                raise Unavailable("malformed NSG destination application security group")
            dests = ["asg:" + identifier for identifier in ids]
        elif any(not dest.strip() for dest in dests):
            raise Unavailable("empty NSG destination selector")
        rules.append({"name": rule.get("name"), "priority": priority, "direction": direction, "access": access,
                      "protocol": protocol.lower(), "sources": [source.lower() for source in nsg_sources(p)],
                      "ports": ports, "source_ports": source_ports, "dests": [d.lower() for d in dests]})
    return rules


def _internet_families(rule):
    families = set()
    for source in rule["sources"]:
        families.update(_INTERNET.get(source, ()))
    return families


def _internet(rule):
    return bool(_internet_families(rule))


def _protocols(protocol, targets):
    if targets is None:
        return [protocol]
    if protocol == "*":
        return list(targets)
    return [protocol] if protocol in targets else []


def _intervals(rule, ports):
    """Port intervals of the target that this rule matches."""
    if ports == "any":
        return list(rule["ports"])
    if ports is None:
        return [(0, 65535)] if any(lo <= 0 and hi >= 65535 for lo, hi in rule["ports"]) else []
    return [(p, p) for p in ports if any(lo <= p <= hi for lo, hi in rule["ports"])]


def _uncovered_ports(rectangles, source_ports, destination_ports):
    """Subtract a deny's source/destination port rectangles from an Allow."""
    for source_lo, source_hi in source_ports:
        for dest_lo, dest_hi in destination_ports:
            remaining = []
            for src_lo, src_hi, dst_lo, dst_hi in rectangles:
                cut_src_lo, cut_src_hi = max(src_lo, source_lo), min(src_hi, source_hi)
                cut_dst_lo, cut_dst_hi = max(dst_lo, dest_lo), min(dst_hi, dest_hi)
                if cut_src_lo > cut_src_hi or cut_dst_lo > cut_dst_hi:
                    remaining.append((src_lo, src_hi, dst_lo, dst_hi))
                    continue
                if src_lo < cut_src_lo:
                    remaining.append((src_lo, cut_src_lo - 1, dst_lo, dst_hi))
                if cut_src_hi < src_hi:
                    remaining.append((cut_src_hi + 1, src_hi, dst_lo, dst_hi))
                if dst_lo < cut_dst_lo:
                    remaining.append((cut_src_lo, cut_src_hi, dst_lo, cut_dst_lo - 1))
                if cut_dst_hi < dst_hi:
                    remaining.append((cut_src_lo, cut_src_hi, cut_dst_hi + 1, dst_hi))
            rectangles = remaining
    return rectangles


def _shadow(rules, allow, protocol, interval):
    uncovered = {(family, dest): [(lo, hi, *interval) for lo, hi in allow["source_ports"]]
                 for family in _internet_families(allow) for dest in set(allow["dests"])}
    for deny in rules:
        if deny["access"] != "Deny" or deny["direction"] != allow["direction"] or deny["priority"] >= allow["priority"]:
            continue
        families = {family for family, _ in uncovered} & _internet_families(deny)
        if not families or (deny["protocol"] != "*" and deny["protocol"] != protocol):
            continue
        destinations = set(allow["dests"]) if "*" in deny["dests"] else set(allow["dests"]) & set(deny["dests"])
        if not destinations:
            continue
        for key in list(uncovered):
            family, dest = key
            if family not in families or dest not in destinations:
                continue
            uncovered[key] = _uncovered_ports(uncovered[key], deny["source_ports"], deny["ports"])
            if not uncovered[key]:
                del uncovered[key]
        if not uncovered:
            return True
    return None


def nsg_exposure(item, *, direction="Inbound", protocols=("tcp",), ports=None):
    """Unshadowed internet-source Allow rules. ``ports``: list of ints, None (all ports) or "any"."""
    rules = _rules(item)
    hits = []
    for allow in rules:
        if allow["access"] != "Allow" or allow["direction"] != direction or not _internet(allow):
            continue
        for protocol in _protocols(allow["protocol"], protocols):
            for interval in _intervals(allow, ports):
                if _shadow(rules, allow, protocol, interval) is None:
                    port = "all" if ports is None else interval[0] if interval[0] == interval[1] else "%d-%d" % interval
                    hits.append({"rule": allow["name"], "priority": allow["priority"], "protocol": protocol, "port": port})
    return hits


def _rule(name, protocol, sources, ports, priority=200, direction="Inbound", access="Allow", dest="*"):
    data = nsg_rule(name, protocol, sources, ports, direction, access)
    data["properties"].update({"priority": priority, "destinationAddressPrefix": dest})
    return data


DEFAULT_RULES = [
    _rule("AllowVnetInBound", "*", "VirtualNetwork", "*", 65000, dest="VirtualNetwork"),
    _rule("AllowAzureLoadBalancerInBound", "*", "AzureLoadBalancer", "*", 65001),
    _rule("DenyAllInBound", "*", "*", "*", 65500, access="Deny"),
    _rule("AllowVnetOutBound", "*", "VirtualNetwork", "*", 65000, "Outbound", dest="VirtualNetwork"),
    _rule("AllowInternetOutBound", "*", "*", "*", 65001, "Outbound", dest="Internet"),
    _rule("DenyAllOutBound", "*", "*", "*", 65500, "Outbound", "Deny"),
]


def _nsg(*rules):
    return nsg_case(*rules, defaults=DEFAULT_RULES)


NSG_REMEDIATION = ("Remove or narrow the NSG Allow rule so the port is not reachable from Internet, '*' or 0.0.0.0/0; "
                   "allow only specific trusted prefixes, or front administration with Azure Bastion/VPN. A higher-priority "
                   "Deny from the internet also closes the exposure.")


def nsg_check(slug, title, *, protocols=("tcp",), ports=None, direction="Inbound", severity="high", remediation=None,
              fixture_protocol=None, fixture_port=None):
    @claude(slug, "nsg", title, severity=severity, control="SC-7", category="exposure", remediation=remediation or NSG_REMEDIATION)
    def evaluate(item, index):
        hits = nsg_exposure(item, direction=direction, protocols=protocols, ports=ports)
        return result(bool(hits), exposed_rules=hits[:25], direction=direction)
    evaluate.__name__ = "claude_" + slug
    protocol = fixture_protocol or ("Tcp" if protocols is None else protocols[0].capitalize())
    port = fixture_port or ("*" if ports in (None, "any") else str(ports[0]))
    if direction == "Outbound":
        fail = _nsg()
    else:
        fail = _nsg(_rule("open", protocol, "Internet", port))
    shadow = _rule("deny-internet", "*", "Internet", "*", 100, direction, "Deny")
    CASES[cid(slug)] = {"pass": _nsg(shadow, _rule("open", protocol, "Internet", port, direction=direction)), "fail": fail}
    return evaluate


TCP_PORTS = {135: "RPC/DCOM", 1433: "SQL Server", 20: "FTP data", 21: "FTP", 23: "Telnet", 25: "SMTP", 3306: "MySQL",
             4333: "mSQL", 445: "SMB/CIFS", 53: "DNS over TCP", 5432: "PostgreSQL", 5500: "VNC listener", 5900: "VNC server"}
UDP_PORTS = {137: "NetBIOS name service", 138: "NetBIOS datagram", 1434: "SQL Server browser", 445: "SMB over UDP", 53: "DNS"}
for _port, _service in TCP_PORTS.items():
    nsg_check("nsg_internet_tcp_%d" % _port, "NSG blocks internet ingress to TCP port %d (%s)" % (_port, _service), ports=[_port],
              severity="medium" if _port in (25, 53) else "high")
for _port, _service in UDP_PORTS.items():
    nsg_check("nsg_internet_udp_%d" % _port, "NSG blocks internet ingress to UDP port %d (%s)" % (_port, _service),
              protocols=("udp",), ports=[_port], severity="medium" if _port == 53 else "high")
nsg_check("nsg_internet_rdp", "NSG blocks internet ingress to RDP (TCP 3389)", ports=[3389])
nsg_check("nsg_internet_ssh", "NSG blocks internet ingress to SSH (TCP 22)", ports=[22])
nsg_check("nsg_internet_remote_access", "NSG blocks internet ingress to SSH and RDP (TCP 22/3389)", ports=[22, 3389])
nsg_check("nsg_internet_http", "NSG blocks internet ingress to HTTP (TCP 80)", ports=[80], severity="medium",
          remediation="Do not expose TCP 80 directly from Internet/'*'/0.0.0.0/0 on workload NSGs; publish web workloads through "
                      "Application Gateway/Front Door with WAF and HTTPS, or restrict the source prefixes.")
nsg_check("nsg_internet_http_https", "NSG blocks internet ingress to TCP 80 and 443", ports=[80, 443], severity="medium",
          remediation="Do not expose TCP 80/443 directly from Internet/'*'/0.0.0.0/0 on workload NSGs; publish web workloads through "
                    "a WAF-protected reverse proxy (Application Gateway/Front Door) or restrict the source prefixes.")
nsg_check("nsg_internet_icmp", "NSG blocks internet ingress for ICMP", protocols=("icmp",), ports=None, severity="medium",
          fixture_protocol="Icmp")
nsg_check("nsg_internet_udp_services", "NSG blocks internet ingress to UDP 53/123/161/389/1900", protocols=("udp",),
          ports=[53, 123, 161, 389, 1900], fixture_port="100-2000")
nsg_check("nsg_internet_udp_any", "NSG blocks UDP ingress from the internet on any port", protocols=("udp",), ports="any",
          fixture_port="5000")
nsg_check("nsg_internet_all_ports_tcp_udp", "NSG blocks internet ingress to all TCP/UDP ports", protocols=("tcp", "udp"), ports=None,
          severity="critical")
COMMON_PORTS = [20, 21, 22, 23, 25, 110, 135, 143, 445, 1433, 1434, 3306, 3389, 4333, 5432, 5500, 5601, 8080, 9200, 9300]
nsg_check("nsg_internet_common_ports", "NSG blocks internet ingress to common administrative and data ports (any protocol)",
          protocols=None, ports=COMMON_PORTS, fixture_port="9200")
nsg_check("nsg_outbound_restricted", "NSG does not allow unrestricted outbound traffic on all ports", direction="Outbound",
          protocols=None, ports=None, severity="low",
          remediation="Add explicit outbound rules that allow only required destinations/ports and a lower-numbered Deny-all outbound "
                      "rule ahead of the default AllowInternetOutBound rule, or route egress through Azure Firewall.")


# --- Activity log alerts --------------------------------------------------------------------------------

def _conditions(alert):
    return list_of_objects(get(alert, "properties.condition.allOf", list))


def _has(conditions, field, value):
    return any(_ieq(c.get("field"), field) and _ieq(c.get("equals"), value) for c in conditions)


def _operation_covers_scope(conditions, operations, category):
    # ARM write/delete operations produce Administrative activity events.
    # allOf must not add a caller, resource group, ID, status, or unknown
    # restriction when this check claims subscription-wide operation coverage.
    if not conditions:
        raise Unavailable("missing activity log alert conditions")
    operation_value = None
    for condition in conditions:
        field = get(condition, "field", str).casefold()
        equals = get(condition, "equals", str)
        if field == "operationname":
            if not any(_ieq(equals, operation) for operation in operations):
                return False
            if operation_value is not None and not _ieq(equals, operation_value):
                return False
            operation_value = equals
        elif field == "category":
            if not _ieq(equals, category):
                return False
        else:
            raise Unavailable("unsupported activity log alert condition for whole-subscription coverage")
    return operation_value is not None


def _strict_alert(alert, scope, category, operations, resource_type):
    if not _ieq(get(alert, "location", str), "global") or get(alert, "properties.enabled", bool) is not True:
        return False
    scopes = [s.rstrip("/").lower() for s in get(alert, "properties.scopes", list) if isinstance(s, str)]
    if scope not in scopes:
        return False
    conditions = _conditions(alert)
    if not _has(conditions, "category", category):
        return False
    if any(_has(conditions, "operationName", operation) for operation in operations):
        return _operation_covers_scope(conditions, operations, category)
    return bool(resource_type) and _has(conditions, "resourceType", resource_type) and len(conditions) == 2


def _loose_alert(alert, scope, operations):
    if get(alert, "properties.enabled", bool) is not True:
        return False
    # The alert resource can be listed in this subscription while its event
    # scopes cover only a different resource group. A subscription finding
    # needs the selected subscription itself as an event prefix.
    scopes = get(alert, "properties.scopes", list)
    if not scopes or any(not isinstance(value, str) or not value.strip() for value in scopes):
        raise Unavailable("malformed activity log alert scopes")
    if scope not in {("/" + value.strip("/")).casefold() for value in scopes}:
        return False
    return _operation_covers_scope(_conditions(alert), operations, "Administrative")


def _alert_scan(item, index, matcher):
    scope = get(item, "scope", str).rstrip("/").lower()
    malformed = 0
    for alert in scoped(index, "activity_log_alert"):
        try:
            if matcher(alert, scope):
                return result(False, alert=alert.get("id") or alert.get("name"))
        except Unavailable:
            malformed += 1
    if malformed:
        return unknown("no matching alert and some alert rules are malformed", malformed_alerts=malformed)
    return result(True, reason="no matching enabled activity log alert")


def _alert(conditions, enabled=True, scopes=(SUB,), location="Global"):
    return {"id": SUB + "/resourceGroups/r/providers/Microsoft.Insights/activityLogAlerts/a", "name": "a", "location": location,
            "properties": {"enabled": enabled, "scopes": list(scopes),
                           "condition": {"allOf": [{"field": f, "equals": e} for f, e in conditions]}}}


ALERT_REMEDIATION = ("Create an enabled Azure Monitor activity log alert rule (location Global) scoped to the subscription with "
                     "condition category={category} and operationName={operation}, attached to an action group that notifies the "
                     "security team.")


def strict_alert_check(slug, title, *, category="Administrative", operations=(), resource_type=None, severity="medium"):
    shown = operations[0] if operations else resource_type

    @claude(slug, "activity_log_alert", title, severity=severity, control="AU-6", target="scope",
            remediation=ALERT_REMEDIATION.format(category=category, operation=shown), dependencies=["activity_log_alert"])
    def evaluate(item, index):
        return _alert_scan(item, index, lambda alert, scope: _strict_alert(alert, scope, category, operations, resource_type))
    evaluate.__name__ = "claude_" + slug
    if operations:
        good = _alert([("category", category), ("operationName", operations[0])])
    else:
        good = _alert([("category", category), ("resourceType", resource_type)])
    wrong_scope = _alert([("category", category), ("operationName", operations[0] if operations else "x"),
                          ("resourceType", resource_type or "x")], scopes=(SUB + "/resourceGroups/r",))
    CASES[cid(slug)] = {"pass": {"scope": SUB}, "fail": {"scope": SUB},
                        "pass_index": scope_index({"activity_log_alert": [good]}),
                        "fail_index": scope_index({"activity_log_alert": [wrong_scope]})}
    return evaluate


def loose_alert_check(slug, title, operations, severity="medium"):
    @claude(slug, "activity_log_alert", title, severity=severity, control="AU-6", target="scope",
            remediation=ALERT_REMEDIATION.format(category="Administrative/Security", operation=operations[0]),
            dependencies=["activity_log_alert"])
    def evaluate(item, index):
        return _alert_scan(item, index, lambda alert, scope: _loose_alert(alert, scope, operations))
    evaluate.__name__ = "claude_" + slug
    CASES[cid(slug)] = {"pass": {"scope": SUB}, "fail": {"scope": SUB},
                        "pass_index": scope_index({"activity_log_alert": [_alert([("operationName", operations[-1])])]}),
                        "fail_index": scope_index({"activity_log_alert": [_alert([("operationName", operations[0])], enabled=False)]})}
    return evaluate


NSG_T = "microsoft.network/networksecuritygroups"
STRICT_ALERTS = [
    ("activity_log_alert_subscription_policy_assignment_write", "Create Policy Assignment", "Administrative",
     ("Microsoft.Authorization/policyAssignments/write",), None),
    ("activity_log_alert_subscription_policy_assignment_delete", "Delete Policy Assignment", "Administrative",
     ("Microsoft.Authorization/policyAssignments/delete",), None),
    ("activity_log_alert_subscription_nsg_write", "Create or Update Network Security Group", "Administrative",
     ("Microsoft.Network/networkSecurityGroups/write",), NSG_T),
    ("activity_log_alert_subscription_nsg_delete", "Delete Network Security Group", "Administrative",
     ("Microsoft.Network/networkSecurityGroups/delete",), NSG_T),
    ("activity_log_alert_subscription_nsg_rule_write", "Create or Update Network Security Group Rule", "Administrative",
     ("Microsoft.Network/networksecuritygroups/securityrules/write",), NSG_T + "/securityrules"),
    ("activity_log_alert_subscription_nsg_rule_delete", "Delete Network Security Group Rule", "Administrative",
     ("Microsoft.Network/networksecuritygroups/securityrules/delete",), NSG_T + "/securityrules"),
    ("activity_log_alert_subscription_public_ip_write", "Create or Update Public IP Address", "Administrative",
     ("Microsoft.Network/publicIPAddresses/write",), "microsoft.network/publicipaddresses"),
    ("activity_log_alert_subscription_public_ip_delete", "Delete Public IP Address", "Administrative",
     ("Microsoft.Network/publicIPAddresses/delete",), "microsoft.network/publicipaddresses"),
    ("activity_log_alert_subscription_security_solution_write", "Create or Update Security Solution", "Administrative",
     ("Microsoft.Security/securitySolutions/write",), "microsoft.security/securitysolutions"),
    ("activity_log_alert_subscription_security_solution_delete", "Delete Security Solution", "Administrative",
     ("Microsoft.Security/securitySolutions/delete",), "microsoft.security/securitysolutions"),
    ("activity_log_alert_subscription_sql_firewall_rule_write", "Create or Update SQL Server Firewall Rule", "Administrative",
     ("Microsoft.Sql/servers/firewallRules/write",), "microsoft.sql/servers/firewallrules"),
    ("activity_log_alert_subscription_sql_firewall_rule_delete", "Delete SQL Server Firewall Rule", "Administrative",
     ("Microsoft.Sql/servers/firewallRules/delete",), "microsoft.sql/servers/firewallrules"),
    ("activity_log_alert_subscription_administrative_operations", "an administrative network/SQL firewall operation", "Administrative",
     ("Microsoft.Sql/servers/firewallRules/write", "Microsoft.Sql/servers/firewallRules/delete",
      "Microsoft.Network/networkSecurityGroups/write", "Microsoft.Network/networkSecurityGroups/delete",
      "Microsoft.ClassicNetwork/networkSecurityGroups/write", "Microsoft.ClassicNetwork/networkSecurityGroups/delete",
      "Microsoft.Network/networkSecurityGroups/securityRules/write", "Microsoft.Network/networkSecurityGroups/securityRules/delete",
      "Microsoft.ClassicNetwork/networkSecurityGroups/securityRules/write",
      "Microsoft.ClassicNetwork/networkSecurityGroups/securityRules/delete"), None),
    ("activity_log_alert_subscription_sql_server", "SQL server resource operations", "Administrative", (), "microsoft.sql/servers"),
]
for _slug, _what, _category, _operations, _rtype in STRICT_ALERTS:
    strict_alert_check(_slug, "Subscription-scoped activity log alert exists for " + _what, category=_category, operations=_operations,
                       resource_type=_rtype, severity="high" if "nsg" in _slug or "policy" in _slug else "medium")

LOOSE_ALERTS = [
    ("activity_log_alert_policy_assignment_write", "Create Policy Assignment", ("Microsoft.Authorization/policyAssignments/write",), "medium"),
    ("activity_log_alert_policy_assignment_delete", "Delete Policy Assignment", ("Microsoft.Authorization/policyAssignments/delete",), "high"),
    ("activity_log_alert_nsg_write", "Create or Update Network Security Group", ("Microsoft.Network/networkSecurityGroups/write",), "high"),
    ("activity_log_alert_nsg_delete", "Delete Network Security Group",
     ("Microsoft.Network/networkSecurityGroups/delete", "Microsoft.ClassicNetwork/networkSecurityGroups/delete"), "high"),
    ("activity_log_alert_public_ip_write", "Create or Update Public IP Address", ("Microsoft.Network/publicIPAddresses/write",), "medium"),
    ("activity_log_alert_public_ip_delete", "Delete Public IP Address", ("Microsoft.Network/publicIPAddresses/delete",), "medium"),
    ("activity_log_alert_security_solution_write", "Create or Update Security Solution", ("Microsoft.Security/securitySolutions/write",), "medium"),
    ("activity_log_alert_security_solution_delete", "Delete Security Solution", ("Microsoft.Security/securitySolutions/delete",), "medium"),
    ("activity_log_alert_sql_firewall_rule_write", "Create or Update SQL Server Firewall Rule", ("Microsoft.Sql/servers/firewallRules/write",), "medium"),
    ("activity_log_alert_sql_firewall_rule_delete", "Delete SQL Server Firewall Rule", ("Microsoft.Sql/servers/firewallRules/delete",), "medium"),
]
for _slug, _what, _operations, _severity in LOOSE_ALERTS:
    loose_alert_check(_slug, "Enabled activity log alert exists for " + _what, _operations, _severity)


@claude("activity_log_alert_service_health", "activity_log_alert", "Enabled activity log alert exists for Service Health incidents",
        control="IR-6", target="scope", dependencies=["activity_log_alert"],
        remediation="Create an enabled activity log alert with condition category=ServiceHealth and properties.incidentType=Incident "
                    "and route it to an action group monitored by operations/security.")
def claude_activity_log_alert_service_health(item, index):
    def match(alert, scope):
        conditions = _conditions(alert)
        return (get(alert, "properties.enabled", bool) is True and _has(conditions, "category", "ServiceHealth")
                and _has(conditions, "properties.incidentType", "Incident"))
    return _alert_scan(item, index, match)


CASES[cid("activity_log_alert_service_health")] = {
    "pass": {"scope": SUB}, "fail": {"scope": SUB},
    "pass_index": scope_index({"activity_log_alert": [_alert([("category", "ServiceHealth"), ("properties.incidentType", "Incident")])]}),
    "fail_index": scope_index({"activity_log_alert": [_alert([("category", "ServiceHealth")])]})}


# --- Subscription diagnostic settings (activity log export) ---------------------------------------------

ACTIVITY_CATEGORIES = ("administrative", "security", "alert", "policy")


def _enabled_categories(setting_item):
    enabled = set()
    for log in diagnostic_logs(setting_item):
        if get(log, "enabled", bool):
            if _ieq(log.get("categoryGroup"), "allLogs"):
                enabled.update(ACTIVITY_CATEGORIES)
            elif isinstance(log.get("category"), str):
                enabled.add(log["category"].lower())
    return enabled


def _sub_setting(logs, storage=None, name="export"):
    properties = {"logs": logs}
    if storage:
        properties["storageAccountId"] = storage
    return {"id": SUB + "/providers/microsoft.insights/diagnosticSettings/" + name, "name": name, "properties": properties}


ALL_CATS = [diag_log(c) for c in ("Administrative", "Security", "Alert", "Policy")]
DIAG_REMEDIATION = ("Create a subscription diagnostic setting (Monitor > Activity log > Export Activity Logs) that sends the "
                    "Administrative, Security, Alert and Policy categories to a Log Analytics workspace, storage account or event hub.")


@claude("subscription_diagnostic_setting_exists", "subscription_diagnostic_setting", "Subscription exports the activity log through a diagnostic setting",
        severity="high", control="AU-12", target="scope", dependencies=["subscription_diagnostic_setting"], remediation=DIAG_REMEDIATION)
def claude_subscription_diagnostic_setting_exists(item, index):
    get(item, "scope", str)
    settings = scoped(index, "subscription_diagnostic_setting")
    return result(not settings, settings=[s.get("name") for s in settings][:10])


CASES[cid("subscription_diagnostic_setting_exists")] = {
    "pass": {"scope": SUB}, "fail": {"scope": SUB},
    "pass_index": scope_index({"subscription_diagnostic_setting": [_sub_setting(ALL_CATS)]}),
    "fail_index": scope_index({"subscription_diagnostic_setting": []})}


@claude("subscription_diagnostic_setting_categories", "subscription_diagnostic_setting",
        "Subscription diagnostic setting captures Administrative, Security, Alert and Policy", severity="medium", control="AU-12",
        remediation=DIAG_REMEDIATION)
def claude_subscription_diagnostic_setting_categories(item, index):
    enabled = _enabled_categories(item)
    missing = [c for c in ACTIVITY_CATEGORIES if c not in enabled]
    return result(bool(missing), missing_categories=missing)


CASES[cid("subscription_diagnostic_setting_categories")] = {"pass": _sub_setting(ALL_CATS), "fail": _sub_setting(ALL_CATS[:2])}


@claude("subscription_diagnostic_setting_any_categories", "subscription_diagnostic_setting",
        "A subscription diagnostic setting captures Administrative, Security, Alert and Policy", severity="high", control="AU-12",
        target="scope", dependencies=["subscription_diagnostic_setting"], remediation=DIAG_REMEDIATION)
def claude_subscription_diagnostic_setting_any_categories(item, index):
    get(item, "scope", str)
    for setting_item in scoped(index, "subscription_diagnostic_setting"):
        if all(c in _enabled_categories(setting_item) for c in ACTIVITY_CATEGORIES):
            return result(False, setting=setting_item.get("name"))
    return result(True, reason="no diagnostic setting captures all four categories")


CASES[cid("subscription_diagnostic_setting_any_categories")] = {
    "pass": {"scope": SUB}, "fail": {"scope": SUB},
    "pass_index": scope_index({"subscription_diagnostic_setting": [_sub_setting(ALL_CATS[:1], name="a"), _sub_setting(ALL_CATS)]}),
    "fail_index": scope_index({"subscription_diagnostic_setting": [_sub_setting(ALL_CATS[:3])]})}


SA_ID = SUB + "/resourceGroups/r/providers/Microsoft.Storage/storageAccounts/logs"


def _activity_storage(item, index, judge):
    """Judge storage accounts that subscription diagnostic settings export the activity log to."""
    get(item, "scope", str)
    accounts = {get(a, "id", str).lower(): a for a in scoped(index, "storage_account")}
    targets = []
    for setting_item in scoped(index, "subscription_diagnostic_setting"):
        storage = optional(get(setting_item, "properties", dict), "storageAccountId", None)
        if storage:
            if not isinstance(storage, str):
                raise Unavailable("malformed storageAccountId")
            targets.append(storage.lower())
    if not targets:
        return "NOT_APPLICABLE", {"reason": "no diagnostic setting exports the activity log to a storage account"}
    failed, unresolved = [], []
    for target in sorted(set(targets)):
        account = accounts.get(target)
        verdict = None
        if account is not None:
            try:
                verdict = judge(account)
            except Unavailable:
                verdict = None
        if verdict is True:
            failed.append(target)
        elif verdict is None:
            unresolved.append(target)
    if failed:
        return result(True, storage_accounts=failed)
    if unresolved:
        return unknown("activity log storage account not collected in scope or facts unavailable", storage_accounts=unresolved)
    return result(False, storage_accounts=sorted(set(targets)))


def _cmk_fails(account):
    source = get(account, "properties.encryption.keySource", str)
    if source == "Microsoft.Storage":
        return True
    if source == "Microsoft.Keyvault":
        return False
    return None


@claude("activity_log_storage_cmk", "storage_account", "Storage account receiving the activity log is encrypted with a customer-managed key",
        control="SC-28", target="scope", dependencies=["subscription_diagnostic_setting", "storage_account"],
        remediation="Configure customer-managed keys (Key Vault key source) on the storage account that receives activity-log exports.")
def claude_activity_log_storage_cmk(item, index):
    return _activity_storage(item, index, _cmk_fails)


@claude("activity_log_storage_private", "storage_account", "Storage account receiving the activity log disallows blob public access",
        severity="high", control="AC-3", target="scope", dependencies=["subscription_diagnostic_setting", "storage_account"],
        remediation="Set allowBlobPublicAccess=false on the storage account that receives activity-log exports.")
def claude_activity_log_storage_private(item, index):
    return _activity_storage(item, index, lambda account: get(account, "properties.allowBlobPublicAccess", bool))


def _sa(**properties):
    return {"id": SA_ID, "name": "logs", "properties": properties}


for _slug, _good, _bad in (("activity_log_storage_cmk", {"encryption": {"keySource": "Microsoft.Keyvault"}},
                            {"encryption": {"keySource": "Microsoft.Storage"}}),
                           ("activity_log_storage_private", {"allowBlobPublicAccess": False}, {"allowBlobPublicAccess": True})):
    CASES[cid(_slug)] = {
        "pass": {"scope": SUB}, "fail": {"scope": SUB},
        "pass_index": scope_index({"subscription_diagnostic_setting": [_sub_setting(ALL_CATS, SA_ID)], "storage_account": [_sa(**_good)]}),
        "fail_index": scope_index({"subscription_diagnostic_setting": [_sub_setting(ALL_CATS, SA_ID)], "storage_account": [_sa(**_bad)]})}


def _container(item, name):
    for container in list_of_objects(get(item, "blobContainers", list)):
        if get(container, "name", str) == name:
            return container
    return None


def insights_container_checks(container_name, label):
    slug = "insights_%s_container_byok" % label

    @claude(slug, "storage_account", "Storage account holding %s is encrypted with a customer-managed key" % container_name,
            control="SC-28", remediation="Configure the storage account that holds the %s container with a Key Vault "
                                         "customer-managed key (encryption.keySource=Microsoft.Keyvault)." % container_name)
    def byok(item, index):
        if _container(item, container_name) is None:
            return "NOT_APPLICABLE", {"reason": "account holds no %s container" % container_name}
        verdict = _cmk_fails(item)
        if verdict is None:
            return unknown("unrecognized encryption key source")
        return result(verdict, key_source=get(item, "properties.encryption.keySource", str))
    byok.__name__ = "claude_" + slug
    holder = {"blobContainers": [{"name": container_name, "properties": {"publicAccess": "None"}}]}
    CASES[cid(slug)] = {"pass": {**holder, "properties": {"encryption": {"keySource": "Microsoft.Keyvault"}}},
                        "fail": {**holder, "properties": {"encryption": {"keySource": "Microsoft.Storage"}}}}

    slug2 = "insights_%s_container_private" % label

    @claude(slug2, "storage_account", "%s container is not publicly accessible" % container_name, severity="high", control="AC-3",
            remediation="Set the %s container public access level to Private (None) and allowBlobPublicAccess=false on the "
                        "storage account." % container_name)
    def private(item, index):
        container = _container(item, container_name)
        if container is None:
            return "NOT_APPLICABLE", {"reason": "account holds no %s container" % container_name}
        if optional(get(item, "properties", dict), "allowBlobPublicAccess", None, bool) is False:
            return result(False, reason="account disallows blob public access")
        access = get(container, "properties.publicAccess", str)
        if access not in ("None", "Container", "Blob"):
            return unknown("unrecognized container public access", public_access=access)
        return result(access != "None", public_access=access)
    private.__name__ = "claude_" + slug2
    CASES[cid(slug2)] = {"pass": {"properties": {}, "blobContainers": [{"name": container_name, "properties": {"publicAccess": "None"}}]},
                         "fail": {"properties": {}, "blobContainers": [{"name": container_name, "properties": {"publicAccess": "Container"}}]}}


insights_container_checks("insights-activity-logs", "activity_logs")
insights_container_checks("insights-operational-logs", "operational_logs")


# --- Log Analytics, Logic Apps, Machine Learning --------------------------------------------------------

@claude("log_analytics_public_ingestion_query_disabled", "log_analytics_workspace",
        "Log Analytics workspace blocks public ingestion and query", control="SC-7", category="exposure",
        remediation="Set publicNetworkAccessForIngestion and publicNetworkAccessForQuery to Disabled and use an Azure Monitor "
                    "Private Link Scope (AMPLS) for ingestion and queries.")
def claude_log_analytics_public_ingestion_query_disabled(item, index):
    values = {f: get(item, "properties." + f, str) for f in ("publicNetworkAccessForIngestion", "publicNetworkAccessForQuery")}
    if any(v not in ("Enabled", "Disabled", "SecuredByPerimeter") for v in values.values()):
        return unknown("unrecognized public network access value", **values)
    return result(any(v == "Enabled" for v in values.values()), **values)


CASES[cid("log_analytics_public_ingestion_query_disabled")] = {
    "pass": {"properties": {"publicNetworkAccessForIngestion": "Disabled", "publicNetworkAccessForQuery": "Disabled"}},
    "fail": {"properties": {"publicNetworkAccessForIngestion": "Disabled", "publicNetworkAccessForQuery": "Enabled"}}}

setting("log_analytics_local_auth_disabled", "log_analytics_workspace", "properties.features.disableLocalAuth", True, False,
        "Log Analytics workspace requires Microsoft Entra authentication for ingestion", expected=bool, control="IA-2",
        remediation="Set features.disableLocalAuth=true on the workspace so agents and APIs must ingest with Microsoft Entra ID tokens.")

setting("ml_workspace_cmk", "ml_workspace", "properties.encryption.status", "Enabled", "Disabled",
        "Machine Learning workspace is encrypted with a customer-managed key", control="SC-28",
        remediation="Create the Azure Machine Learning workspace with a customer-managed Key Vault key (encryption cannot be "
                    "added later; redeploy the workspace).")


def _any_enabled_log(item):
    for setting_item in diagnostic_settings(item):
        for log in diagnostic_logs(setting_item):
            if get(log, "enabled", bool):
                return True
    return False


@claude("logic_app_workflow_diagnostic_logging", "logic_app_workflow", "Logic App workflow sends resource logs through a diagnostic setting",
        severity="low", control="AU-12",
        remediation="Add a diagnostic setting on the Logic App workflow that enables WorkflowRuntime logs to Log Analytics or storage.")
def claude_logic_app_workflow_diagnostic_logging(item, index):
    enabled = _any_enabled_log(item)
    return result(not enabled, diagnostic_logging_enabled=enabled)


CASES[cid("logic_app_workflow_diagnostic_logging")] = {"pass": diag_case(diag_log("WorkflowRuntime")),
                                                       "fail": diag_case(diag_log("WorkflowRuntime", enabled=False))}


@claude("nsg_diagnostic_logging", "nsg", "Network security group sends resource logs through a diagnostic setting",
        severity="low", control="AU-12",
        remediation="Add a diagnostic setting on the NSG enabling NetworkSecurityGroupEvent and NetworkSecurityGroupRuleCounter "
                    "(or the allLogs group), e.g. through the built-in DeployIfNotExists policy.")
def claude_nsg_diagnostic_logging(item, index):
    enabled = _any_enabled_log(item)
    return result(not enabled, diagnostic_logging_enabled=enabled)


CASES[cid("nsg_diagnostic_logging")] = {"pass": diag_case(diag_log(group="allLogs")),
                                        "fail": {"diagnosticSettings": []}}


# --- SQL Managed Instance -------------------------------------------------------------------------------

@claude("mssql_managed_instance_tde_cmk", "mssql_managed_instance", "SQL Managed Instance TDE protector is a customer-managed Key Vault key",
        control="SC-28", remediation="Set the managed instance TDE protector to a customer-managed key in Azure Key Vault.")
def claude_mssql_managed_instance_tde_cmk(item, index):
    protectors = list_of_objects(get(item, "encryptionProtectors", list))
    if not protectors:
        return unknown("no encryption protector returned")
    types = [get(p, "properties.serverKeyType", str) for p in protectors]
    for protector, key_type in zip(protectors, types):
        if key_type == "AzureKeyVault" and isinstance(protector["properties"].get("uri"), str) and protector["properties"]["uri"]:
            return result(False, server_key_type=key_type)
    if all(t in ("ServiceManaged", "AzureKeyVault") for t in types):
        return result(True, server_key_types=types)
    return unknown("unrecognized server key type", server_key_types=types)


CASES[cid("mssql_managed_instance_tde_cmk")] = {
    "pass": {"encryptionProtectors": [{"properties": {"serverKeyType": "AzureKeyVault", "uri": "https://v.vault.azure.net/keys/k/1"}}]},
    "fail": {"encryptionProtectors": [{"properties": {"serverKeyType": "ServiceManaged"}}]}}


@claude("mssql_managed_instance_vulnerability_assessment", "mssql_managed_instance",
        "SQL Managed Instance has vulnerability assessment recurring scans enabled", control="RA-5",
        remediation="Enable Microsoft Defender for SQL and configure vulnerability assessment with recurring scans on the managed instance.")
def claude_mssql_managed_instance_vulnerability_assessment(item, index):
    for assessment in list_of_objects(get(item, "vulnerabilityAssessments", list)):
        if get(assessment, "name", str).casefold() == "default" and get(assessment, "properties.recurringScans.isEnabled", bool):
            return result(False, recurring_scans_enabled=True)
    return result(True, recurring_scans_enabled=False, reason="no Default vulnerability assessment with recurring scans enabled")


CASES[cid("mssql_managed_instance_vulnerability_assessment")] = {
    "pass": {"vulnerabilityAssessments": [{"name": "Default", "properties": {"recurringScans": {"isEnabled": True}}}]},
    "fail": {"vulnerabilityAssessments": [{"name": "Default", "properties": {"recurringScans": {"isEnabled": False}}}]}}


# --- MySQL / PostgreSQL flexible servers ----------------------------------------------------------------

ABSENT = object()


def _config(item, name):
    for config in list_of_objects(get(item, "configurations", list)):
        if _ieq(get(config, "name", str), name):
            value = get(config, "properties.value")
            if not isinstance(value, str):
                raise Unavailable("malformed server parameter value: " + name)
            return value
    return ABSENT


def _cfg(name, value):
    return {"name": name, "properties": {"value": value}}


def config_check(slug, kind, name, title, *, good=("on",), bad=("off",), absent="unknown", severity="medium", control="CM-6",
                 remediation):
    @claude(slug, kind, title, severity=severity, control=control, remediation=remediation)
    def evaluate(item, index):
        value = _config(item, name)
        if value is ABSENT:
            if absent == "na":
                return "NOT_APPLICABLE", {"reason": "server parameter not offered by this engine version", "parameter": name}
            return unknown("server parameter not returned", parameter=name)
        if value.lower() in good:
            return result(False, parameter=name, value=value)
        if value.lower() in bad:
            return result(True, parameter=name, value=value)
        return unknown("unrecognized parameter value", parameter=name, value=value)
    evaluate.__name__ = "claude_" + slug
    CASES[cid(slug)] = {"pass": {"configurations": [_cfg(name, good[0].upper() if kind.startswith("mysql") else good[0])]},
                        "fail": {"configurations": [_cfg(name, bad[0].upper() if kind.startswith("mysql") else bad[0])]}}
    return evaluate


MYSQL = "mysql_flexible_server"
PG = "postgresql_flexible_server"

config_check("mysql_flexible_audit_log_enabled", MYSQL, "audit_log_enabled", "MySQL flexible server enables the audit log",
             control="AU-12", remediation="Set the audit_log_enabled server parameter to ON and route MySqlAuditLogs to Log Analytics.")
config_check("mysql_flexible_secure_transport", MYSQL, "require_secure_transport", "MySQL flexible server requires TLS connections",
             severity="high", control="SC-8", remediation="Set the require_secure_transport server parameter to ON.")


@claude("mysql_flexible_audit_log_connection", MYSQL, "MySQL flexible server audit log records CONNECTION events", control="AU-12",
        remediation="Set audit_log_events to include CONNECTION (and audit_log_enabled=ON).")
def claude_mysql_flexible_audit_log_connection(item, index):
    value = _config(item, "audit_log_events")
    if value is ABSENT:
        return unknown("audit_log_events parameter not returned")
    events = [e.strip().upper() for e in value.split(",")]
    return result("CONNECTION" not in events, audit_log_events=value)


CASES[cid("mysql_flexible_audit_log_connection")] = {"pass": {"configurations": [_cfg("audit_log_events", "CONNECTION,DDL")]},
                                                     "fail": {"configurations": [_cfg("audit_log_events", "DDL,DML")]}}


@claude("mysql_flexible_min_tls_12", MYSQL, "MySQL flexible server allows only TLS 1.2 or later", severity="high", control="SC-8",
        remediation="Set the tls_version server parameter to TLSv1.2 (and TLSv1.3 where supported); remove TLSv1 and TLSv1.1.")
def claude_mysql_flexible_min_tls_12(item, index):
    value = _config(item, "tls_version")
    if value is ABSENT:
        return unknown("tls_version parameter not returned")
    versions = [v.strip() for v in value.split(",") if v.strip()]
    if any(v in ("TLSv1", "TLSv1.0", "TLSv1.1") for v in versions):
        return result(True, tls_version=value)
    if versions and all(v in ("TLSv1.2", "TLSv1.3") for v in versions):
        return result(False, tls_version=value)
    return unknown("unrecognized tls_version", tls_version=value)


CASES[cid("mysql_flexible_min_tls_12")] = {"pass": {"configurations": [_cfg("tls_version", "TLSv1.2")]},
                                           "fail": {"configurations": [_cfg("tls_version", "TLSv1.1,TLSv1.2")]}}

for _kind, _engine in ((MYSQL, "mysql"), (PG, "postgresql")):
    setting(_engine + "_flexible_geo_redundant_backup", _kind, "properties.backup.geoRedundantBackup", "Enabled", "Disabled",
            ("MySQL" if _engine == "mysql" else "PostgreSQL") + " flexible server enables geo-redundant backup", control="CP-9",
            severity="low", remediation="Geo-redundant backup can only be chosen at server creation; restore or recreate the server "
                                        "with backup.geoRedundantBackup=Enabled in a region pair that supports it.")

    def _ha(slug, kind, label):
        @claude(slug, kind, label + " flexible server enables high availability", severity="low", control="CP-10",
                remediation="Enable zone-redundant (or same-zone) high availability on a General Purpose or Memory Optimized server.")
        def evaluate(item, index):
            if get(item, "sku.tier", str) == "Burstable":
                return "NOT_APPLICABLE", {"reason": "Burstable tier does not support high availability"}
            mode = get(item, "properties.highAvailability.mode", str)
            if mode not in ("Disabled", "ZoneRedundant", "SameZone"):
                return unknown("unrecognized high availability mode", mode=mode)
            return result(mode == "Disabled", mode=mode)
        evaluate.__name__ = "claude_" + slug
        CASES[cid(slug)] = {"pass": {"sku": {"tier": "GeneralPurpose"}, "properties": {"highAvailability": {"mode": "ZoneRedundant"}}},
                            "fail": {"sku": {"tier": "GeneralPurpose"}, "properties": {"highAvailability": {"mode": "Disabled"}}},
                            "not_applicable": {"sku": {"tier": "Burstable"}, "properties": {"highAvailability": {"mode": "Disabled"}}}}
    _ha(_engine + "_flexible_high_availability", _kind, "MySQL" if _engine == "mysql" else "PostgreSQL")

config_check("postgresql_flexible_secure_transport", PG, "require_secure_transport", "PostgreSQL flexible server requires TLS connections",
             severity="high", control="SC-8", remediation="Set the require_secure_transport server parameter to on.")
config_check("postgresql_flexible_connection_throttling", PG, "connection_throttle.enable",
             "PostgreSQL flexible server enables connection throttling", absent="na", control="SC-5",
             remediation="Set connection_throttle.enable to on (parameter exists on PostgreSQL versions that still offer it).")
config_check("postgresql_flexible_log_checkpoints", PG, "log_checkpoints", "PostgreSQL flexible server logs checkpoints", severity="low",
             control="AU-12", remediation="Set the log_checkpoints server parameter to on.")
config_check("postgresql_flexible_log_connections", PG, "log_connections", "PostgreSQL flexible server logs connections", control="AU-12",
             remediation="Set the log_connections server parameter to on.")
config_check("postgresql_flexible_log_disconnections", PG, "log_disconnections", "PostgreSQL flexible server logs disconnections",
             control="AU-12", remediation="Set the log_disconnections server parameter to on.")


@claude("postgresql_flexible_log_retention_over_3_days", PG, "PostgreSQL flexible server retains server logs for more than 3 days",
        control="AU-11", remediation="Set logfiles.retention_days to 4-7 days and export logs to Log Analytics for longer retention.")
def claude_postgresql_flexible_log_retention_over_3_days(item, index):
    value = _config(item, "logfiles.retention_days")
    if value is ABSENT:
        return unknown("logfiles.retention_days parameter not returned")
    try:
        days = int(value)
    except ValueError:
        return unknown("non-integer logfiles.retention_days", value=value)
    return result(days <= 3, retention_days=days)


CASES[cid("postgresql_flexible_log_retention_over_3_days")] = {"pass": {"configurations": [_cfg("logfiles.retention_days", "7")]},
                                                               "fail": {"configurations": [_cfg("logfiles.retention_days", "3")]}}


def _firewall(item):
    rules = list_of_objects(get(item, "firewallRules", list))
    return [(get(r, "properties.startIpAddress", str), get(r, "properties.endIpAddress", str), r.get("name")) for r in rules]


def _public_disabled(item):
    return optional(get(item, "properties", dict), "network", {}, dict).get("publicNetworkAccess") == "Disabled"


@claude("postgresql_flexible_no_azure_services_rule", PG, "PostgreSQL flexible server does not allow access from all Azure services",
        severity="high", control="SC-7", category="exposure",
        remediation="Delete the 0.0.0.0-0.0.0.0 firewall rule (portal: 'Allow public access from any Azure service') and allow "
                    "only specific client ranges or use private access.")
def claude_postgresql_flexible_no_azure_services_rule(item, index):
    if _public_disabled(item):
        return result(False, reason="public network access disabled; firewall rules are inert")
    hits = [n for start, end, n in _firewall(item) if start == "0.0.0.0" and end == "0.0.0.0"]
    return result(bool(hits), rules=hits)


@claude("postgresql_flexible_no_zero_address_rule", PG, "PostgreSQL flexible server has no firewall rule starting or ending at 0.0.0.0",
        severity="high", control="SC-7", category="exposure",
        remediation="Delete firewall rules whose start or end address is 0.0.0.0 (Azure-services or whole-internet ranges) and allow "
                    "only specific client ranges or use private access.")
def claude_postgresql_flexible_no_zero_address_rule(item, index):
    if _public_disabled(item):
        return result(False, reason="public network access disabled; firewall rules are inert")
    hits = [n for start, end, n in _firewall(item) if start == "0.0.0.0" or end == "0.0.0.0"]
    return result(bool(hits), rules=hits)


def _fw(start, end):
    return {"name": "r", "properties": {"startIpAddress": start, "endIpAddress": end}}


CASES[cid("postgresql_flexible_no_azure_services_rule")] = {
    "pass": {"properties": {}, "firewallRules": [_fw("203.0.113.1", "203.0.113.9")]},
    "fail": {"properties": {}, "firewallRules": [_fw("0.0.0.0", "0.0.0.0")]}}
CASES[cid("postgresql_flexible_no_zero_address_rule")] = {
    "pass": {"properties": {}, "firewallRules": [_fw("203.0.113.1", "203.0.113.9")]},
    "fail": {"properties": {}, "firewallRules": [_fw("0.0.0.0", "255.255.255.255")]}}


@claude("postgresql_flexible_entra_authentication", PG, "PostgreSQL flexible server enables Microsoft Entra authentication with an admin",
        control="IA-2", remediation="Enable Microsoft Entra authentication (authConfig.activeDirectoryAuth=Enabled) and add at least "
                                    "one Microsoft Entra administrator.")
def claude_postgresql_flexible_entra_authentication(item, index):
    mode = get(item, "properties.authConfig.activeDirectoryAuth", str)
    if mode == "Disabled":
        return result(True, active_directory_auth=mode)
    if mode != "Enabled":
        return unknown("unrecognized activeDirectoryAuth", active_directory_auth=mode)
    admins = list_of_objects(get(item, "administrators", list))
    return result(not admins, active_directory_auth=mode, administrators=len(admins))


CASES[cid("postgresql_flexible_entra_authentication")] = {
    "pass": {"properties": {"authConfig": {"activeDirectoryAuth": "Enabled"}}, "administrators": [{"name": "oid"}]},
    "fail": {"properties": {"authConfig": {"activeDirectoryAuth": "Enabled"}}, "administrators": []}}


# --- Network resources ----------------------------------------------------------------------------------

@claude("bastion_host_exists", "bastion_host", "Subscription has at least one Azure Bastion host", severity="low", control="AC-17",
        target="scope", dependencies=["bastion_host"],
        remediation="Deploy Azure Bastion in the virtual networks that host VMs and remove public RDP/SSH exposure.")
def claude_bastion_host_exists(item, index):
    get(item, "scope", str)
    hosts = scoped(index, "bastion_host")
    return result(not hosts, bastion_hosts=len(hosts))


CASES[cid("bastion_host_exists")] = {"pass": {"scope": SUB}, "fail": {"scope": SUB},
                                     "pass_index": scope_index({"bastion_host": [{"id": SUB + "/b", "name": "b"}]}),
                                     "fail_index": scope_index({"bastion_host": []})}


@claude("nic_no_public_ip", "nic", "Network interface has no public IP address", severity="medium", control="SC-7", category="exposure",
        remediation="Dissociate the public IP from the NIC ip configuration; reach the workload through Bastion, a load balancer or "
                    "application gateway instead.")
def claude_nic_no_public_ip(item, index):
    attached = []
    for config in list_of_objects(get(item, "properties.ipConfigurations", list)):
        public = optional(get(config, "properties", dict), "publicIPAddress", None)
        if public is not None:
            attached.append(get(public, "id", str))
    return result(bool(attached), public_ips=attached)


CASES[cid("nic_no_public_ip")] = {
    "pass": {"properties": {"ipConfigurations": [{"properties": {"privateIPAddress": "10.0.0.4"}}]}},
    "fail": {"properties": {"ipConfigurations": [{"properties": {"publicIPAddress": {"id": SUB + "/pip"}}}]}}}


@claude("vnet_peering_connected", "vnet", "Virtual network has no disconnected peerings", severity="low", control="CM-6",
        remediation="Delete and recreate (or resync) peerings in Disconnected state on both virtual networks.")
def claude_vnet_peering_connected(item, index):
    peerings = list_of_objects(optional(get(item, "properties", dict), "virtualNetworkPeerings", [], list))
    states = [get(p, "properties.peeringState", str) for p in peerings]
    return result("Disconnected" in states, peering_states=states)


CASES[cid("vnet_peering_connected")] = {
    "pass": {"properties": {"virtualNetworkPeerings": [{"properties": {"peeringState": "Connected"}}]}},
    "fail": {"properties": {"virtualNetworkPeerings": [{"properties": {"peeringState": "Disconnected"}}]}}}


@claude("nsg_associated_with_subnet", "nsg", "Network security group is associated with at least one subnet", severity="low",
        control="SC-7", remediation="Associate the NSG with the subnets it is meant to protect, or delete unused NSGs.")
def claude_nsg_associated_with_subnet(item, index):
    subnets = optional(get(item, "properties", dict), "subnets", [], list)
    return result(not subnets, subnets=len(subnets))


CASES[cid("nsg_associated_with_subnet")] = {"pass": {"properties": {"subnets": [{"id": SUB + "/sn"}]}}, "fail": {"properties": {}}}

EXCLUDED_SUBNETS = ("GatewaySubnet", "AzureFirewallSubnet", "AzureFirewallManagementSubnet", "AzureBastionSubnet", "RouteServerSubnet")


def _subnet_nsg(item):
    nsg = optional(get(item, "properties", dict), "networkSecurityGroup", None)
    return None if nsg is None else get(nsg, "id", str)


@claude("subnet_nsg_associated", "subnet", "Subnet has a network security group", severity="high", control="SC-7",
        remediation="Associate an NSG with every workload subnet (Azure-managed subnets such as GatewaySubnet/AzureFirewallSubnet "
                    "are excluded).")
def claude_subnet_nsg_associated(item, index):
    name = get(item, "name", str)
    if name in EXCLUDED_SUBNETS:
        return "NOT_APPLICABLE", {"reason": "Azure-managed subnet must not carry a custom NSG", "subnet": name}
    nsg = _subnet_nsg(item)
    return result(nsg is None, nsg=nsg)


CASES[cid("subnet_nsg_associated")] = {"pass": {"name": "app", "properties": {"networkSecurityGroup": {"id": SUB + "/nsg"}}},
                                       "fail": {"name": "app", "properties": {}}}


@claude("gateway_subnet_no_nsg", "subnet", "GatewaySubnet has no network security group", severity="medium", control="CM-6",
        remediation="Remove the NSG from GatewaySubnet; NSGs on the gateway subnet are unsupported and can break the gateway.")
def claude_gateway_subnet_no_nsg(item, index):
    if get(item, "name", str) != "GatewaySubnet":
        return "NOT_APPLICABLE", {"reason": "not a GatewaySubnet"}
    nsg = _subnet_nsg(item)
    return result(nsg is not None, nsg=nsg)


CASES[cid("gateway_subnet_no_nsg")] = {"pass": {"name": "GatewaySubnet", "properties": {}},
                                       "fail": {"name": "GatewaySubnet", "properties": {"networkSecurityGroup": {"id": SUB + "/nsg"}}}}


@claude("vnet_gateway_entra_only", "virtual_network_gateway", "VPN gateway point-to-site uses only Microsoft Entra authentication",
        control="IA-2", remediation="Configure the point-to-site vpnAuthenticationTypes to AAD only (Microsoft Entra ID authentication).")
def claude_vnet_gateway_entra_only(item, index):
    properties = get(item, "properties", dict)
    if get(item, "properties.gatewayType", str) != "Vpn":
        return "NOT_APPLICABLE", {"reason": "not a VPN gateway"}
    config = optional(properties, "vpnClientConfiguration", None)
    if config is None:
        return "NOT_APPLICABLE", {"reason": "no point-to-site configuration"}
    types = get(config, "vpnAuthenticationTypes", list) if isinstance(config, dict) else None
    if types is None:
        raise Unavailable("malformed vpnClientConfiguration")
    if not types:
        return "NOT_APPLICABLE", {"reason": "no point-to-site authentication types"}
    return result(types != ["AAD"], vpn_authentication_types=types)


CASES[cid("vnet_gateway_entra_only")] = {
    "pass": {"properties": {"gatewayType": "Vpn", "vpnClientConfiguration": {"vpnAuthenticationTypes": ["AAD"]}}},
    "fail": {"properties": {"gatewayType": "Vpn", "vpnClientConfiguration": {"vpnAuthenticationTypes": ["AAD", "Certificate"]}}}}

setting("vnet_gateway_no_basic_sku", "virtual_network_gateway", "properties.sku.name",
        ("VpnGw1", "VpnGw2", "VpnGw3", "VpnGw4", "VpnGw5", "VpnGw1AZ", "VpnGw2AZ", "VpnGw3AZ", "VpnGw4AZ", "VpnGw5AZ", "Standard",
         "HighPerformance", "UltraPerformance", "ErGw1AZ", "ErGw2AZ", "ErGw3AZ", "ErGwScale"), "Basic",
        "Virtual network gateway does not use the Basic SKU", control="CM-6",
        remediation="Migrate the gateway from Basic to a VpnGw*/ErGw* SKU (Basic lacks IKEv2/RADIUS P2S, BGP and zone redundancy).")


@claude("network_watcher_in_vnet_region", "vnet", "Network Watcher exists in the region of the virtual network", control="SI-4",
        dependencies=["vnet", "network_watcher"],
        remediation="Enable Network Watcher in every region that hosts virtual networks (it is created in NetworkWatcherRG by default).")
def claude_network_watcher_in_vnet_region(item, index):
    region = _norm(get(item, "location", str))
    watchers = [_norm(get(w, "location", str)) for w in scoped(index, "network_watcher")]
    return result(region not in watchers, region=region)


def _watcher(location="eastus", flow_logs=None):
    data = {"id": SUB + "/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/w", "location": location}
    if flow_logs is not None:
        data["flowLogs"] = flow_logs
    return data


CASES[cid("network_watcher_in_vnet_region")] = {"pass": {"location": "East US"}, "fail": {"location": "westeurope"},
                                                "pass_index": scope_index({"network_watcher": [_watcher()]}),
                                                "fail_index": scope_index({"network_watcher": [_watcher()]})}


def _analytics_enabled(flow_log):
    analytics = optional(get(flow_log, "properties", dict), "flowAnalyticsConfiguration", {}, dict)
    config = optional(analytics, "networkWatcherFlowAnalyticsConfiguration", {}, dict)
    return optional(config, "enabled", False, bool), config


def _flow(enabled=True, analytics=True, interval=60, days=90):
    return {"name": "fl", "properties": {"enabled": enabled, "targetResourceId": SUB + "/nsg",
                                         "retentionPolicy": {"days": days, "enabled": True},
                                         "flowAnalyticsConfiguration": {"networkWatcherFlowAnalyticsConfiguration": {
                                             "enabled": analytics, "workspaceId": "w", "trafficAnalyticsInterval": interval}}}}


setting("flow_log_enabled", "flow_log", "properties.enabled", True, False, "Network Watcher flow log is enabled", expected=bool,
        control="AU-12", remediation="Enable the flow log (prefer virtual network flow logs) and send it to storage and Traffic Analytics.")


@claude("flow_log_traffic_analytics", "flow_log", "Flow log is enabled with Traffic Analytics at a 10-60 minute interval", control="SI-4",
        remediation="Enable Traffic Analytics on the flow log with a Log Analytics workspace and a 10 or 60 minute processing interval.")
def claude_flow_log_traffic_analytics(item, index):
    if not get(item, "properties.enabled", bool):
        return result(True, reason="flow log disabled")
    enabled, config = _analytics_enabled(item)
    if not enabled:
        return result(True, reason="traffic analytics disabled")
    interval = get(config, "trafficAnalyticsInterval", int)
    return result(not 10 <= interval <= 60, traffic_analytics_interval=interval)


CASES[cid("flow_log_traffic_analytics")] = {"pass": _flow(), "fail": _flow(analytics=False)}


@claude("network_watcher_flow_logs_traffic_analytics", "network_watcher", "Network Watcher has flow logs, all enabled with Traffic Analytics",
        severity="high", control="SI-4",
        remediation="Create (virtual network) flow logs for the region's networks, keep them enabled and enable Traffic Analytics.")
def claude_network_watcher_flow_logs_traffic_analytics(item, index):
    logs = list_of_objects(get(item, "flowLogs", list))
    if not logs:
        return result(True, reason="no flow logs configured")
    bad = [f.get("name") for f in logs if not get(f, "properties.enabled", bool) or not _analytics_enabled(f)[0]]
    return result(bool(bad), flow_logs=bad)


CASES[cid("network_watcher_flow_logs_traffic_analytics")] = {"pass": _watcher(flow_logs=[_flow()]), "fail": _watcher(flow_logs=[])}


@claude("network_watcher_flow_logs_retention_90", "network_watcher", "Network Watcher flow logs are enabled and retained at least 90 days",
        control="AU-11", remediation="Keep flow logs enabled with retentionPolicy.days >= 90 (or 0 for indefinite retention).")
def claude_network_watcher_flow_logs_retention_90(item, index):
    logs = list_of_objects(get(item, "flowLogs", list))
    if not logs:
        return result(True, reason="no flow logs configured")
    bad = []
    for flow_log in logs:
        days = get(flow_log, "properties.retentionPolicy.days", int)
        if days < 0:
            raise Unavailable("flow log retention days cannot be negative")
        if not get(flow_log, "properties.enabled", bool) or 0 < days < 90:
            bad.append({"flow_log": flow_log.get("name"), "retention_days": days})
    return result(bool(bad), flow_logs=bad)


CASES[cid("network_watcher_flow_logs_retention_90")] = {"pass": _watcher(flow_logs=[_flow(days=0)]),
                                                        "fail": _watcher(flow_logs=[_flow(days=30)])}


# --- Azure Policy ---------------------------------------------------------------------------------------

@claude("defender_default_policy_enforced", "policy_assignment", "Microsoft Defender for Cloud default initiative is enforced",
        control="CA-7", target="scope", dependencies=["policy_assignment"],
        remediation="Set the SecurityCenterBuiltIn (Microsoft cloud security benchmark) assignment enforcementMode to Default.")
def claude_defender_default_policy_enforced(item, index):
    get(item, "scope", str)
    rows = subscription_builtin_assignments(index, get(item, "scope", str))
    if not rows:
        return "NOT_APPLICABLE", {"reason": "no SecurityCenterBuiltIn assignment visible in scope"}
    modes = [get(r, "properties.enforcementMode", str) for r in rows]
    if any(m not in ("Default", "DoNotEnforce") for m in modes):
        return unknown("unrecognized enforcement mode", modes=modes)
    return result("DoNotEnforce" in modes, modes=modes)


def _assignment(mode):
    return {"id": SUB + "/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn", "name": "SecurityCenterBuiltIn",
            "properties": {"scope": SUB, "enforcementMode": mode}}


CASES[cid("defender_default_policy_enforced")] = {"pass": {"scope": SUB}, "fail": {"scope": SUB},
                                                  "pass_index": scope_index({"policy_assignment": [_assignment("Default")]}),
                                                  "fail_index": scope_index({"policy_assignment": [_assignment("DoNotEnforce")]})}


# --- Recovery Services vaults ---------------------------------------------------------------------------

RECOVERY = "recovery_vault"


@claude("recovery_vault_managed_identity", RECOVERY, "Recovery Services vault has a managed identity", severity="low", control="IA-9",
        remediation="Enable a system-assigned or user-assigned managed identity on the vault (required for CMK and private endpoints).")
def claude_recovery_vault_managed_identity(item, index):
    get(item, "properties", dict)
    identity = optional(item, "identity", None)
    if identity is None:
        return result(True, identity=None)
    kind = get(identity, "type", str)
    if kind.replace(" ", "") in ("SystemAssigned", "UserAssigned", "SystemAssigned,UserAssigned"):
        return result(False, identity_type=kind)
    if kind == "None":
        return result(True, identity_type=kind)
    return unknown("unrecognized identity type", identity_type=kind)


CASES[cid("recovery_vault_managed_identity")] = {"pass": {"properties": {}, "identity": {"type": "SystemAssigned"}},
                                                 "fail": {"properties": {}, "identity": {"type": "None"}}}

setting("recovery_vault_private_endpoint_site_recovery", RECOVERY, "properties.privateEndpointStateForSiteRecovery", "Enabled", "None",
        "Recovery Services vault uses private endpoints for Site Recovery", severity="low", control="SC-7",
        remediation="Create a private endpoint for the vault's Site Recovery sub-resource.")
setting("recovery_vault_private_endpoint_backup", RECOVERY, "properties.privateEndpointStateForBackup", "Enabled", "None",
        "Recovery Services vault uses private endpoints for Backup", severity="low", control="SC-7",
        remediation="Create a private endpoint for the vault's AzureBackup sub-resource.")


@claude("recovery_vault_backup_retention_30_days", RECOVERY, "Recovery Services vault daily backup policies retain at least 30 days",
        control="CP-9", remediation="Set retentionPolicy.dailySchedule.retentionDuration.count to 30 days or more on daily backup policies.")
def claude_recovery_vault_backup_retention_30_days(item, index):
    policies = list_of_objects(get(item, "backupPolicies", list))
    if not policies:
        return result(True, reason="no backup policies configured")
    evaluated, short, unresolved = 0, [], []
    for policy in policies:
        retention = optional(get(policy, "properties", dict), "retentionPolicy", None)
        daily = retention.get("dailySchedule") if isinstance(retention, dict) else None
        if daily is None:
            continue
        duration = get(daily, "retentionDuration", dict)
        count = get(duration, "count", int)
        unit = get(duration, "durationType", str)
        if count <= 0 or unit not in ("Days", "Weeks", "Months", "Years"):
            return unknown("malformed or unrecognized native backup retention duration", policy=policy.get("name"))
        # Months are calendar durations: one month can be shorter than 30 days.
        if unit == "Months" and count == 1:
            unresolved.append(policy.get("name"))
            continue
        minimum_days = count * {"Days": 1, "Weeks": 7, "Months": 28, "Years": 365}[unit]
        evaluated += 1
        if minimum_days < 30:
            short.append({"policy": policy.get("name"), "count": count, "duration_type": unit})
    if short:
        return result(True, short_policies=short)
    if unresolved:
        return unknown("calendar month retention cannot establish the 30-day threshold", policies=unresolved)
    if not evaluated:
        return "NOT_APPLICABLE", {"reason": "no daily-schedule retention policies"}
    return result(False, evaluated_policies=evaluated, semantics="declared backup policy retention only; restore and delivery are separate")

def _policy(days):
    return {"name": "DefaultPolicy", "properties": {"retentionPolicy": {"dailySchedule": {"retentionDuration": {"count": days}}}}}


CASES[cid("recovery_vault_backup_retention_30_days")] = {"pass": {"backupPolicies": [_policy(30)]}, "fail": {"backupPolicies": [_policy(7)]}}


@claude("recovery_vault_has_protected_items", RECOVERY, "Recovery Services vault protects at least one item", severity="low",
        control="CP-9", remediation="Configure backup for the workloads the vault is meant to protect, or delete the unused vault.")
def claude_recovery_vault_has_protected_items(item, index):
    items = list_of_objects(get(item, "backupProtectedItems", list))
    return result(not items, protected_items=len(items))


CASES[cid("recovery_vault_has_protected_items")] = {"pass": {"backupProtectedItems": [{"name": "vm"}]}, "fail": {"backupProtectedItems": []}}


NETWORK_CHECK_IDS = CHECK_IDS[_START:]
