"""Azure NSG internet-ingress *declaration* checks (CIS Azure 6.1/6.2/6.4/6.6 audit semantics).

The pinned turbot ``network_security_group_*_access_restricted`` queries join their risky-rule CTE to
NSGs by name only (NSG names are unique per resource group, so a safe NSG inherits another group's
alarm), the UDP query omits exact single-port declarations, and the HTTP(S) query requires one range to
cover both 80 and 443. The existing ``azure.claude.nsg_internet_*`` natives are priority-aware
(a higher-priority internet Deny shadows the Allow), which is an effective-reachability pass condition,
not the CIS audit procedure ("no Allow rule exists with ...").

These natives implement the audited declaration requirement per full-ARM-ID NSG item: FAIL when any
custom inbound Allow rule has an internet source (``*``, ``0.0.0.0``, ``0.0.0.0/0``, ``Internet``,
``any``, ``<nw>/0``, ``/0``) and a destination port specification covering a listed port. Rule
priority and Deny rules are deliberately ignored, exactly as in the audit. Protocol ``*`` (Any) is
treated as allowing TCP/UDP, which only removes an upstream false pass. Malformed rule facts are UNKNOWN.
"""
from __future__ import annotations

from . import register, result
from .claude_azure_common import INTERNET_SOURCES, internet_allow_rules, nsg_rule, nsg_case, nsg_rules, port_range
from .fixtures import CASES

CHECK_IDS = []
SOURCE_QUERIES = {}
# Prowler NSG checks are the same declaration audits (no priority/Deny evaluation); their upstream defects are
# that only the singular sourceAddressPrefix/destinationPortRange fields are read and port '*' is not matched.
PROWLER_SOURCES = {
    "prowler.azure.network_rdp_internet_access_restricted": "azure.gap.nsg_declared_internet_rdp",
    "prowler.azure.network_ssh_internet_access_restricted": "azure.gap.nsg_declared_internet_ssh",
    "prowler.azure.network_http_internet_access_restricted": "azure.gap.nsg_declared_internet_http",
    "prowler.azure.network_udp_internet_access_restricted": "azure.gap.nsg_declared_internet_udp_any",
}
# Priority-aware effective-reachability natives (a higher-priority internet Deny shadows the Allow). They stay as
# Exposure checks but carry no compliance-framework labels: every compliance/Prowler declaration-audit row for these
# controls targets the azure.gap.nsg_declared_internet_* natives instead.
EXPOSURE_ONLY_NATIVES = tuple("azure.claude.nsg_internet_" + s for s in
                              ("rdp", "ssh", "remote_access", "http", "http_https", "udp_services", "udp_any"))
REMEDIATION = ("Remove or narrow every inbound Allow rule that admits {what} from Internet/'*'/0.0.0.0/0 (a higher-priority "
               "Deny does not satisfy the CIS audit); allow only specific trusted prefixes or use Azure Bastion/VPN/WAF fronting.")

# query -> (slug, protocols, ports, title, what, severity, fixture (protocol, port))
SPECS = {
    "network_security_group_rdp_access_restricted": (
        "nsg_declared_internet_rdp", ("tcp", "*"), [3389], "NSG declares no internet-source inbound Allow rule for RDP (TCP 3389)",
        "TCP 3389", "high", ("Tcp", "3000-4000")),
    "network_security_group_ssh_access_restricted": (
        "nsg_declared_internet_ssh", ("tcp", "*"), [22], "NSG declares no internet-source inbound Allow rule for SSH (TCP 22)",
        "TCP 22", "high", ("*", "22")),
    "network_security_group_https_access_restricted": (
        "nsg_declared_internet_http", ("tcp", "*"), [80], "NSG declares no internet-source inbound Allow rule for HTTP (TCP 80)",
        "TCP 80", "medium", ("Tcp", "80")),
    "network_security_group_https_port_80_443_access_restricted": (
        "nsg_declared_internet_http_https", ("tcp", "*"), [80, 443],
        "NSG declares no internet-source inbound Allow rule for HTTP or HTTPS (TCP 80/443)", "TCP 80 or 443", "medium", ("Tcp", "80-81")),
    "network_security_group_remote_access_restricted": (
        "nsg_declared_internet_remote_access", ("tcp", "*"), [22, 3389],
        "NSG declares no internet-source inbound Allow rule for SSH or RDP (TCP 22/3389)", "TCP 22 or 3389", "high", ("Tcp", "3000-4000")),
    "network_security_group_udp_service_restricted": (
        "nsg_declared_internet_udp_services", ("udp", "*"), [53, 123, 161, 389, 1900],
        "NSG declares no internet-source inbound Allow rule for UDP 53/123/161/389/1900", "UDP 53/123/161/389/1900", "high",
        ("Udp", "53")),
    # Prowler-only control (no turbot query): any UDP port. ports=None means every destination port.
    "prowler:network_udp_internet_access_restricted": (
        "nsg_declared_internet_udp_any", ("udp", "*"), None, "NSG declares no internet-source inbound Allow rule for UDP on any port",
        "UDP (any port)", "high", ("Udp", "40000")),
}


def _declared_any_port(item, protocols):
    hits = []
    for rule in nsg_rules(item):
        if rule["direction"] != "Inbound" or rule["access"] != "Allow" or rule["protocol"].lower() not in protocols:
            continue
        if not any(source in INTERNET_SOURCES for source in rule["sources"]):
            continue
        if [port_range(spec) for spec in rule["ports"]]:  # every port spec is validated; any declared port matches
            hits.append({k: rule[k] for k in ("name", "priority", "protocol", "sources", "ports")})
    return hits


def _register(query, spec):
    slug, protocols, ports, title, what, severity, (fixture_protocol, fixture_port) = spec
    cid = "azure.gap." + slug
    CHECK_IDS.append(cid)
    if not query.startswith("prowler:"):
        SOURCE_QUERIES[query] = cid

    @register(cid, "azure", "exposure", "nsg", title, severity, "SC-7", REMEDIATION.format(what=what), dependencies=["nsg"])
    def evaluate(item, index):
        if ports is None:
            hits = _declared_any_port(item, protocols)
        else:
            hits = internet_allow_rules(item, direction="Inbound", protocols=protocols, ports=ports)
        return result(bool(hits), declared_internet_allow_rules=hits[:25], ports=ports or "any",
                      semantics="Declaration audit: any custom inbound internet Allow rule; priority/Deny shadowing ignored")
    evaluate.__name__ = "gap_" + slug
    shadowing_deny = nsg_rule("deny-internet", "*", "Internet", "*", access="Deny")
    CASES[cid] = {
        "pass": nsg_case(shadowing_deny, nsg_rule("trusted", fixture_protocol, "10.0.0.0/8", fixture_port)),
        "fail": nsg_case(shadowing_deny, nsg_rule("open", fixture_protocol, "Internet", fixture_port)),
    }


for _query, _spec in SPECS.items():
    _register(_query, _spec)
