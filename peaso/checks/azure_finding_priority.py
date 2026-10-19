"""Finding-level priority for known Azure NSG evidence shapes, without detection changes."""
import re


_NSG_CHECKS = frozenset(('azure.claude.nsg_internet_all_ports_tcp_udp', 'azure.claude.nsg_internet_common_ports', 'azure.claude.nsg_internet_http', 'azure.claude.nsg_internet_http_https', 'azure.claude.nsg_internet_icmp', 'azure.claude.nsg_internet_rdp', 'azure.claude.nsg_internet_remote_access', 'azure.claude.nsg_internet_ssh', 'azure.claude.nsg_internet_tcp_135', 'azure.claude.nsg_internet_tcp_1433', 'azure.claude.nsg_internet_tcp_20', 'azure.claude.nsg_internet_tcp_21', 'azure.claude.nsg_internet_tcp_23', 'azure.claude.nsg_internet_tcp_25', 'azure.claude.nsg_internet_tcp_3306', 'azure.claude.nsg_internet_tcp_4333', 'azure.claude.nsg_internet_tcp_445', 'azure.claude.nsg_internet_tcp_53', 'azure.claude.nsg_internet_tcp_5432', 'azure.claude.nsg_internet_tcp_5500', 'azure.claude.nsg_internet_tcp_5900', 'azure.claude.nsg_internet_udp_137', 'azure.claude.nsg_internet_udp_138', 'azure.claude.nsg_internet_udp_1434', 'azure.claude.nsg_internet_udp_445', 'azure.claude.nsg_internet_udp_53', 'azure.claude.nsg_internet_udp_any', 'azure.claude.nsg_internet_udp_services'))

_RULE_CHECKS = frozenset({
    "azure.claude.vm_nic_nsg_internet_tcp_ingress",
    "azure.claude.vm_nsg_internet_management_ports",
})


def _port(value):
    if type(value) is int:
        return (value, value) if 0 <= value <= 65535 else None
    if not isinstance(value, str):
        return None
    if value in ("*", "all"):
        return (0, 65535)
    if not re.fullmatch(r"\d{1,5}(?:-\d{1,5})?", value):
        return None
    parts = value.split("-")
    low, high = int(parts[0]), int(parts[-1])
    return (low, high) if 0 <= low <= high <= 65535 else None


def contextual_severity(finding, default=None):
    """Web-only TCP80/443 is Medium; other explicit TCP/UDP exposure is High.

    Only source-bound NSG evaluators are supported. Missing/malformed facts,
    ICMP, non-failing rows and unrelated checks retain the caller's baseline.
    An Allow rule is not a claim of an independently tested complete route.
    """
    if not isinstance(finding, dict):
        return default
    baseline = default if default is not None else finding.get("severity")
    if finding.get("status") != "FAIL":
        return baseline
    check_id = finding.get("check_id")
    evidence = finding.get("evidence")
    if not isinstance(check_id, str) or not isinstance(evidence, dict):
        return baseline
    selections = []
    if check_id in _NSG_CHECKS:
        if evidence.get("direction") != "Inbound":
            return baseline
        rules = evidence.get("exposed_rules")
        if not isinstance(rules, list) or not rules:
            return baseline
        for rule in rules:
            if not isinstance(rule, dict) or rule.get("protocol") not in ("tcp", "udp", "*"):
                return baseline
            parsed = _port(rule.get("port"))
            if parsed is None:
                return baseline
            selections.append((rule["protocol"], parsed))
    elif check_id in _RULE_CHECKS:
        rules = evidence.get("internet_allow_rules")
        if not isinstance(rules, list) or not rules:
            return baseline
        for rule in rules:
            if not isinstance(rule, dict):
                return baseline
            protocol = rule.get("protocol", "tcp" if check_id.endswith("tcp_ingress") else None)
            if not isinstance(protocol, str) or protocol.lower() not in ("tcp", "udp", "*"):
                return baseline
            ports = rule.get("ports")
            if not isinstance(ports, list) or not ports:
                return baseline
            for value in ports:
                parsed = _port(value)
                if parsed is None:
                    return baseline
                selections.append((protocol.lower(), parsed))
    elif check_id == "azure.network.restrict_internet_ingress" or check_id in {
            "azure.gap.nsg_declared_internet_rdp", "azure.gap.nsg_declared_internet_ssh",
            "azure.gap.nsg_declared_internet_http", "azure.gap.nsg_declared_internet_http_https",
            "azure.gap.nsg_declared_internet_remote_access", "azure.gap.nsg_declared_internet_udp_services",
            "azure.gap.nsg_declared_internet_udp_any"}:
        core = check_id == "azure.network.restrict_internet_ingress"
        rules = evidence.get("broad_ingress_rules" if core else "declared_internet_allow_rules")
        if not isinstance(rules, list) or not rules:
            return baseline
        for rule in rules:
            if not isinstance(rule, dict):
                return baseline
            protocol = rule.get("protocol")
            if not isinstance(protocol, str) or protocol.lower() not in ("tcp", "udp", "*"):
                return baseline
            ports = rule.get("destination_ports" if core else "ports")
            if not isinstance(ports, list) or not ports:
                return baseline
            for value in ports:
                parsed = _port(value)
                if parsed is None:
                    return baseline
                selections.append((protocol.lower(), parsed))
    else:
        return baseline
    if not selections:
        return baseline
    if all(protocol == "tcp" and low == high and low in (80, 443)
           for protocol, (low, high) in selections):
        return "medium"
    return "high"
