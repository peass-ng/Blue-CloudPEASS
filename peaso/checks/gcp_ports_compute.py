"""Reviewed Compute/network metadata declarations and source-defect replacements."""
import copy
from . import register, result, unknown
from .facts import get, optional, Unavailable, list_of_objects, complete_items
from .fixtures import CASES
from .gcp_extended import metadata_flag

IDS, REFERENCE_SPECS = [], {}


def rule(query, kind, title, function, good, bad, *, dependencies=None, target="resource"):
    cid = "gcp.ports." + query
    IDS.append(cid)
    register(cid, "gcp", "hardening", kind, title, "medium", "CM-6",
        "Review the explicit native configuration and applicable workload exceptions; do not infer effective access or reachability.",
        dependencies=dependencies, target=target)(function)
    CASES[cid] = {"pass": good, "fail": bad, "missing": {}, "malformed": None}
    REFERENCE_SPECS[query] = cid
    return cid


REFERENCE_SPECS.update({
    "compute_instance_confidential_computing_enabled": "gcp.reviewed.compute.confidential_computing",
    "compute_instance_block_project_wide_ssh_enabled": "gcp.reviewed.compute.block_project_ssh_keys",
    "compute_instance_serial_port_connection_disabled": "gcp.reviewed.compute.no_serial_console",
    "compute_instance_with_no_default_service_account": "gcp.reviewed.compute.no_default_service_account",
    "compute_instance_with_no_default_service_account_with_full_access": "gcp.reviewed.compute.no_default_full_api",
    "compute_network_contains_no_default_network": "gcp.reviewed.network.no_default_vpc",
})


def declared_gke(item):
    name = get(item, "name", str)
    labels = optional(item, "labels", {}, dict)
    return name.startswith("gke-") and "goog-gke-node" in labels


def account_rule(query, require_full_scope):
    def evaluate(item, index):
        if declared_gke(item):
            return "NOT_APPLICABLE", {"reason": "Source's declared GKE node naming+ownership-label scope; node-pool identity is reviewed separately"}
        defaults = []
        for account in list_of_objects(get(item, "serviceAccounts", list)):
            email = get(account, "email", str)
            if not email.endswith("-compute@developer.gserviceaccount.com"):
                continue
            if require_full_scope:
                scopes = get(account, "scopes", list)
                if any(not isinstance(value, str) for value in scopes):
                    raise Unavailable("malformed OAuth scope list")
                if "https://www.googleapis.com/auth/cloud-platform" not in scopes:
                    continue
            defaults.append(email)
        return result(bool(defaults), declared_default_accounts=defaults,
            semantics="Attached identity/OAuth scope declarations, not effective IAM permission")
    account = {"email": "123-compute@developer.gserviceaccount.com", "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}
    return rule(query, "instance", "VM reviews default identity attachment" + (" with full OAuth API scope" if require_full_scope else ""), evaluate,
        {"name": "vm", "serviceAccounts": []}, {"name": "vm", "serviceAccounts": [account]})


account_rule("compute_instance_with_no_default_service_account", False)
account_rule("compute_instance_with_no_default_service_account_with_full_access", True)


def no_forward(item, index):
    if declared_gke(item):
        return "NOT_APPLICABLE", {"reason": "Explicit source GKE-node scope exclusion"}
    forwarding = get(item, "canIpForward", bool)
    return result(forwarding, can_ip_forward=forwarding, semantics="IP forwarding configuration only")


rule("compute_instance_ip_forwarding_disabled", "instance", "VM avoids explicit IP forwarding outside GKE source scope", no_forward,
    {"name": "vm", "canIpForward": False}, {"name": "vm", "canIpForward": True})


def block_project_keys(item, index):
    if declared_gke(item):
        return "NOT_APPLICABLE", {"reason": "Explicit source GKE-node scope exclusion"}
    blocked = metadata_flag(item, "metadata.items", "block-project-ssh-keys")
    return result(not blocked, block_project_ssh_keys=blocked)


rule("compute_instance_block_project_wide_ssh_enabled", "instance", "VM explicitly blocks project SSH keys outside GKE source scope", block_project_keys,
    {"name": "vm", "metadata": {"items": [{"key": "block-project-ssh-keys", "value": "true"}]}},
    {"name": "vm", "metadata": {"items": [{"key": "block-project-ssh-keys", "value": "false"}]}})


def shielding(item, index):
    vtpm = get(item, "shieldedInstanceConfig.enableVtpm", bool)
    monitoring = get(item, "shieldedInstanceConfig.enableIntegrityMonitoring", bool)
    return result(not (vtpm and monitoring), enableVtpm=vtpm, enableIntegrityMonitoring=monitoring)


rule("compute_instance_shielded_vm_enabled", "instance", "VM explicitly enables both vTPM and integrity monitoring", shielding,
    {"shieldedInstanceConfig": {"enableVtpm": True, "enableIntegrityMonitoring": True}},
    {"shieldedInstanceConfig": {"enableVtpm": False, "enableIntegrityMonitoring": True}})


def no_legacy(item, index):
    get(item, "name", str)
    ipv4 = optional(item, "IPv4Range", None, str)
    return result(ipv4 is not None, legacy_ipv4_range=ipv4,
        semantics="Legacy-network IPv4Range declaration; auto subnet mode is a different property")


rule("compute_network_contains_no_legacy_network", "network", "Network avoids the legacy IPv4Range model", no_legacy,
    {"name": "vpc"}, {"name": "legacy", "IPv4Range": "10.0.0.0/8"})


def public_interfaces(item, index):
    interfaces = list_of_objects(get(item, "networkInterfaces", list))
    public = []
    for interface in interfaces:
        for config in list_of_objects(optional(interface, "accessConfigs", [], list)):
            address = optional(config, "natIP", None, str)
            if address:
                public.append(address)
        for config in list_of_objects(optional(interface, "ipv6AccessConfigs", [], list)):
            address = optional(config, "externalIpv6", None, str)
            if address:
                public.append(address)
    return result(bool(public), declared_external_addresses=public, semantics="All observed interfaces, no reachability or firewall inference")


rule("compute_instance_with_no_public_ip_addresses", "instance", "VM interface inventory avoids declared external addresses", public_interfaces,
    {"networkInterfaces": [{"network": "projects/p/global/networks/private"}]},
    {"networkInterfaces": [{"network": "projects/p/global/networks/private"}, {"accessConfigs": [{"natIP": "203.0.113.1"}]}]})


def firewall_port(query, port):
    def evaluate(item, index):
        direction = get(item, "direction", str)
        if direction not in ("INGRESS", "EGRESS"):
            return unknown("unrecognized firewall direction")
        if direction != "INGRESS" or optional(item, "disabled", False, bool):
            return "NOT_APPLICABLE", {"reason": "Not an active ingress declaration"}
        allowed = list_of_objects(optional(item, "allowed", [], list))
        ranges = optional(item, "sourceRanges", None, list)
        if not ranges:
            # No source selector means Google's default of all IPv4 sources.
            tags = optional(item, "sourceTags", [], list)
            accounts = optional(item, "sourceServiceAccounts", [], list)
            if any(not isinstance(value, str) or not value for value in tags + accounts):
                raise Unavailable("malformed firewall source selectors")
            ranges = [] if tags or accounts else ["0.0.0.0/0"]
        if any(not isinstance(value, str) for value in ranges):
            raise Unavailable("malformed firewall source ranges")
        public = bool(set(ranges).intersection({"0.0.0.0/0", "::/0"}))
        exposed = False
        for entry in allowed:
            protocol = get(entry, "IPProtocol", str)
            ports = optional(entry, "ports", [], list)
            if protocol in ("all", "tcp", "6"):
                if protocol == "all" or not ports:
                    exposed = True
                for value in ports:
                    if not isinstance(value, str):
                        raise Unavailable("malformed allowed port")
                    parts = value.split("-")
                    if len(parts) not in (1, 2) or any(not part.isdigit() for part in parts):
                        raise Unavailable("malformed allowed port range")
                    low, high = int(parts[0]), int(parts[-1])
                    if not 0 <= low <= high <= 65535:
                        raise Unavailable("invalid allowed port range")
                    exposed |= low <= port <= high
        return result(public and exposed, port=port, source_ranges=ranges,
            semantics="Declared ingress candidate; priorities, targets and effective routing/firewall decisions are separate")
    return rule(query, "firewall", "Firewall avoids broad declared ingress to TCP " + str(port), evaluate,
        {"direction": "INGRESS", "sourceRanges": ["10.0.0.0/8"], "allowed": [{"IPProtocol": "tcp", "ports": [str(port)]}]},
        {"direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp"}]})


firewall_port("compute_firewall_rule_ssh_access_restricted", 22)
firewall_port("compute_firewall_rule_rdp_access_restricted", 3389)


def sql_ssl(item, index):
    mode = get(item, "settings.ipConfiguration.sslMode", str)
    if mode not in ("ALLOW_UNENCRYPTED_AND_ENCRYPTED", "ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"):
        return unknown("unrecognized SQL TLS mode")
    return result(mode == "ALLOW_UNENCRYPTED_AND_ENCRYPTED", sslMode=mode,
        semantics="Encrypted-only and trusted-client-certificate modes both require encrypted client connections")


rule("sql_instance_require_ssl_enabled", "sql_instance", "SQL metadata requires encrypted client connections", sql_ssl,
    {"settings": {"ipConfiguration": {"sslMode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}}},
    {"settings": {"ipConfiguration": {"sslMode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}}})


def audit_scope(item, index):
    scope = get(item, "scope", str)
    policies = complete_items(index, "iam_policy")
    roots = [policy for policy in policies if policy.get("name") in (scope, "//cloudresourcemanager.googleapis.com/" + scope)]
    if len(roots) != 1:
        return unknown("project policy root absent or ambiguous")
    if "effectiveAuditConfigs" in roots[0]:
        # Collector-materialized union of organization, folder and project
        # auditConfigs: inherited configuration counts, as Cloud Audit Logs applies it.
        from .gcp import effective_audit
        status, evidence = effective_audit(roots[0], frozenset(("ADMIN_READ", "DATA_READ", "DATA_WRITE")))
        # This source predicate also rejects exemptions (reviewed check: MANUAL).
        return ("FAIL", evidence) if status == "MANUAL" else (status, evidence)
    rows = list_of_objects(get(roots[0], "auditConfigs", list))
    types, exemptions = set(), []
    for row in rows:
        if get(row, "service", str) != "allServices":
            continue
        for entry in list_of_objects(get(row, "auditLogConfigs", list)):
            types.add(get(entry, "logType", str))
            exemptions += optional(entry, "exemptedMembers", [], list)
    return result(not {"ADMIN_READ", "DATA_READ", "DATA_WRITE"} <= types or bool(exemptions), configured_log_types=sorted(types),
        exempted_members=exemptions, semantics="Exact project audit policy declaration; inherited policies and delivery require additional evidence")


cid = rule("audit_logging_configured_for_all_service", "inventory", "Project declares all-service audit categories without exemptions",
    audit_scope, {"scope": "projects/p"}, {"scope": "projects/p"}, dependencies=["iam_policy"], target="scope")
CASES[cid]["pass_index"] = {"collections": {"iam_policy": [{"scope": "projects/p", "status": "collected"}]}, "iam_policy": [{"data": {
    "name": "projects/p", "auditConfigs": [{"service": "allServices", "auditLogConfigs": [{"logType": log} for log in ("ADMIN_READ", "DATA_READ", "DATA_WRITE")]}]}}]}
CASES[cid]["fail_index"] = {"collections": {"iam_policy": [{"scope": "projects/p", "status": "collected"}]}, "iam_policy": [{"data": {"name": "projects/p", "auditConfigs": []}}]}
