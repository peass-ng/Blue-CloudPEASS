"""Parameterized principal trust and network configuration metadata predicates."""
from ipaddress import ip_network
from . import register, result, unknown
from .facts import get, optional, list_of_objects, Unavailable, principal_trust_lists, PUBLIC_PRINCIPALS
from .fixtures import CASES
from .gcp_ports_keys import caller_restrictions

IDS, REFERENCE_SPECS = [], {}


def rule(query, kind, function, good, bad):
    cid = "gcp.ports." + query
    IDS.append(cid)
    register(cid, "gcp", "exposure", kind, query.replace("_", " "), "medium", "AC-3",
        "Review declared scope, selected principal policy, ingress and service configuration. This does not establish effective authorization or network reachability.")(function)
    CASES[cid] = {"pass": good, "fail": bad, "missing": {}, "malformed": None}
    REFERENCE_SPECS[query] = cid
    return cid


def trust(query, kind):
    def evaluate(item, index):
        rows = list_of_objects(get(item, "iamPolicy.bindings", list))
        if not rows:
            return "NOT_APPLICABLE", {"reason": "Source excludes empty policy binding declarations"}
        approved = principal_trust_lists(get(index, "context.metadata", dict))
        untrusted, project_members, other_members = [], [], []
        for binding in rows:
            members = get(binding, "members", list)
            if not members or any(not isinstance(member, str) for member in members):
                raise Unavailable("malformed nonempty binding member declaration")
            role = get(binding, "role", str)
            condition = optional(binding, "condition", None, dict)
            for member in members:
                if member.startswith("project"):
                    project_members.append(member)
                    continue
                other_members.append(member)
                prefix, separator, identity = member.partition(":")
                if approved is None:
                    # No operator trust lists: only public principals are decidable.
                    if member in PUBLIC_PRINCIPALS:
                        untrusted.append({"principal": member, "role": role, "condition": condition})
                    continue
                if not separator or prefix not in approved or identity not in approved[prefix]:
                    untrusted.append({"principal": member, "role": role, "condition": condition})
        if approved is None and other_members and not untrusted:
            return "MANUAL", {"reason": "Principal trust lists not configured; no public principal is bound, review the "
                              "remaining nonproject principals against the approved lists", "project_principals_for_separate_review": project_members}
        if not other_members:
            return "MANUAL", {"reason": "Pinned source INFO project-level principal exception requires separate review", "project_principals": project_members}
        return result(bool(untrusted), untrusted_nonproject_declarations=untrusted, project_principals_for_separate_review=project_members,
            semantics="Pinned explicit four-list trust policy for nonproject principals; project principal exception is disclosed, conditions/deny/PAB and effective access are separate")
    cid = rule(query, kind, evaluate,
        {"iamPolicy": {"bindings": [{"role": "roles/viewer", "members": ["user:trusted@example.com"]}]}},
        {"iamPolicy": {"bindings": [{"role": "roles/viewer", "members": ["user:untrusted@example.com"]}]}})
    CASES[cid]["index"] = {"context": {"metadata": {"trusted_users": ["trusted@example.com"], "trusted_groups": [], "trusted_domains": [], "trusted_service_accounts": []}}}


for _kind, _query in (("bigtable_instance", "bigtable_instance_policy_shared_access"), ("billing_account", "billing_account_policy_shared_access"),
    ("function", "cloud_function_policy_shared_access"), ("cloudrun_job", "cloud_run_job_policy_shared_access"), ("cloudrun_service", "cloud_run_service_policy_shared_access")):
    trust(_query, _kind)


def cloudrun_public(item, index):
    rows = list_of_objects(get(item, "iamPolicy.bindings", list))
    public = []
    for row in rows:
        members = get(row, "members", list)
        if any(not isinstance(member, str) for member in members):
            raise Unavailable("malformed IAM member list")
        if {"allUsers", "allAuthenticatedUsers"}.intersection(members):
            public.append({"role": get(row, "role", str), "condition": optional(row, "condition", None, dict)})
    return result(bool(public), public_principal_declarations=public,
        semantics="Any public-principal role declaration, distinct from run.invoker-only and IAM-check-disabled settings")


rule("cloud_run_service_policy_prohibit_public_access", "cloudrun_service", cloudrun_public,
    {"iamPolicy": {"bindings": []}}, {"iamPolicy": {"bindings": [{"role": "roles/viewer", "members": ["allUsers"]}]}})


def run_ingress(item, index):
    ingress = get(item, "ingress", str)
    if ingress not in ("INGRESS_TRAFFIC_ALL", "INGRESS_TRAFFIC_INTERNAL_ONLY", "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"):
        return unknown("unrecognized Cloud Run ingress")
    return result(ingress == "INGRESS_TRAFFIC_ALL", ingress=ingress,
        semantics="Declared ingress boundary, not public invocation permission or endpoint reachability")


rule("cloud_run_not_publicly_accessible", "cloudrun_service", run_ingress,
    {"ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY"}, {"ingress": "INGRESS_TRAFFIC_ALL"})


def sql_authorized(item, index):
    config = get(item, "settings.ipConfiguration", dict)
    rows = list_of_objects(optional(config, "authorizedNetworks", [], list))
    ranges = [get(row, "value", str) for row in rows]
    return result(any(value in ("0.0.0.0/0", "::/0") for value in ranges), declared_authorized_ranges=ranges,
        semantics="Broad CIDR allowlist declaration, not actual SQL reachability")


rule("sql_instance_not_open_to_internet", "sql_instance", sql_authorized,
    {"settings": {"ipConfiguration": {"authorizedNetworks": []}}},
    {"settings": {"ipConfiguration": {"authorizedNetworks": [{"value": "::/0"}]}}})
REFERENCE_SPECS["cloud_sql_not_publicly_accessible"] = "gcp.sql.no_public_ip"


def sql_ssl(item, index):
    config = get(item, "settings.ipConfiguration", dict)
    mode = optional(config, "sslMode", "SSL_MODE_UNSPECIFIED", str)
    if mode not in ("SSL_MODE_UNSPECIFIED", "ALLOW_UNENCRYPTED_AND_ENCRYPTED", "ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"):
        return unknown("unrecognized SQL SSL mode")
    legacy = optional(config, "requireSsl", False, bool)
    return result(mode == "ALLOW_UNENCRYPTED_AND_ENCRYPTED" or mode == "SSL_MODE_UNSPECIFIED" and not legacy,
        ssl_mode=mode, legacy_require_ssl=legacy, semantics="Exact source mode/fallback policy; client certificate authentication is separate")


rule("reference_sql_ssl_connections", "sql_instance", sql_ssl,
    {"settings": {"ipConfiguration": {"sslMode": "SSL_MODE_UNSPECIFIED", "requireSsl": True}}},
    {"settings": {"ipConfiguration": {"sslMode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED", "requireSsl": True}}})


def meaningful_restrictions(item, index):
    restrictions = get(item, "restrictions", dict)
    targets = list_of_objects(optional(restrictions, "apiTargets", [], list))
    names = [get(target, "service", str) for target in targets]
    api_restricted = bool(names) and "cloudapis.googleapis.com" not in names and all(names)
    status, caller_evidence = caller_restrictions(item, index)
    if status == "UNKNOWN":
        return status, caller_evidence
    return result(not api_restricted and status != "PASS", restricted_services=names, caller_declaration=caller_evidence,
        semantics="Meaningful API target or caller restriction; object nonemptiness alone is not a security restriction")


rule("api_key_meaningful_restrictions", "api_key", meaningful_restrictions,
    {"restrictions": {"apiTargets": [{"service": "storage.googleapis.com"}]}},
    {"restrictions": {"serverKeyRestrictions": {"allowedIps": ["0.0.0.0/0"]}}})


def dataset_acl(item, index):
    access = list_of_objects(get(item, "access", list))
    public = [row for row in access if row.get("iamMember") in ("allUsers", "allAuthenticatedUsers") or row.get("specialGroup") == "allAuthenticatedUsers"]
    return result(bool(public), public_acl_declarations=public,
        semantics="Actual public IAM/legacy ACL fields, not arbitrary nested object text")


REFERENCE_SPECS["bigquery_dataset_public_acl_declarations"] = "gcp.reviewed.bigquery.no_public_acl"
IDS.append(REFERENCE_SPECS["bigquery_dataset_public_acl_declarations"])


def function_internal(item, index):
    ingress = get(item, "serviceConfig.ingressSettings", str)
    if ingress not in ("ALLOW_ALL", "ALLOW_INTERNAL_ONLY", "ALLOW_INTERNAL_AND_GCLB"):
        return unknown("unrecognized function ingress setting")
    return result(ingress != "ALLOW_INTERNAL_ONLY", ingress=ingress,
        semantics="Internal ingress declaration; VPC connector configures outbound traffic and IAM invocation is separate")


rule("function_internal_ingress_declaration", "function", function_internal,
    {"serviceConfig": {"ingressSettings": "ALLOW_INTERNAL_ONLY"}}, {"serviceConfig": {"ingressSettings": "ALLOW_ALL"}})


def iap_sources(query, allowed_ranges):
    def evaluate(item, index):
        direction = get(item, "direction", str)
        if direction == "EGRESS" or optional(item, "disabled", False, bool):
            return "NOT_APPLICABLE", {"reason": "Not an active ingress rule declaration"}
        if direction != "INGRESS":
            return unknown("unrecognized firewall direction")
        allowed = list_of_objects(get(item, "allowed", list))
        if not any(get(row, "IPProtocol", str) in ("tcp", "6", "all") for row in allowed):
            return "NOT_APPLICABLE", {"reason": "No TCP/protocol-all ingress declaration"}
        ranges = optional(item, "sourceRanges", [], list)
        if any(not isinstance(value, str) for value in ranges):
            raise Unavailable("malformed firewall source range")
        networks = [ip_network(value, strict=False) for value in ranges]
        trusted = [ip_network(value) for value in allowed_ranges]
        narrow = bool(networks) and all(any(value.version == parent.version and value.subnet_of(parent) for parent in trusted) for value in networks)
        return result(not narrow, declared_source_ranges=ranges, approved_proxy_ranges=allowed_ranges,
            semantics="Explicit proxy-source restriction policy only; no effective firewall rule ordering, IAP identity or endpoint reachability inference")
    rule(query, "firewall", evaluate,
        {"direction": "INGRESS", "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "sourceRanges": allowed_ranges},
        {"direction": "INGRESS", "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "sourceRanges": allowed_ranges + ["0.0.0.0/0"]})


iap_sources("firewall_iap_tcp_proxy_source_restriction", ["35.235.240.0/20", "2600:2d00:1:7::/64"])
iap_sources("firewall_http_lb_proxy_source_restriction", ["130.211.0.0/22", "35.191.0.0/16"])
