"""GCP CIS coverage gaps: CIS GCP 1.5 and 3.10 declaration audits.

The upstream evaluators for these recommendations are defective (see the reviewed
manifest rows ``gcp-compliance.control.cis_v*_1_5`` / ``cis_v*_3_10``,
``iam_service_account_without_admin_privilege``,
``compute_firewall_allow_tcp_connections_proxied_by_iap`` and
``prowler.gcp.iam_sa_no_administrative_privileges``), and the nearest existing
natives evaluate different predicates. These natives follow the CIS wording:

* CIS 1.5: a user-managed service account
  (``SERVICE_ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com``) must not hold a
  role matching ``*Admin`` / ``*admin``, ``roles/editor`` or ``roles/owner``.
* CIS 3.10: TCP ingress must be allowed only from the IAP proxy range
  ``35.235.240.0/20`` and the Google load-balancer health-check ranges
  ``130.211.0.0/22`` and ``35.191.0.0/16``.

Both are declaration audits: IAM conditions, deny policies and firewall rule
priority/targets are carried as evidence, never flattened into effective access.
"""
from __future__ import annotations
import re
from ipaddress import ip_network
from . import register, result, unknown
from .facts import get, optional, list_of_objects, Unavailable
from .fixtures import CASES
from .gcp_ports_iam import bindings, project_roots

CIS_DOCS = "https://cloud.google.com/iap/docs/using-tcp-forwarding#create-firewall-rule"
# CIS GCP 3.10 remediation: "IAP Proxy Addresses 35.235.240.0/20", "Google Health Check
# 130.211.0.0/22", "Google Health Check 35.191.0.0/16". Nothing else (CIS lists no IPv6 range).
CIS_3_10_RANGES = ("35.235.240.0/20", "130.211.0.0/22", "35.191.0.0/16")
BASIC_ADMIN_ROLES = ("roles/editor", "roles/owner")
IDS = []


def admin_role(role):
    """CIS 1.5: role ``*Admin``/``*admin`` (predefined or custom role id), roles/editor or roles/owner."""
    short = role.rsplit("/", 1)[-1]
    return role in BASIC_ADMIN_ROLES or short.endswith(("Admin", "admin"))


def user_managed_sa_admin_roles(item, index):
    email = get(item, "email", str)
    project_id = get(item, "projectId", str)
    if not email.endswith("@" + project_id + ".iam.gserviceaccount.com"):
        return "NOT_APPLICABLE", {"email": email, "reason": "Not a user-managed service account (CIS 1.5 scope: SERVICE_ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com)"}
    findings = []
    for policy in project_roots(item, index):
        for row in bindings(policy):
            if "serviceAccount:" + email in row["members"] and admin_role(row["role"]):
                findings.append({"role": row["role"], "policy": policy["name"], "condition": row.get("condition")})
    return result(bool(findings), email=email, admin_role_bindings=findings,
        semantics="Declared project/folder/organization IAM bindings; conditions, deny policies and PAB are evidence only")


def iap_lb_sources_only(item, index):
    direction = get(item, "direction", str)
    if direction == "EGRESS" or optional(item, "disabled", False, bool):
        return "NOT_APPLICABLE", {"reason": "Not an active ingress rule declaration"}
    if direction != "INGRESS":
        return unknown("unrecognized firewall direction", direction=direction)
    if "allowed" not in item and "denied" in item:
        return "NOT_APPLICABLE", {"reason": "Deny rule"}
    allowed = list_of_objects(get(item, "allowed", list))
    if not any(get(row, "IPProtocol", str).lower() in ("tcp", "6", "all") for row in allowed):
        return "NOT_APPLICABLE", {"reason": "No TCP/protocol-all ingress declaration"}
    ranges = optional(item, "sourceRanges", None, list)
    selectors = [value for field in ("sourceTags", "sourceServiceAccounts") for value in optional(item, field, [], list)]
    if any(not isinstance(value, str) or not value.strip() for value in selectors):
        raise Unavailable("malformed firewall source selector")
    if ranges is None:
        # GCP defaults an ingress rule without any source to 0.0.0.0/0.
        ranges = [] if selectors else ["0.0.0.0/0"]
    if any(not isinstance(value, str) for value in ranges):
        raise Unavailable("malformed firewall source range")
    try:
        networks = [ip_network(value, strict=False) for value in ranges]
    except ValueError:
        raise Unavailable("malformed firewall source range")
    trusted = [ip_network(value) for value in CIS_3_10_RANGES]
    outside = [value for value, network in zip(ranges, networks)
               if not any(network.version == parent.version and network.subnet_of(parent) for parent in trusted)]
    # Google combines CIDRs OR source tag/account selectors. A selector is
    # an additional declared source population, not a constraint on the CIDRs.
    failed = bool(outside) or not networks or bool(selectors)
    return result(failed, declared_source_ranges=ranges, source_selectors=selectors, ranges_outside_cis_list=outside,
        cis_allowed_ranges=list(CIS_3_10_RANGES), allowed=allowed, target_tags=optional(item, "targetTags", [], list),
        semantics="Declared TCP ingress sources vs the CIS 3.10 IAP/health-check list; no rule priority, target or IAP identity inference")


def _register(cid, kind, category, title, severity, control, remediation, function, dependencies, good, bad, index=None):
    IDS.append(cid)
    register(cid, "gcp", category, kind, title, severity, control, remediation, dependencies=dependencies)(function)
    CASES[cid] = {"pass": good, "fail": bad, "missing": {}, "malformed": None}
    if index is not None:
        CASES[cid]["index"] = index


def _sa(name):
    return {"email": name + "@p.iam.gserviceaccount.com", "projectId": "p", "name": "projects/p/serviceAccounts/" + name + "@p.iam.gserviceaccount.com",
            "_provenance": {"scope": "projects/p"}}


_register("gcp.gap.iam_user_managed_sa_no_admin_roles", "service_account", "least_privilege",
    "User-managed service account holds no admin, editor or owner role", "high", "AC-6",
    "Remove roles matching *Admin/*admin, roles/editor and roles/owner from the user-managed service account and grant "
    "narrowly scoped predefined or custom roles instead (CIS GCP 1.5).",
    user_managed_sa_admin_roles, ["service_account", "project", "iam_policy"], _sa("reader"), _sa("deployer"),
    {"collections": {kind: [{"status": "collected"}] for kind in ("project", "iam_policy")},
     "project": [{"data": {"name": "projects/p", "projectId": "p", "_ancestry": []}}],
     "iam_policy": [{"data": {"name": "projects/p", "bindings": [
         {"role": "roles/storage.objectViewer", "members": ["serviceAccount:reader@p.iam.gserviceaccount.com"]},
         {"role": "roles/iam.serviceAccountAdmin", "members": ["serviceAccount:deployer@p.iam.gserviceaccount.com"]}]}}]})

_register("gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only", "firewall", "network",
    "Firewall TCP ingress allows only the IAP proxy and Google health-check ranges", "medium", "SC-7",
    "Restrict TCP ingress source ranges to the IAP proxy range 35.235.240.0/20 and the Google health-check ranges "
    "130.211.0.0/22 and 35.191.0.0/16, and delete default-allow-http/https/internal (CIS GCP 3.10); see " + CIS_DOCS,
    iap_lb_sources_only, ["firewall"],
    {"direction": "INGRESS", "allowed": [{"IPProtocol": "tcp", "ports": ["80", "443"]}], "sourceRanges": list(CIS_3_10_RANGES)},
    {"direction": "INGRESS", "allowed": [{"IPProtocol": "tcp", "ports": ["80", "443"]}], "sourceRanges": list(CIS_3_10_RANGES) + ["0.0.0.0/0"]})


def sql_3625_off_cis_v1(item, index):
    version = get(item, "databaseVersion", str)
    if not version.startswith(("MYSQL", "POSTGRES", "SQLSERVER")):
        return unknown("unrecognized database engine", database_version=version)
    if not version.startswith("SQLSERVER"):
        return "NOT_APPLICABLE", {"reason": "Different database engine", "database_version": version}
    flags = {}
    for row in list_of_objects(get(item, "settings.databaseFlags", list)):
        name, value = get(row, "name", str), get(row, "value", str)
        # SQL Admin returns this documented name; retain the historical short
        # name as an imported compatibility alias, not as a different flag.
        if name == "3625 (trace flag)":
            name = "3625"
        if name == "3625" and value not in ("on", "off"):
            return unknown("unrecognized trace flag value", flag=name)
        if name in flags:
            return unknown("duplicate database flag", flag=name)
        flags[name] = value
    return result(flags.get("3625") != "off", flag="3625", configured=flags.get("3625"), database_version=version,
        semantics="Literal CIS GCP v1.2.0/v1.3.0 6.3.6 requirement (explicit 'off'); CIS v2.0+ reversed it and the security-preferred setting is 'on'")


def _sql(value):
    return {"databaseVersion": "SQLSERVER_2019_STANDARD", "settings": {"databaseFlags": [{"name": "3625", "value": value}]}}


_register("gcp.gap.sql_3625_trace_flag_off_cis_v1", "sql_instance", "hardening",
    "Cloud SQL SQL Server trace flag 3625 is 'off' (literal CIS GCP v1.2/v1.3 6.3.6)", "low", "CM-6",
    "Only for CIS GCP v1.2.0/v1.3.0 6.3.6 literal compliance: set database flag 3625 to 'off'. CIS GCP v2.0+ reversed this "
    "recommendation; the security-preferred setting is 'on' (3625 masks error-message parameters for non-sysadmin users), "
    "see gcp.ports.sql_instance_sql_3625_trace_database_flag_on.",
    sql_3625_off_cis_v1, ["sql_instance"], _sql("off"), _sql("on"))
