"""Exact resource joins and declared configuration; no reachability actions."""
import re
from . import register, result, unknown
from .facts import get, optional, complete_items, unique_join, list_of_objects, Unavailable
from .fixtures import CASES

IDS, REFERENCE_SPECS = [], {}


def rule(query, kind, function, good, bad, dependencies=None):
    cid = "gcp.ports." + query
    IDS.append(cid)
    register(cid, "gcp", "hardening", kind, query.replace("_", " "), "medium", "CM-6",
        "Review exact native references, service applicability and complete metadata dependencies before configuration changes.",
        dependencies=dependencies)(function)
    CASES[cid] = {"pass": good, "fail": bad, "missing": {}, "malformed": None}
    REFERENCE_SPECS[query] = cid
    return cid


def metadata_value(item, field):
    metadata = get(item, field, dict)
    rows = list_of_objects(optional(metadata, "items", [], list))
    values = [get(row, "value", str).lower() for row in rows if get(row, "key", str).lower() == "enable-oslogin"]
    if len(values) > 1 or any(value not in ("true", "false") for value in values):
        raise Unavailable("ambiguous or unrecognized OS Login metadata")
    return values[0] if values else None


def oslogin(item, index):
    # Unset on instance and project: the effective compute.requireOsLogin decides
    # (previously an unset project was read as FAIL without the org policy).
    from . import gcp_instance_oslogin
    return gcp_instance_oslogin(item, index)


cid = rule("compute_oslogin_metadata_precedence", "instance", oslogin,
    {"metadata": {"items": [{"key": "enable-oslogin", "value": "true"}]}},
    {"metadata": {"items": [{"key": "enable-oslogin", "value": "false"}]}}, ["instance", "project", "org_policy_effective"])


def csek(item, index):
    get(item, "name", str)
    encryption = optional(item, "diskEncryptionKey", {}, dict)
    digest = optional(encryption, "sha256", "", str)
    return result(not digest, csek_digest_present=bool(digest), semantics="CSEK digest presence only; no raw or wrapped encryption key")


rule("compute_disk_encrypted_with_csk", "disk", csek,
    {"name": "disk", "diskEncryptionKey": {"sha256": "metadata-digest"}}, {"name": "disk"})


WEAK = {"TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}


def ssl_policy(item, index):
    kind = get(item, "kind", str)
    if kind not in ("compute#targetHttpsProxy", "compute#targetSslProxy"):
        return "NOT_APPLICABLE", {"reason": "Not an HTTPS/SSL target proxy"}
    reference = optional(item, "sslPolicy", "", str)
    if not reference:
        return result(True, reason="No explicit SSL policy; default compatibility does not establish the strict cipher/TLS policy")
    policy = unique_join(index, "ssl_policy", "selfLink", reference)
    profile, minimum = get(policy, "profile", str), get(policy, "minTlsVersion", str)
    if profile not in ("COMPATIBLE", "MODERN", "RESTRICTED", "CUSTOM", "FIPS_202205") or minimum not in ("TLS_1_0", "TLS_1_1", "TLS_1_2"):
        return unknown("unrecognized SSL profile/minimum TLS version")
    if profile == "CUSTOM":
        features = get(policy, "enabledFeatures", list)
        if not features or any(not isinstance(value, str) for value in features):
            return unknown("custom enabled cipher feature inventory unavailable")
        good = minimum == "TLS_1_2" and not WEAK.intersection(features)
    else:
        good = profile == "RESTRICTED" or profile in ("MODERN", "FIPS_202205") and minimum == "TLS_1_2"
    return result(not good, profile=profile, min_tls_version=minimum, policy_reference=reference,
        semantics="Negotiation policy declaration, not endpoint TLS probing")


cid = rule("compute_ssl_policy_strict_declaration", "target_proxy", ssl_policy,
    {"kind": "compute#targetHttpsProxy", "sslPolicy": "projects/p/global/sslPolicies/strong"},
    {"kind": "compute#targetHttpsProxy"}, ["target_proxy", "ssl_policy"])
CASES[cid]["index"] = {"collections": {"ssl_policy": [{"status": "collected"}]}, "ssl_policy": [{"data": {"selfLink": "projects/p/global/sslPolicies/strong", "profile": "MODERN", "minTlsVersion": "TLS_1_2"}}]}


def backend_references(item):
    references = set()
    def visit(row):
        if not isinstance(row, dict):
            raise Unavailable("malformed URL map route object")
        for key, value in row.items():
            if key in ("defaultService", "service", "backendService"):
                if not isinstance(value, str):
                    raise Unavailable("malformed backend reference")
                references.add(value)
            elif isinstance(value, dict):
                visit(value)
            elif isinstance(value, list):
                for child in value:
                    if isinstance(child, dict):
                        visit(child)
    visit(item)
    return references


def map_logging(item, index):
    get(item, "name", str)
    references = backend_references(item)
    if not references:
        if "defaultUrlRedirect" in item:
            get(item, "defaultUrlRedirect", dict)
            return "NOT_APPLICABLE", {"reason": "Redirect-only URL map has no backend"}
        return unknown("no route/backend declaration")
    services = complete_items(index, "backend_service")
    buckets = complete_items(index, "backend_bucket")
    failed, configured, bucket_refs = [], [], []
    for reference in sorted(references):
        service_rows = [row for row in services if get(row, "selfLink", str) == reference]
        bucket_rows = [row for row in buckets if get(row, "selfLink", str) == reference]
        if len(service_rows) + len(bucket_rows) != 1:
            return unknown("backend relation missing or ambiguous", reference=reference)
        if bucket_rows:
            bucket_refs.append(reference)
            continue
        config = optional(service_rows[0], "logConfig", {}, dict)
        if not optional(config, "enable", False, bool):
            failed.append(reference)
        configured.append(reference)
    if not configured:
        return "NOT_APPLICABLE", {"reason": "Source covers backend services, not backend bucket logging", "backend_buckets": bucket_refs}
    return result(bool(failed), backend_services_without_logging=failed, backend_buckets=bucket_refs,
        semantics="All declared URL-map backend service routes, not live request completeness")


cid = rule("compute_url_map_backend_logging", "url_map", map_logging,
    {"name": "map", "defaultService": "projects/p/global/backendServices/good"},
    {"name": "map", "defaultService": "projects/p/global/backendServices/good", "pathMatchers": [{"pathRules": [{"service": "projects/p/global/backendServices/bad"}]}]},
    ["url_map", "backend_service", "backend_bucket"])
CASES[cid]["index"] = {"collections": {kind: [{"status": "collected"}] for kind in ("backend_service", "backend_bucket")}, "backend_bucket": [],
    "backend_service": [{"data": {"selfLink": "projects/p/global/backendServices/good", "logConfig": {"enable": True}}}, {"data": {"selfLink": "projects/p/global/backendServices/bad", "logConfig": {"enable": False}}}]}


def contacts(item, index):
    name = get(item, "name", str)
    if not name.startswith("organizations/"):
        return "NOT_APPLICABLE", {"reason": "Organization contact subscription control"}
    rows = [row for row in complete_items(index, "essential_contact") if get(row, "name", str).startswith(name + "/contacts/")]
    categories = set()
    for row in rows:
        values = get(row, "notificationCategorySubscriptions", list)
        if any(not isinstance(value, str) for value in values):
            raise Unavailable("malformed notification category subscriptions")
        categories.update(values)
    required = {"LEGAL", "SECURITY", "SUSPENSION", "TECHNICAL", "TECHNICAL_INCIDENTS"}
    return result("ALL" not in categories and not required.issubset(categories), configured_categories=sorted(categories),
        semantics="Declared organization contact subscriptions, not delivery or contact validation proof")


cid = rule("organization_essential_contacts_complete", "organization", contacts, {"name": "organizations/o"}, {"name": "organizations/q"}, ["organization", "essential_contact"])
CASES[cid]["index"] = {"collections": {"essential_contact": [{"status": "collected"}]}, "essential_contact": [{"data": {"name": "organizations/o/contacts/c", "notificationCategorySubscriptions": ["ALL"]}}]}


def approval(item, index):
    get(item, "name", str)
    enrollments = list_of_objects(optional(item, "enrolledServices", [], list))
    blocking = [get(row, "cloudProduct", str) for row in enrollments if get(row, "enrollmentLevel", str) == "BLOCK_ALL"]
    if not blocking and optional(item, "enrolledAncestor", False, bool):
        return unknown("ancestor enrollment requires parent settings metadata; notification emails alone are not enrollment")
    return result(not blocking, enrolled_products=blocking, semantics="Explicit Access Approval enrollment; notifications are separate")


rule("access_approval_explicit_enrollment", "access_approval_settings", approval,
    {"name": "projects/p/accessApprovalSettings", "enrolledServices": [{"cloudProduct": "all", "enrollmentLevel": "BLOCK_ALL"}]},
    {"name": "projects/p/accessApprovalSettings", "notificationEmails": []})
