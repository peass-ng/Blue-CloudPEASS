"""claude_gcp_k8s: IAM, logging, storage, KMS, Cloud SQL, BigQuery, Secret Manager, Pub/Sub and GKE predicates.

Declared configuration only: no effective-access, reachability or runtime claims. Missing, denied or
malformed facts are UNKNOWN; absence-based results require complete scoped inventories.
"""
from __future__ import annotations
from decimal import Decimal
import re
from urllib.parse import urlparse

from .claude_gcp_k8s_common import (gcp, gid, cases, strings, opt_strings, scope_index, captured_at, parse_time,
    duration_seconds, bindings, active_ingress, is_public, source_ranges, fw, PUBLIC_MEMBERS, SCOPE, result, unknown,
    get, optional, list_of_objects, complete_items, context_scope, Unavailable, CASES)
from .facts import omitted, principal_trust_lists, PUBLIC_PRINCIPALS

IAM_IDS = []
ROOT_POLICY = re.compile(r"(//cloudresourcemanager\.googleapis\.com/)?(projects|folders|organizations)/[^/]+")
PROJECT_POLICY = re.compile(r"(//cloudresourcemanager\.googleapis\.com/)?projects/[^/]+")


def track(cid):
    IAM_IDS.append(cid)
    return cid


def public_bindings(policy):
    return [{"role": b["role"], "members": sorted(set(b["members"]) & set(PUBLIC_MEMBERS)), "condition": b["condition"]}
            for b in bindings(policy) if set(b["members"]) & set(PUBLIC_MEMBERS)]


def project_prefixes(item):
    project = get(item, "projectId", str)
    number = optional(item, "name", "", str).removeprefix("projects/")
    return ["projects/" + value + "/" for value in {project, number} if value]


def in_project(name, prefixes):
    return any(name.startswith(prefix) for prefix in prefixes)


# --- Cloud Storage --------------------------------------------------------------------------------------------

def sink_buckets(index):
    names = set()
    for sink in complete_items(index, "log_sink"):
        destination = get(sink, "destination", str)
        if destination.startswith("storage.googleapis.com/"):
            names.add(destination.split("/", 1)[1])
    return names


def log_bucket(slug, title, evaluate_bucket, good, bad, *, severity="medium", control="AU-9", remediation, malformed=None):
    @gcp(slug, "bucket", title, severity=severity, control=control, category="hardening", dependencies=["bucket", "log_sink"],
         remediation=remediation)
    def evaluate(item, index):
        name = get(item, "name", str)
        if name not in sink_buckets(index):
            return "NOT_APPLICABLE", {"reason": "Bucket is not a Cloud Storage destination of a same-scope log sink"}
        failed, evidence = evaluate_bucket(item)
        return result(failed, bucket=name, **evidence,
                      semantics="Same-scope sink destination declaration; sinks in other projects/folders are not joined")
    cid = track(gid(slug))
    sinks = scope_index({"log_sink": [{"name": "projects/p/sinks/s", "destination": "storage.googleapis.com/logs"}]})
    cases(cid, {"name": "logs", **good}, {"name": "logs", **bad}, pass_index=sinks, fail_index=sinks,
          not_applicable={"name": "other", **bad}, not_applicable_index=sinks,
          malformed={"name": "logs", **(malformed or {"retentionPolicy": "locked"})})
    return cid


def _locked(bucket):
    policy = optional(bucket, "retentionPolicy", None, dict)
    locked = optional(policy, "isLocked", False, bool) if policy is not None else False
    return not locked, {"retention_policy_declared": policy is not None, "retention_locked": locked}


def _retention(bucket):
    policy = optional(bucket, "retentionPolicy", None, dict)
    period = get(policy, "retentionPeriod", (str, int)) if policy is not None else None
    return policy is None, {"retention_period": period}


def _log_public(bucket):
    public = public_bindings(get(bucket, "iamPolicy", dict))
    return bool(public), {"public_bindings": public}


def _log_versioning(bucket):
    enabled = optional(optional(bucket, "versioning", {}, dict), "enabled", False, bool)
    return not enabled, {"versioning_enabled": enabled}


log_bucket("bucket.log_sink_retention_locked", "Log sink destination bucket has a locked retention policy", _locked,
           {"retentionPolicy": {"retentionPeriod": "31536000", "isLocked": True}}, {"retentionPolicy": {"retentionPeriod": "1"}},
           remediation="Configure and lock a retention policy on Cloud Storage buckets that receive log sink exports.")
log_bucket("bucket.log_sink_retention_policy", "Log sink destination bucket has a retention policy", _retention,
           {"retentionPolicy": {"retentionPeriod": "2592000"}}, {},
           remediation="Configure a retention policy on Cloud Storage buckets that receive log sink exports.")
log_bucket("bucket.log_sink_not_public", "Log sink destination bucket is not publicly accessible", _log_public,
           {"iamPolicy": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["group:sec@example.com"]}]}},
           {"iamPolicy": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}},
           severity="high", control="AC-3", malformed={"iamPolicy": {"bindings": [{"role": "r", "members": "allUsers"}]}},
           remediation="Remove allUsers/allAuthenticatedUsers bindings from buckets that receive log exports.")
log_bucket("bucket.log_sink_versioning", "Log sink destination bucket has object versioning enabled", _log_versioning,
           {"versioning": {"enabled": True}}, {"versioning": {"enabled": False}}, control="CP-9",
           malformed={"versioning": {"enabled": "yes"}},
           remediation="Enable object versioning on buckets that receive log sink exports.")


@gcp("bucket.retention_90_days", "bucket", "Bucket retention policy is at least 90 days", control="AU-11", category="hardening",
     remediation="Configure a bucket retention policy of at least 90 days where the data class requires immutable retention.")
def bucket_retention(item, index):
    policy = optional(item, "retentionPolicy", None, dict)
    if policy is None:
        return result(True, retention_policy=None)
    raw = get(policy, "retentionPeriod", (str, int))
    if isinstance(raw, bool) or not str(raw).isdigit():
        raise Unavailable("malformed retentionPeriod")
    days = int(raw) // 86400
    return result(days < 90, retention_days=days)


cases(track(gid("bucket.retention_90_days")), {"retentionPolicy": {"retentionPeriod": "7776000"}},
      {"retentionPolicy": {"retentionPeriod": "86400"}}, malformed={"retentionPolicy": {"retentionPeriod": "90d"}})


@gcp("project.storage_vpc_service_controls", "project", "Project is protected by a VPC Service Controls perimeter restricting Cloud Storage",
     control="SC-7", category="network", dependencies=["project", "service_perimeter"],
     remediation="Add the project to a VPC Service Controls perimeter that restricts storage.googleapis.com.")
def storage_perimeter(item, index):
    number = get(item, "name", str)
    if not re.fullmatch(r"projects/[0-9]+", number):
        raise Unavailable("project number unavailable")
    protected = []
    for perimeter in complete_items(index, "service_perimeter"):
        status = optional(perimeter, "status", {}, dict)
        services = opt_strings(status, "restrictedServices")
        resources = opt_strings(status, "resources")
        if "storage.googleapis.com" in services and number in resources:
            protected.append(get(perimeter, "name", str))
    return result(not protected, perimeters=protected, semantics="Enforced perimeter status declarations; dry-run configs are not counted")


cases(track(gid("project.storage_vpc_service_controls")), {"name": "projects/123"}, {"name": "projects/123"},
      pass_index=scope_index({"service_perimeter": [{"name": "accessPolicies/1/servicePerimeters/p", "status": {
          "restrictedServices": ["storage.googleapis.com"], "resources": ["projects/123"]}}]}),
      fail_index=scope_index({"service_perimeter": [{"name": "accessPolicies/1/servicePerimeters/p", "status": {
          "restrictedServices": ["bigquery.googleapis.com"], "resources": ["projects/123"]}}]}), malformed={"name": "my-project"})


# --- Root IAM policy (project/folder/organization getIamPolicy) --------------------------------------------------

def root_only(item, project_only=False, direct=False):
    name = get(item, "name", str)
    if direct:
        # Only the direct getIamPolicy document carries auditConfigs; Cloud Asset copies do not.
        return bool(re.fullmatch(r"projects/[^/]+", name))
    return bool((PROJECT_POLICY if project_only else ROOT_POLICY).fullmatch(name))


def _storage_data_access_state(configs, services, log_types):
    declared = set()
    has_exemption = False
    for config in list_of_objects(configs):
        service = get(config, "service", str)
        for row in list_of_objects(optional(config, "auditLogConfigs", [], list)):
            log_type = get(row, "logType", str)
            if log_type not in ("ADMIN_READ", "DATA_READ", "DATA_WRITE"):
                raise Unavailable("unrecognized audit log type")
            members = optional(row, "exemptedMembers", [], list)
            if any(not isinstance(member, str) or not member.strip() or member != member.strip()
                   for member in members):
                raise Unavailable("malformed Data Access exemption")
            if service in services and log_type in log_types:
                declared.add(log_type)
                has_exemption |= bool(members)
    return declared, has_exemption


def audit_logs(slug, title, services, log_types):
    @gcp(slug, "iam_policy", title, control="AU-2", category="hardening",
         remediation="Enable Data Access audit logs (DATA_READ and DATA_WRITE) for the service, or allServices, in the "
                     "project, folder or organization IAM policy auditConfigs.")
    def evaluate(item, index):
        if not root_only(item, direct=True):
            return "NOT_APPLICABLE", {"reason": "Not the direct project getIamPolicy document"}
        if "_provenance" in item and get(item, "_provenance.representation", str) != "full":
            return "NOT_APPLICABLE", {"reason": "Not the direct full project getIamPolicy document"}
        direct, direct_exemptions = _storage_data_access_state(optional(item, "auditConfigs", [], list), services, log_types)
        has_effective = "effectiveAuditConfigs" in item or "effectiveAuditConfigs" in item.get("_coverage", {})
        if has_effective:
            entries = _effective_audit_entries(item, index)
            declared, exempted = set(), False
            for entry in entries:
                kinds, exclusions = _storage_data_access_state(get(entry, "auditConfigs", list), services, log_types)
                declared.update(kinds)
                exempted |= exclusions
            if log_types - declared:
                return result(True, declared_log_types=sorted(declared), missing_log_types=sorted(log_types - declared),
                              semantics="complete native project and ancestor audit policy")
            if exempted:
                raise Unavailable("Data Access exemptions prevent a universal logging claim")
            return result(False, declared_log_types=sorted(declared),
                          semantics="complete native project and ancestor audit policy")
        if "_provenance" in item and get(item, "_provenance.representation", str) == "full":
            raise Unavailable("native effective ancestor audit policy was not collected")
        if log_types <= direct and not direct_exemptions:
            return result(False, declared_log_types=sorted(direct))
        if direct_exemptions:
            raise Unavailable("Data Access exemptions prevent a universal logging claim")
        return "MANUAL", {"declared_log_types": sorted(direct), "required_log_types": sorted(log_types),
                          "reason": "Project policy lacks the audit config; folder/organization auditConfigs are inherited and were not joined"}
    cid = track(gid(slug))
    good = {"name": "projects/p", "bindings": [], "auditConfigs": [{"service": "allServices", "auditLogConfigs": [
        {"logType": t} for t in sorted(log_types)]}]}
    cases(cid, good, None, manual={"name": "projects/p", "bindings": []},
          not_applicable={"name": "projects/p/buckets/b", "bindings": []},
          malformed={"name": "projects/p", "auditConfigs": [{"service": 1}]})
    CASES[cid].pop("fail")
    return cid


audit_logs("project.storage_data_access_audit_logs", "Cloud Storage Data Access audit logs are enabled",
           {"storage.googleapis.com", "allServices"}, {"DATA_READ", "DATA_WRITE"})


def _effective_audit_entries(item, index):
    coverage = get(item, "_coverage.effectiveAuditConfigs", dict)
    if (get(coverage, "status", str) != "collected"
            or get(coverage, "collection_status", str) != "collected"
            or get(coverage, "ancestry_known", bool) is not True
            or get(coverage, "missing_scopes", list)
            or get(coverage, "malformed_scopes", list)):
        raise Unavailable("effective ancestor audit policy incomplete")
    entries = list_of_objects(get(item, "effectiveAuditConfigs", list))
    source_refs = get(coverage, "source_requests", list)
    if not source_refs or any(not isinstance(ref, str) or not ref for ref in source_refs):
        raise Unavailable("effective audit source requests unavailable")
    scopes = [get(entry, "scope", str) for entry in entries]
    project = get(item, "name", str)
    inherited = get(index, "context.metadata.inherited_scopes", list)
    ancestors = get(coverage, "ancestor_scopes", list)
    if (not scopes or scopes[0] != project or len(scopes) != len(set(scopes))
            or scopes[1:] != ancestors
            or any(scope.startswith("organizations/") for scope in scopes[1:-1])
            or any(scope not in inherited or not re.fullmatch(r"(?:folders|organizations)/[0-9]+", scope)
                   for scope in scopes[1:])):
        raise Unavailable("effective audit ancestry foreign or incomplete")
    ledger = list_of_objects(get(index, "context.metadata.source_requests", list))
    by_ref = {}
    for row in ledger:
        ref = get(row, "id", str)
        if ref in by_ref:
            raise Unavailable("duplicate native request identity")
        by_ref[ref] = row
    def exact_read(ref, url):
        row = by_ref.get(ref)
        if (row is None or get(row, "method", str) != "POST"
                or get(row, "status", str) != "collected" or get(row, "url", str) != url):
            raise Unavailable("native audit policy request is unavailable or foreign")
    ancestry_refs = get(coverage, "ancestry_source_requests", list)
    if len(ancestry_refs) != 1 or not isinstance(ancestry_refs[0], str):
        raise Unavailable("native project ancestry request unavailable")
    exact_read(ancestry_refs[0],
               f"https://cloudresourcemanager.googleapis.com/v1/{project}:getAncestry")
    union_refs = set()
    for entry in entries:
        refs = get(entry, "source_requests", list)
        if not refs or any(not isinstance(ref, str) or ref not in source_refs for ref in refs):
            raise Unavailable("ancestor audit source request unavailable")
        policy_scope = get(entry, "scope", str)
        for ref in refs:
            exact_read(ref, f"https://cloudresourcemanager.googleapis.com/v3/{policy_scope}:getIamPolicy")
            union_refs.add(ref)
    if union_refs != set(source_refs) or len(union_refs) != len(source_refs):
        raise Unavailable("effective audit request union mismatch")
    return entries


@gcp("project.audit_logs_configured", "iam_policy", "Project IAM policy declares a Cloud Audit Logs configuration", control="AU-2",
     category="hardening", remediation="Declare auditConfigs (Data Access audit logs) for allServices or the required services.")
def audit_any(item, index):
    if not root_only(item, direct=True):
        return "NOT_APPLICABLE", {"reason": "Not a project root IAM policy"}
    if "_provenance" in item and get(item, "_provenance.representation", str) != "full":
        return "NOT_APPLICABLE", {"reason": "Not the direct full project getIamPolicy document"}
    services = [get(c, "service", str) for c in list_of_objects(optional(item, "auditConfigs", [], list))]
    if services:
        return result(False, audit_config_services=services)
    # A missing project declaration can be supplied by a parent IAM policy.
    # Only the collector's complete, source-bound ancestry union can settle it.
    if "effectiveAuditConfigs" in item or "effectiveAuditConfigs" in item.get("_coverage", {}):
        entries = _effective_audit_entries(item, index)
        services = [get(config, "service", str) for entry in entries
                    for config in list_of_objects(get(entry, "auditConfigs", list))]
        return result(not services, audit_config_services=services,
                      semantics="complete project and ancestor IAM audit policy")
    if "_provenance" in item and get(item, "_provenance.representation", str) == "full":
        raise Unavailable("native effective ancestor audit policy was not collected")
    return "MANUAL", {"reason": "No project auditConfigs; folder/organization auditConfigs are inherited and were not joined"}


cases(track(gid("project.audit_logs_configured")), {"name": "projects/p", "auditConfigs": [{"service": "storage.googleapis.com"}]}, None,
      manual={"name": "projects/p", "bindings": []}, not_applicable={"name": "folders/1", "bindings": []},
      malformed={"name": "projects/p", "auditConfigs": [{"service": 1}]})
CASES[gid("project.audit_logs_configured")].pop("fail")


@gcp("iam_policy.no_all_users", "iam_policy", "Root IAM policy does not grant roles to allUsers", severity="critical", control="AC-3",
     category="exposure", remediation="Remove allUsers from project, folder and organization IAM bindings.")
def no_all_users(item, index):
    if not root_only(item):
        return "NOT_APPLICABLE", {"reason": "Not a project, folder or organization root IAM policy"}
    public = [b for b in bindings(item) if "allUsers" in b["members"]]
    return result(bool(public), public_roles=[b["role"] for b in public])


cases(track(gid("iam_policy.no_all_users")), {"name": "projects/p", "bindings": [{"role": "roles/viewer", "members": ["user:a@example.com"]}]},
      {"name": "projects/p", "bindings": [{"role": "roles/viewer", "members": ["allUsers"]}]},
      not_applicable={"name": "projects/p/topics/t", "bindings": []}, malformed={"name": "projects/p", "bindings": [{"role": "r"}]})


SA_ROLES = ("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator")


@gcp("iam_policy.no_project_sa_user_or_token_creator", "iam_policy",
     "Project IAM policy does not grant Service Account User or Token Creator at project level", severity="high", control="AC-6",
     category="least_privilege",
     remediation="Grant roles/iam.serviceAccountUser and roles/iam.serviceAccountTokenCreator on individual service accounts instead of the project.")
def project_sa_roles(item, index):
    if not root_only(item, project_only=True):
        return "NOT_APPLICABLE", {"reason": "Not a project root IAM policy"}
    hits = [b for b in bindings(item) if b["role"] in SA_ROLES and b["members"]]
    unconditional = [b for b in hits if not b["condition"]]
    if hits and not unconditional:
        return "MANUAL", {"conditional_bindings": hits, "reason": "Only IAM-conditioned project-level grants match"}
    return result(bool(unconditional), project_level_bindings=[{"role": b["role"], "members": b["members"]} for b in unconditional])


cases(track(gid("iam_policy.no_project_sa_user_or_token_creator")),
      {"name": "projects/p", "bindings": [{"role": "roles/viewer", "members": ["user:a@example.com"]}]},
      {"name": "projects/p", "bindings": [{"role": "roles/iam.serviceAccountTokenCreator", "members": ["serviceAccount:x@p.iam.gserviceaccount.com"]}]},
      not_applicable={"name": "organizations/1", "bindings": []},
      malformed={"name": "projects/p", "bindings": [{"role": "roles/iam.serviceAccountUser", "members": [3]}]})


# --- Service accounts, keys and workload identity ----------------------------------------------------------------

@gcp("service_account_key.age_100_days", "service_account_key", "User-managed service account key is not older than 100 days",
     control="IA-5", category="least_privilege",
     remediation="Rotate user-managed service account keys at least every 100 days, or replace them with keyless workload identity.")
def key_age_100(item, index):
    key_type = get(item, "keyType", str)
    if key_type == "SYSTEM_MANAGED":
        return "NOT_APPLICABLE", {"reason": "Google-managed key"}
    if key_type != "USER_MANAGED":
        return unknown("unrecognized key type")
    from datetime import datetime, timedelta, timezone
    captured = captured_at(item, index)
    created = parse_time(get(item, "validAfterTime", str))
    cutoff = datetime.combine(captured.date() - timedelta(days=100), datetime.min.time(), tzinfo=timezone.utc)
    return result(created <= cutoff, valid_after=created.isoformat(), cutoff=cutoff.isoformat(),
                  semantics="Key creation metadata at the captured UTC date")


cases(track(gid("service_account_key.age_100_days")),
      {"keyType": "USER_MANAGED", "validAfterTime": "2026-09-01T00:00:00Z", "_provenance": {"collected_at": "2026-10-10T12:00:00Z"}},
      {"keyType": "USER_MANAGED", "validAfterTime": "2026-01-01T00:00:00Z", "_provenance": {"collected_at": "2026-10-10T12:00:00Z"}},
      not_applicable={"keyType": "SYSTEM_MANAGED"}, malformed={"keyType": "USER_MANAGED", "validAfterTime": "old"})


UNUSED_DAYS = 180


def last_authentication(item):
    """Policy Analyzer serviceAccount(Key)LastAuthentication fact, when a collector supplies it."""
    activity = get(item, "_activity", dict)
    observed = get(activity, "observationEndTime", str)
    last = activity.get("lastAuthenticatedTime")
    return parse_time(observed), (parse_time(last) if last is not None else None)


@gcp("service_account.recently_used", "service_account", "Service account authenticated within the last 180 days", severity="low",
     control="AC-2", category="least_privilege",
     remediation="Disable or delete service accounts that have not authenticated within the review window after confirming they are unused.")
def account_unused(item, index):
    if optional(item, "disabled", False, bool):
        return "NOT_APPLICABLE", {"reason": "Service account is disabled"}
    observed, last = last_authentication(item)
    idle = None if last is None else (observed - last).days
    return result(last is None or idle > UNUSED_DAYS, last_authenticated=last.isoformat() if last else None, idle_days=idle,
                  semantics="Policy Analyzer observation window; absence means no authentication was observed in the window")


_activity = lambda last: {"_activity": {"observationEndTime": "2026-10-10T00:00:00Z", "lastAuthenticatedTime": last}}
cases(track(gid("service_account.recently_used")), {"email": "a@p.iam.gserviceaccount.com", **_activity("2026-10-01T00:00:00Z")},
      {"email": "a@p.iam.gserviceaccount.com", **_activity("2025-01-01T00:00:00Z")}, not_applicable={"disabled": True},
      malformed={"_activity": {"observationEndTime": 5}})


@gcp("service_account_key.recently_used", "service_account_key", "User-managed service account key authenticated within the last 180 days",
     severity="low", control="IA-5", category="least_privilege",
     remediation="Delete user-managed service account keys that have not been used within the review window.")
def key_unused(item, index):
    key_type = get(item, "keyType", str)
    if key_type == "SYSTEM_MANAGED" or optional(item, "disabled", False, bool):
        return "NOT_APPLICABLE", {"reason": "Google-managed or disabled key"}
    if key_type != "USER_MANAGED":
        return unknown("unrecognized key type")
    observed, last = last_authentication(item)
    idle = None if last is None else (observed - last).days
    return result(last is None or idle > UNUSED_DAYS, last_authenticated=last.isoformat() if last else None, idle_days=idle)


cases(track(gid("service_account_key.recently_used")), {"keyType": "USER_MANAGED", **_activity("2026-10-01T00:00:00Z")},
      {"keyType": "USER_MANAGED", **_activity("2025-01-01T00:00:00Z")}, not_applicable={"keyType": "SYSTEM_MANAGED"},
      malformed={"keyType": "USER_MANAGED", "_activity": {"observationEndTime": "x"}})


MULTI_TENANT_ISSUERS = {"token.actions.githubusercontent.com", "gitlab.com", "accounts.google.com", "app.terraform.io"}


@gcp("workload_identity_provider.multi_tenant_condition", "workload_identity_provider",
     "Workload identity provider trusting a multi-tenant OIDC issuer enforces an attribute condition", severity="high",
     control="IA-8", category="least_privilege",
     remediation="Add an attributeCondition (for example on repository/owner/namespace claims) to providers that trust shared issuers.")
def wif_condition(item, index):
    state = get(item, "state", str)
    if optional(item, "disabled", False, bool) or state != "ACTIVE":
        return "NOT_APPLICABLE", {"reason": "Provider disabled or not active", "state": state}
    if optional(item, "attributeCondition", "", str):
        return result(False, attribute_condition=True)
    oidc = optional(item, "oidc", None, dict)
    if oidc is None:
        return "NOT_APPLICABLE", {"reason": "Not an OIDC provider"}
    issuer = get(oidc, "issuerUri", str)
    host = urlparse(issuer).hostname or issuer.lower()
    return result(host in MULTI_TENANT_ISSUERS, issuer_host=host, attribute_condition=False)


cases(track(gid("workload_identity_provider.multi_tenant_condition")),
      {"state": "ACTIVE", "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"}, "attributeCondition": "assertion.repository_owner=='acme'"},
      {"state": "ACTIVE", "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"}},
      not_applicable={"state": "DELETED"}, malformed={"state": "ACTIVE", "oidc": {"issuerUri": 1}})


@gcp("organization.essential_contacts_any", "organization", "Organization has at least one Essential Contact", severity="low",
     control="IR-6", category="hardening", dependencies=["organization", "essential_contact"],
     remediation="Configure Essential Contacts for the organization (security, technical and legal categories).")
def any_contact(item, index):
    name = get(item, "name", str)
    if not name.startswith("organizations/"):
        return "NOT_APPLICABLE", {"reason": "Organization-level control"}
    contacts = [get(c, "name", str) for c in complete_items(index, "essential_contact")
                if get(c, "name", str).startswith(name + "/contacts/")]
    return result(not contacts, contacts=len(contacts))


cases(track(gid("organization.essential_contacts_any")), {"name": "organizations/1"}, {"name": "organizations/1"},
      pass_index=scope_index({"essential_contact": [{"name": "organizations/1/contacts/c"}]}, "organizations/1"),
      fail_index=scope_index({"essential_contact": [{"name": "organizations/2/contacts/c"}]}, "organizations/1"),
      not_applicable={"name": "folders/1"}, malformed={"name": 1})


def service_rows(item, index, service_name):
    rows = [r for r in complete_items(index, "service_usage")
            if in_project(get(r, "name", str), project_prefixes(item)) and get(r, "name", str).endswith("/services/" + service_name)]
    if len(rows) != 1:
        raise Unavailable("service state not collected or ambiguous: " + service_name)
    state = get(rows[0], "state", str)
    if state not in ("ENABLED", "DISABLED"):
        raise Unavailable("unrecognized service state")
    return state


def service_state(slug, title, service_name, want, *, severity="medium", control="CM-7", remediation):
    @gcp(slug, "project", title, severity=severity, control=control, dependencies=["project", "service_usage"], remediation=remediation)
    def evaluate(item, index):
        state = service_rows(item, index, service_name)
        return result(state != want, service=service_name, state=state)
    cid = track(gid(slug))
    usage = lambda state: scope_index({"service_usage": [{"name": "projects/123/services/" + service_name, "state": state}]})
    other = "DISABLED" if want == "ENABLED" else "ENABLED"
    cases(cid, {"projectId": "p", "name": "projects/123"}, {"projectId": "p", "name": "projects/123"},
          pass_index=usage(want), fail_index=usage(other), malformed={"projectId": 5})
    return cid


service_state("project.container_scanning_api_enabled", "Container Scanning API is enabled", "containerscanning.googleapis.com",
              "ENABLED", control="RA-5", remediation="Enable containerscanning.googleapis.com (Artifact Analysis) for registries in the project.")
service_state("project.gemini_api_disabled", "Generative Language (Gemini) API is disabled where not required",
              "generativelanguage.googleapis.com", "DISABLED", severity="low",
              remediation="Disable generativelanguage.googleapis.com in projects that do not need it, or restrict API keys to it.")


# --- Cloud Logging metric alerts and sinks -------------------------------------------------------------------------

def loose(text):
    """Whitespace-tolerant regex for a literal prowler metric filter."""
    out = ""
    for char in text:
        out += r"\s*" + re.escape(char) + r"\s*" if char in "=():" else (r"\s+" if char == " " else re.escape(char))
    return out


METRIC_PATTERNS = {
    "audit_configuration_changes": (
        r'\s*protoPayload.methodName\s*=\s*"SetIamPolicy"\s*AND\s*protoPayload.serviceData.policyDelta.auditConfigDeltas:\*\s*',),
    "custom_role_changes": (
        r'\s*resource\.type\s*=\s*"iam_role"\s*AND\s*\(\s*protoPayload\.methodName\s*=\s*"google\.iam\.admin\.v1\.CreateRole"\s*OR\s*protoPayload\.methodName\s*=\s*"google\.iam\.admin\.v1\.DeleteRole"\s*OR\s*protoPayload\.methodName\s*=\s*"google\.iam\.admin\.v1\.UpdateRole"\s*',),
    "custom_role_changes_with_undelete": (
        r'\s*resource\.type\s*=\s*"iam_role"\s*AND\s*\(\s*protoPayload\.methodName\s*=\s*"google\.iam\.admin\.v1\.CreateRole"\s*OR\s*protoPayload\.methodName\s*=\s*"google\.iam\.admin\.v1\.DeleteRole"\s*OR\s*protoPayload\.methodName\s*=\s*"google\.iam\.admin\.v1\.UpdateRole"\s*OR\s*protoPayload\.methodName\s*=\s*"google\.iam\.admin\.v1\.UndeleteRole"\s*\)',),
    "firewall_rule_changes": (
        r'\s*resource\.type\s*=\s*"gce_firewall_rule"\s*AND\s*\(\s*protoPayload\.methodName\s*:\s*"compute\.firewalls\.patch"\s*OR\s*protoPayload\.methodName\s*:\s*"compute\.firewalls\.insert"\s*OR\s*protoPayload\.methodName\s*:\s*"compute\.firewalls\.delete"\s*\)',),
    "network_changes_beta_methods": (
        r'\s*resource\.type\s*=\s*gce_network\s*AND\s*\(\s*protoPayload\.methodName\s*=\s*"beta\.compute\.networks\.insert"\s*OR\s*protoPayload\.methodName\s*=\s*"beta\.compute\.networks\.patch"\s*OR\s*protoPayload\.methodName\s*=\s*"v1\.compute\.networks\.delete"\s*OR\s*protoPayload\.methodName\s*=\s*"v1\.compute\.networks\.removePeering"\s*OR\s*protoPayload\.methodName\s*=\s*"v1\.compute\.networks\.addPeering"\s*\)',),
    "network_changes": (loose('resource.type="gce_network" AND (protoPayload.methodName:"compute.networks.insert" OR protoPayload.methodName:"compute.networks.patch" OR protoPayload.methodName:"compute.networks.delete" OR protoPayload.methodName:"compute.networks.removePeering" OR protoPayload.methodName:"compute.networks.addPeering")'),),
    "route_changes": (
        r'\s*resource\.type\s*=\s*"gce_route"\s*AND\s*\(\s*protoPayload\.methodName\s*:\s*"compute\.routes\.delete"\s*OR\s*protoPayload\.methodName\s*:\s*"compute\.routes\.insert"\s*\)',),
    "project_ownership_changes": (
        r'\s*\(protoPayload.serviceName\s*=\s*"cloudresourcemanager.googleapis.com"\s*\)\s*AND\s*\(\s*ProjectOwnership\s*OR\s*projectOwnerInvitee\s*\)\s*OR\s*\(\s*protoPayload.serviceData.policyDelta.bindingDeltas.action\s*=\s*"REMOVE"\s*AND\s*protoPayload.serviceData.policyDelta.bindingDeltas.role\s*=\s*"roles/owner"\s*\)\s*OR\s*\(\s*protoPayload.serviceData.policyDelta.bindingDeltas.action\s*=\s*"ADD"\s*AND\s*protoPayload.serviceData.policyDelta.bindingDeltas.role\s*=\s*"roles/owner"\s*\)\s*',),
    "sql_instance_configuration_changes": (r'\s*protoPayload.methodName\s*=\s*"cloudsql.instances.update"\s*',),
    "bucket_iam_changes": (
        r'\s*resource\.type\s*=\s*"gcs_bucket"\s*AND\s*protoPayload\.methodName\s*=\s*"storage\.setIamPermissions"',),
    "compute_configuration_changes": (loose('protoPayload.serviceName="compute.googleapis.com"'),),
}
SAMPLE_FILTERS = {
    "audit_configuration_changes": 'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*',
    "custom_role_changes": 'resource.type="iam_role" AND (protoPayload.methodName="google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole")',
    "custom_role_changes_with_undelete": 'resource.type="iam_role" AND (protoPayload.methodName = "google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole" OR protoPayload.methodName="google.iam.admin.v1.UndeleteRole")',
    "firewall_rule_changes": 'resource.type="gce_firewall_rule" AND (protoPayload.methodName:"compute.firewalls.patch" OR protoPayload.methodName:"compute.firewalls.insert" OR protoPayload.methodName:"compute.firewalls.delete")',
    "network_changes_beta_methods": 'resource.type=gce_network AND (protoPayload.methodName="beta.compute.networks.insert" OR protoPayload.methodName="beta.compute.networks.patch" OR protoPayload.methodName="v1.compute.networks.delete" OR protoPayload.methodName="v1.compute.networks.removePeering" OR protoPayload.methodName="v1.compute.networks.addPeering")',
    "network_changes": 'resource.type="gce_network" AND (protoPayload.methodName:"compute.networks.insert" OR protoPayload.methodName:"compute.networks.patch" OR protoPayload.methodName:"compute.networks.delete" OR protoPayload.methodName:"compute.networks.removePeering" OR protoPayload.methodName:"compute.networks.addPeering")',
    "route_changes": 'resource.type="gce_route" AND (protoPayload.methodName:"compute.routes.delete" OR protoPayload.methodName:"compute.routes.insert")',
    "project_ownership_changes": '(protoPayload.serviceName="cloudresourcemanager.googleapis.com") AND (ProjectOwnership OR projectOwnerInvitee) OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner") OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")',
    "sql_instance_configuration_changes": 'protoPayload.methodName="cloudsql.instances.update"',
    "bucket_iam_changes": 'resource.type="gcs_bucket" AND protoPayload.methodName="storage.setIamPermissions"',
    "compute_configuration_changes": 'protoPayload.serviceName="compute.googleapis.com"',
}
METRIC_IDS = {}


def alert_filters(alert):
    filters = []
    for condition in list_of_objects(get(alert, "conditions", list)):
        for key in ("conditionThreshold", "conditionAbsent"):
            body = optional(condition, key, None, dict)
            if body is not None:
                filters.append(get(body, "filter", str))
        mql = optional(condition, "conditionMonitoringQueryLanguage", None, dict)
        if mql is not None:
            filters.append(get(mql, "query", str))
    return filters


def metric_alert(name, patterns):
    slug = "logging.metric_alert_" + name

    @gcp(slug, "project", "Log metric and enabled alert exist for " + name.replace("_", " "), control="AU-6", category="hardening",
         dependencies=["project", "logging_metric", "monitoring_alert_policy"],
         remediation="Create a log-based metric with the reference filter and an enabled Cloud Monitoring alert policy on it.")
    def evaluate(item, index):
        prefixes = project_prefixes(item)
        metric_types = []
        for metric in complete_items(index, "logging_metric"):
            if not in_project(get(metric, "name", str), prefixes) or optional(metric, "disabled", False, bool):
                continue
            if any(re.search(p, get(metric, "filter", str)) for p in patterns):
                metric_types.append(get(metric, "metricDescriptor.type", str))
        alerted = []
        for alert in complete_items(index, "monitoring_alert_policy"):
            if not in_project(get(alert, "name", str), prefixes) or not get(alert, "enabled", bool):
                continue
            filters = alert_filters(alert)
            for metric_type in metric_types:
                if any(re.search(r'metric\.type\s*=\s*"' + re.escape(metric_type) + '"', f) for f in filters):
                    alerted.append({"alert": alert["name"], "metric_type": metric_type})
        return result(not alerted, matching_metrics=metric_types, alerting=alerted,
                      semantics="Same-project metric and enabled alert declarations; cross-project metrics scopes and "
                                "notification delivery are not evaluated")
    cid = track(gid(slug))
    METRIC_IDS[name] = cid
    metric = {"name": "projects/p/metrics/m", "filter": SAMPLE_FILTERS[name],
              "metricDescriptor": {"type": "logging.googleapis.com/user/m"}}
    alert = {"name": "projects/p/alertPolicies/a", "enabled": True,
             "conditions": [{"conditionThreshold": {"filter": 'metric.type="logging.googleapis.com/user/m" resource.type="global"'}}]}
    cases(cid, {"projectId": "p"}, {"projectId": "p"},
          pass_index=scope_index({"logging_metric": [metric], "monitoring_alert_policy": [alert]}),
          fail_index=scope_index({"logging_metric": [metric], "monitoring_alert_policy": [{**alert, "enabled": False}]}),
          malformed={"projectId": 1})
    return cid


for _name, _patterns in METRIC_PATTERNS.items():
    metric_alert(_name, _patterns)


def _bound_inherited_sinks(item, index):
    """Collector-proven complete ancestor sink chain for this exact project."""
    scope = context_scope(index)
    project_id = get(item, "projectId", str)
    name = optional(item, "name", "", str)
    if not project_id or (name and not re.fullmatch(r"projects/[1-9][0-9]*", name)):
        raise Unavailable("malformed project identity")
    aliases = {project_id}
    if name:
        aliases.add(name.split("/", 1)[1])
    if scope != "projects/" + project_id and scope != name:
        raise Unavailable("project identity differs from evaluation scope")
    ancestry = list_of_objects(get(item, "_ancestry", list))
    if not ancestry:
        raise Unavailable("project ancestry is empty")
    chain, seen, organization_seen = [], set(), False
    for position, row in enumerate(ancestry):
        resource = get(row, "resourceId", dict)
        kind, identifier = get(resource, "type", str), get(resource, "id", str)
        if position == 0:
            if kind != "project" or identifier not in aliases:
                raise Unavailable("foreign project ancestry root")
            continue
        if (kind not in ("folder", "organization") or not re.fullmatch(r"[1-9][0-9]*", identifier)
                or organization_seen or (kind, identifier) in seen):
            raise Unavailable("malformed project ancestry chain")
        seen.add((kind, identifier))
        chain.append(kind + "s/" + identifier)
        organization_seen = kind == "organization"
    coverage = get(get(item, "_coverage", dict), "_inherited_sinks", dict)
    if (get(coverage, "status", str) != "collected"
            or get(coverage, "collection_status", str) != "collected"
            or get(coverage, "ancestors", list) != chain):
        raise Unavailable("inherited sink coverage does not match ancestry")
    refs = get(coverage, "source_requests", list)
    if (any(not isinstance(ref, str) or not ref for ref in refs)
            or len(set(refs)) != len(refs) or len(refs) < len(chain)):
        raise Unavailable("inherited sink request provenance incomplete")
    provenance = get(item, "_provenance", dict)
    project_refs = get(provenance, "source_requests", list)
    if not set(refs) <= set(project_refs):
        raise Unavailable("ancestor sink requests absent from project provenance")
    metadata = get(get(index, "context", dict), "metadata", dict)
    request_rows = list_of_objects(get(metadata, "source_requests", list))
    requests = {get(row, "id", str): row for row in request_rows}
    if len(requests) != len(request_rows):
        raise Unavailable("duplicate source request identity")
    ancestry_url = "https://cloudresourcemanager.googleapis.com/v1/" + scope + ":getAncestry"
    if not any(ref in requests and get(requests[ref], "method", str) == "POST"
               and get(requests[ref], "url", str) == ancestry_url
               and get(requests[ref], "scope", str) == scope
               and get(requests[ref], "status", str) == "collected" for ref in project_refs):
        raise Unavailable("project ancestry source request unverified")
    for ancestor in chain:
        expected_url = "https://logging.googleapis.com/v2/" + ancestor + "/sinks"
        if not any(ref in requests and get(requests[ref], "method", str) == "GET"
                   and get(requests[ref], "url", str) == expected_url
                   and get(requests[ref], "scope", str) == ancestor
                   and get(requests[ref], "status", str) == "collected" for ref in refs):
            raise Unavailable("ancestor sink source request unverified")
    for ref in refs:
        if (ref not in requests or get(requests[ref], "status", str) != "collected"
                or get(requests[ref], "method", str) != "GET"
                or get(requests[ref], "scope", str) not in chain
                or get(requests[ref], "url", str) !=
                    "https://logging.googleapis.com/v2/" + get(requests[ref], "scope", str) + "/sinks"):
            raise Unavailable("foreign or incomplete ancestor sink source")
    sinks = list_of_objects(get(item, "_inherited_sinks", list))
    seen_sinks = set()
    for sink in sinks:
        ancestor, sink_name = get(sink, "ancestor", str), get(sink, "name", str)
        if sink_name in seen_sinks:
            raise Unavailable("duplicate inherited sink identity")
        seen_sinks.add(sink_name)
        if (ancestor not in chain or not sink_name.startswith(ancestor + "/sinks/")
                or not sink_name[len(ancestor) + len("/sinks/"):]
                or "/" in sink_name[len(ancestor) + len("/sinks/"):]):
            raise Unavailable("foreign inherited sink identity")
    return sinks, chain


@gcp("logging.project_sink_all_entries", "project", "Project has an enabled log sink exporting all entries", control="AU-9",
     category="hardening", dependencies=["project", "log_sink"],
     remediation="Create an enabled project (or aggregated organization) sink with an empty filter, no active exclusions and a destination.")
def sink_all_entries(item, index):
    from .claude2_gcp_logging import all_entries
    prefixes = project_prefixes(item)
    local = []
    for sink in complete_items(index, "log_sink"):
        name = get(sink, "name", str)
        if not any(re.fullmatch(re.escape(prefix) + r"sinks/[^/]+", name) for prefix in prefixes):
            raise Unavailable("foreign or malformed project sink identity")
        local.append(sink)
    local_matches = [get(sink, "name", str) for sink in local if all_entries(sink)]
    # Older signed fixtures contain no native project provenance. Preserve
    # their documented same-project PASS / no-local MANUAL decisions only there.
    if "_provenance" not in item and "_ancestry" not in item and "_coverage" not in item:
        if local_matches:
            return result(False, sinks=local_matches, source="project")
        return "MANUAL", {"reason": "Legacy fixture has no collected project ancestry"}
    inherited, chain = _bound_inherited_sinks(item, index)
    inherited_matches, intercepting = [], []
    for sink in inherited:
        name = get(sink, "name", str)
        include = optional(sink, "includeChildren", False, bool)
        intercept = optional(sink, "interceptChildren", False, bool)
        if intercept and (not include or not re.fullmatch(
                r"logging\.googleapis\.com/projects/[^/]+", get(sink, "destination", str))):
            raise Unavailable("invalid intercepting sink configuration")
        if include and all_entries(sink):
            inherited_matches.append(name)
        if include and intercept and not optional(sink, "disabled", False, bool):
            intercepting.append(name)
    if inherited_matches:
        # GetAncestry orders nearest parent first. An interceptor higher in
        # that chain can stop entries before they reach a descendant sink.
        positions = {ancestor: position for position, ancestor in enumerate(chain)}
        owners = {get(sink, "name", str): get(sink, "ancestor", str) for sink in inherited}
        unshadowed = [name for name in inherited_matches if not any(
            positions[owners[interceptor]] > positions[owners[name]] for interceptor in intercepting)]
        if unshadowed:
            return result(False, sinks=unshadowed, source="ancestor aggregated sink",
                          semantics="Complete declared ancestor route, not delivery proof")
        return unknown("Higher ancestor interceptor may divert entries from aggregated sink",
                       ancestor_sinks=intercepting)
    if local_matches:
        if intercepting:
            return unknown("Active intercepting ancestor may divert entries from project sink",
                           ancestor_sinks=intercepting)
        return result(False, sinks=local_matches, source="project",
                      semantics="Complete declared project route, not delivery proof")
    return result(True, sinks=[], ancestors=chain,
                  semantics="Complete project and ancestor sink inventories contain no all-entries route")



cases(track(gid("logging.project_sink_all_entries")), {"projectId": "p"}, None,
      pass_index=scope_index({"log_sink": [{"name": "projects/p/sinks/all", "destination": "storage.googleapis.com/b"}]}),
      manual={"projectId": "p"},
      manual_index=scope_index({"log_sink": [{"name": "projects/p/sinks/all", "filter": "severity>=ERROR", "destination": "x"}]}),
      malformed={"projectId": 1})
CASES[gid("logging.project_sink_all_entries")].pop("fail")


# --- Cloud KMS ------------------------------------------------------------------------------------------------------

@gcp("kms_key.users_limited_to_3", "kms_key", "KMS key is not public and no IAM binding lists more than three members", control="AC-6",
     category="least_privilege", remediation="Remove public members and narrow each KMS key IAM binding to at most three principals.")
def kms_users(item, index):
    rows = bindings(get(item, "iamPolicy", dict))
    public = [b["role"] for b in rows if set(b["members"]) & set(PUBLIC_MEMBERS)]
    broad = [{"role": b["role"], "members": len(b["members"])} for b in rows if len(b["members"]) > 3]
    return result(bool(public or broad), public_roles=public, broad_bindings=broad)


cases(track(gid("kms_key.users_limited_to_3")),
      {"iamPolicy": {"bindings": [{"role": "roles/cloudkms.cryptoKeyDecrypter", "members": ["user:a@x.com", "user:b@x.com"]}]}},
      {"iamPolicy": {"bindings": [{"role": "roles/cloudkms.cryptoKeyDecrypter", "members": ["user:a@x.com", "user:b@x.com", "user:c@x.com", "user:d@x.com"]}]}},
      malformed={"iamPolicy": {"bindings": [{"role": "r", "members": "x"}]}})


@gcp("kms_key.rotation_100_days", "kms_key", "KMS key automatic rotation period is at most 100 days", severity="high", control="SC-12",
     category="hardening", remediation="Set rotationPeriod to 100 days (8640000s) or less on symmetric KMS keys.")
def kms_rotation_100(item, index):
    purpose = get(item, "purpose", str)
    if purpose != "ENCRYPT_DECRYPT":
        return "NOT_APPLICABLE", {"reason": "Automatic rotation applies to symmetric encryption keys", "purpose": purpose}
    state = get(item, "primary.state", str)
    if state in ("DESTROYED", "DESTROY_SCHEDULED", "DISABLED"):
        return "NOT_APPLICABLE", {"primary_state": state}
    period = optional(item, "rotationPeriod", None, str)
    if period is None:
        return result(True, rotation_period=None, semantics="No automatic rotation declared")
    seconds = duration_seconds(period)
    return result(seconds > 8640000, rotation_seconds=seconds)


_sym = {"purpose": "ENCRYPT_DECRYPT"}
cases(track(gid("kms_key.rotation_100_days")), {**_sym, "primary": {"state": "ENABLED"}, "rotationPeriod": "8640000s"},
      {**_sym, "primary": {"state": "ENABLED"}, "rotationPeriod": "8640001s"}, not_applicable={"purpose": "ASYMMETRIC_SIGN"},
      malformed={**_sym, "primary": {"state": "ENABLED"}, "rotationPeriod": "100d"})


# --- Principal trust (gcp-perimeter *_policy_shared_access) -------------------------------------------------------

TRUST_FIELDS = (("user", "trusted_users"), ("group", "trusted_groups"), ("domain", "trusted_domains"),
                ("serviceAccount", "trusted_service_accounts"))
SHARED_KINDS = {"disk": "disk", "image": "image", "instance": "instance", "node_group": "node_group",
                "node_template": "node_template", "resource_policy": "resource_policy", "subnetwork": "subnetwork",
                "service_account": "service_account", "kms_key": "kms_key", "kms_key_ring": "kms_key_ring",
                "pubsub_subscription": "pubsub_subscription", "pubsub_topic": "pubsub_topic", "bucket": "bucket"}
SHARED_IDS = {}


def shared_access(kind):
    slug = kind + ".policy_shared_access"

    @gcp(slug, kind, kind.replace("_", " ").capitalize() + " IAM policy grants access only to trusted principals", control="AC-3",
         category="exposure", remediation="Remove IAM bindings to principals outside the approved user, group, domain and "
                                          "service-account lists, or add vetted principals to the trust lists.")
    def evaluate(item, index):
        rows = list_of_objects(get(item, "iamPolicy.bindings", list))
        if not rows:
            return "NOT_APPLICABLE", {"reason": "Empty IAM policy"}
        approved = principal_trust_lists(get(index, "context.metadata", dict))
        untrusted, project_members = [], []
        for binding in rows:
            members = strings(get(binding, "members", list), "binding members")
            role = get(binding, "role", str)
            for member in members:
                if member.startswith("project"):
                    project_members.append(member)
                    continue
                prefix, separator, identity = member.partition(":")
                if approved is None:
                    if member in PUBLIC_PRINCIPALS:
                        untrusted.append({"principal": member, "role": role, "condition": binding.get("condition")})
                    continue
                if not separator or prefix not in approved or identity not in approved[prefix]:
                    untrusted.append({"principal": member, "role": role, "condition": binding.get("condition")})
        if approved is None and not untrusted:
            # No operator trust lists: only public principals are decidable.
            return "MANUAL", {"reason": "Principal trust lists not configured; no public principal is bound, review the "
                              "remaining principals against the approved lists", "project_principals": project_members}
        if not untrusted and project_members:
            return "MANUAL", {"reason": "Only project convenience principals besides trusted ones; review separately",
                              "project_principals": project_members}
        return result(bool(untrusted), untrusted_declarations=untrusted, project_principals=project_members,
                      semantics="Operator trust lists from snapshot metadata; conditions are evidence, effective access is not computed")
    cid = track(gid(slug))
    SHARED_IDS[kind] = cid
    trust = {"context": {"provider": "gcp", "scope": SCOPE, "metadata": {"trusted_users": ["trusted@example.com"],
             "trusted_groups": [], "trusted_domains": [], "trusted_service_accounts": []}}}
    cases(cid, {"iamPolicy": {"bindings": [{"role": "roles/viewer", "members": ["user:trusted@example.com"]}]}},
          {"iamPolicy": {"bindings": [{"role": "roles/viewer", "members": ["user:other@example.com"]}]}},
          pass_index=trust, fail_index=trust, not_applicable={"iamPolicy": {"bindings": []}}, not_applicable_index=trust,
          malformed={"iamPolicy": {"bindings": [{"role": "roles/viewer", "members": [1]}]}})
    return cid


for _kind in SHARED_KINDS:
    shared_access(_kind)


def public_policy(slug, kind, title, *, severity="high"):
    @gcp(slug, kind, title, severity=severity, control="AC-3", category="exposure",
         remediation="Remove allUsers and allAuthenticatedUsers bindings from the resource IAM policy.")
    def evaluate(item, index):
        public = public_bindings(get(item, "iamPolicy", dict))
        return result(bool(public), public_bindings=public)
    cid = track(gid(slug))
    cases(cid, {"iamPolicy": {"bindings": [{"role": "roles/viewer", "members": ["group:team@example.com"]}]}},
          {"iamPolicy": {"bindings": [{"role": "roles/viewer", "members": ["allAuthenticatedUsers"]}]}},
          malformed={"iamPolicy": {"bindings": [{"role": "roles/viewer", "members": "allUsers"}]}})
    return cid


public_policy("pubsub_topic.not_public", "pubsub_topic", "Pub/Sub topic IAM policy does not grant public access")
public_policy("pubsub_subscription.not_public", "pubsub_subscription", "Pub/Sub subscription IAM policy does not grant public access")
public_policy("pubsub_snapshot.not_public", "pubsub_snapshot", "Pub/Sub snapshot IAM policy does not grant public access")
public_policy("secret.not_public", "secret", "Secret Manager secret IAM policy does not grant public access", severity="critical")


@gcp("secret.rotation_90_days", "secret", "Secret Manager secret rotates at most every 90 days and is not overdue", control="IA-5",
     category="hardening", remediation="Configure rotation (rotationPeriod <= 90 days with a future nextRotationTime) and a "
                                             "Pub/Sub rotation handler for the secret.")
def secret_rotation(item, index):
    rotation = optional(item, "rotation", None, dict)
    if rotation is None:
        return result(True, rotation=None)
    # Secret Manager requires nextRotationTime alongside rotationPeriod. The
    # period is input-only in the REST model, so an omitted period in a read
    # cannot prove either an acceptable interval or a violation.
    period = get(rotation, "rotationPeriod", str)
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]{1,9})?s", period):
        raise Unavailable("malformed Secret Manager rotation period")
    seconds = Decimal(period[:-1])
    if seconds < 3600:
        raise Unavailable("Secret Manager rotation period below documented minimum")
    if seconds > 90 * 86400:
        return result(True, rotation_seconds=str(seconds))
    next_time = get(rotation, "nextRotationTime", str)
    overdue = parse_time(next_time) <= captured_at(item, index)
    return result(overdue, rotation_seconds=str(seconds), next_rotation_time=next_time,
                  semantics="Declared Secret Manager rotation notification schedule only; subscriber action is unverified")


cases(track(gid("secret.rotation_90_days")),
      {"rotation": {"rotationPeriod": "2592000s", "nextRotationTime": "2026-11-01T00:00:00Z"}, "_provenance": {"collected_at": "2026-10-10T00:00:00Z"}},
      {"rotation": {"rotationPeriod": "31536000s"}}, malformed={"rotation": {"rotationPeriod": 30}})


# --- Cloud SQL and BigQuery ---------------------------------------------------------------------------------------

def addresses(item):
    rows = list_of_objects(optional(item, "ipAddresses", [], list))
    return [get(row, "type", str) for row in rows]


@gcp("sql_instance.second_gen_no_public_ip", "sql_instance", "Second-generation Cloud SQL instance has no public (PRIMARY) IP address",
     severity="high", control="SC-7", category="exposure",
     remediation="Disable public IPv4 (ipv4Enabled=false) and connect over private IP or the Cloud SQL Auth Proxy.")
def sql_public_ip(item, index):
    backend = get(item, "backendType", str)
    if backend != "SECOND_GEN":
        return "NOT_APPLICABLE", {"reason": "Criterion covers second-generation instances", "backend_type": backend}
    types = addresses(item)
    return result("PRIMARY" in types, ip_address_types=types)


cases(track(gid("sql_instance.second_gen_no_public_ip")), {"backendType": "SECOND_GEN", "ipAddresses": [{"type": "PRIVATE"}]},
      {"backendType": "SECOND_GEN", "ipAddresses": [{"type": "PRIMARY"}]}, not_applicable={"backendType": "EXTERNAL"},
      malformed={"backendType": "SECOND_GEN", "ipAddresses": [{"type": 1}]})


@gcp("sql_instance.private_ip_only", "sql_instance", "Cloud SQL instance uses a private network address and no public address",
     control="SC-7", category="exposure",
     remediation="Attach the instance to a private VPC network (private IP) and disable public IPv4.")
def sql_private_only(item, index):
    types = addresses(item)
    network = optional(get(item, "settings.ipConfiguration", dict), "privateNetwork", None, str)
    good = "PRIVATE" in types and bool(network) and "PRIMARY" not in types
    return result(not good, ip_address_types=types, private_network=network)


cases(track(gid("sql_instance.private_ip_only")),
      {"ipAddresses": [{"type": "PRIVATE"}], "settings": {"ipConfiguration": {"privateNetwork": "projects/p/global/networks/v"}}},
      {"ipAddresses": [{"type": "PRIMARY"}], "settings": {"ipConfiguration": {}}},
      malformed={"ipAddresses": [{"type": "PRIVATE"}], "settings": {"ipConfiguration": {"privateNetwork": 1}}})


def dataset_domain(slug, suffix, label):
    @gcp(slug, "bigquery_dataset", "BigQuery dataset access does not grant " + label + " accounts", control="AC-3", category="exposure",
         remediation="Remove dataset access entries for consumer " + label + " accounts and grant access to managed identities.")
    def evaluate(item, index):
        hits = []
        for entry in list_of_objects(omitted(item, "access", [], list)):  # empty ACL omitted on full reads
            email = optional(entry, "userByEmail", None, str)
            if email is not None and email.lower().endswith(suffix):
                hits.append({"userByEmail": email, "role": entry.get("role")})
        return result(bool(hits), matching_entries=hits)
    cid = track(gid(slug))
    cases(cid, {"access": [{"role": "READER", "userByEmail": "a@corp.example"}]},
          {"access": [{"role": "READER", "userByEmail": "a" + suffix}]}, malformed={"access": [{"userByEmail": 3}]})
    return cid


dataset_domain("bigquery_dataset.no_gmail_access", "gmail.com", "gmail.com")
dataset_domain("bigquery_dataset.no_googlegroups_access", "googlegroups.com", "googlegroups.com")


# --- GKE -----------------------------------------------------------------------------------------------------------

def gke(slug, title, *, severity="medium", control="CM-6", remediation, dependencies=None, category="hardening"):
    return gcp(slug, "gke_cluster", title, severity=severity, control=control, remediation=remediation, category=category,
               dependencies=dependencies)


@gke("gke.binary_authorization", "GKE cluster enforces Binary Authorization", control="SI-7",
     remediation="Enable Binary Authorization (evaluationMode PROJECT_SINGLETON_POLICY_ENFORCE or POLICY_BINDINGS).")
def gke_binauthz(item, index):
    config = optional(item, "binaryAuthorization", None, dict)
    mode = None
    if config is not None:
        mode = optional(config, "evaluationMode", None, str)
        if mode is None:
            mode = "PROJECT_SINGLETON_POLICY_ENFORCE" if optional(config, "enabled", False, bool) else "DISABLED"
    return result(mode in (None, "DISABLED", "EVALUATION_MODE_UNSPECIFIED"), evaluation_mode=mode)


cases(track(gid("gke.binary_authorization")), {"binaryAuthorization": {"evaluationMode": "PROJECT_SINGLETON_POLICY_ENFORCE"}},
      {"binaryAuthorization": {"evaluationMode": "DISABLED"}}, malformed={"binaryAuthorization": {"evaluationMode": 1}})


@gke("gke.no_client_certificate", "GKE cluster does not issue legacy client certificates", control="IA-5", severity="high",
     remediation="Recreate the cluster without issueClientCertificate; use IAM/OIDC authentication instead.")
def gke_client_cert(item, index):
    auth = optional(item, "masterAuth", {}, dict)
    issued = bool(optional(auth, "clientCertificate", "", str)) or optional(
        optional(auth, "clientCertificateConfig", {}, dict), "issueClientCertificate", False, bool)
    return result(issued, client_certificate_issued=issued)


cases(track(gid("gke.no_client_certificate")), {"masterAuth": {"clusterCaCertificate": "LS0t"}},
      {"masterAuth": {"clientCertificateConfig": {"issueClientCertificate": True}}},
      malformed={"masterAuth": {"clientCertificateConfig": {"issueClientCertificate": "yes"}}})


@gke("gke.no_kubernetes_alpha", "GKE cluster does not enable Kubernetes alpha features",
     remediation="Do not run production workloads on alpha clusters; recreate without enableKubernetesAlpha.")
def gke_alpha(item, index):
    alpha = optional(item, "enableKubernetesAlpha", False, bool)
    return result(alpha, enable_kubernetes_alpha=alpha)


cases(track(gid("gke.no_kubernetes_alpha")), {"enableKubernetesAlpha": False}, {"enableKubernetesAlpha": True},
      malformed={"enableKubernetesAlpha": "true"})


@gke("gke.http_load_balancing", "GKE HTTP load balancing add-on is enabled", severity="low",
     remediation="Enable the HttpLoadBalancing add-on when the cluster uses GKE Ingress.")
def gke_http_lb(item, index):
    addon = optional(get(item, "addonsConfig", dict), "httpLoadBalancing", {}, dict)
    disabled = optional(addon, "disabled", False, bool)
    return result(disabled, http_load_balancing_disabled=disabled)


cases(track(gid("gke.http_load_balancing")), {"addonsConfig": {"httpLoadBalancing": {}}},
      {"addonsConfig": {"httpLoadBalancing": {"disabled": True}}}, malformed={"addonsConfig": {"httpLoadBalancing": {"disabled": 1}}})


@gke("gke.dashboard_disabled", "GKE Kubernetes Dashboard add-on is disabled", control="CM-7",
     remediation="Disable the legacy kubernetesDashboard add-on.")
def gke_dashboard(item, index):
    addon = optional(get(item, "addonsConfig", dict), "kubernetesDashboard", None, dict)
    disabled = True if addon is None else optional(addon, "disabled", False, bool)
    return result(not disabled, dashboard_disabled=disabled)


cases(track(gid("gke.dashboard_disabled")), {"addonsConfig": {"kubernetesDashboard": {"disabled": True}}},
      {"addonsConfig": {"kubernetesDashboard": {}}}, malformed={"addonsConfig": {"kubernetesDashboard": {"disabled": "no"}}})


def telemetry(slug, field, label):
    @gke(slug, "GKE cluster " + label + " service is enabled", control="AU-12", category="hardening",
         remediation="Enable Cloud " + label.capitalize() + " for the cluster (" + field + " not 'none').")
    def evaluate(item, index):
        service = get(item, field, str)
        return result(service in ("none", ""), **{field: service})
    cid = track(gid(slug))
    cases(cid, {field: label + ".googleapis.com/kubernetes"}, {field: "none"}, malformed={field: 1})
    return cid


telemetry("gke.logging_enabled", "loggingService", "logging")
telemetry("gke.monitoring_enabled", "monitoringService", "monitoring")


@gke("gke.no_default_network", "GKE cluster does not use the default VPC network", control="SC-7", category="network",
     remediation="Create clusters in a purpose-built VPC network instead of the auto-created default network.")
def gke_default_network(item, index):
    network = get(item, "network", str)
    return result(network == "default", network=network)


cases(track(gid("gke.no_default_network")), {"network": "prod-vpc"}, {"network": "default"}, malformed={"network": None})


@gke("gke.nodes_no_default_service_account", "GKE nodes do not use the Compute Engine default service account", severity="high",
     control="AC-6", category="least_privilege",
     remediation="Run every node pool with a dedicated least-privilege service account.")
def gke_default_sa(item, index):
    pools = list_of_objects(optional(item, "nodePools", [], list))
    # NodeConfig.serviceAccount: "if no Service Account is specified, the
    # "default" service account is used." Every node pool is evaluated.
    if pools:
        accounts = {get(p, "name", str): optional(get(p, "config", dict), "serviceAccount", "default", str) for p in pools}
    else:
        accounts = {"nodeConfig": optional(get(item, "nodeConfig", dict), "serviceAccount", "default", str)}
    default = sorted(name for name, account in accounts.items() if account == "default" or account.endswith("-compute@developer.gserviceaccount.com"))
    return result(bool(default), default_service_account_pools=default)


cases(track(gid("gke.nodes_no_default_service_account")),
      {"nodePools": [{"name": "np", "config": {"serviceAccount": "nodes@p.iam.gserviceaccount.com"}}]},
      {"nodePools": [{"name": "np", "config": {"serviceAccount": "default"}}]},
      malformed={"nodePools": [{"name": "np", "config": {"serviceAccount": 1}}]})


@gke("gke.release_channel", "GKE cluster is enrolled in a release channel",
     remediation="Enroll the cluster in the RAPID, REGULAR, STABLE or EXTENDED release channel.")
def gke_channel(item, index):
    channel = optional(optional(item, "releaseChannel", {}, dict), "channel", "UNSPECIFIED", str)
    return result(channel == "UNSPECIFIED", channel=channel)


cases(track(gid("gke.release_channel")), {"releaseChannel": {"channel": "REGULAR"}}, {"releaseChannel": {}},
      malformed={"releaseChannel": {"channel": 3}})


@gke("gke.zone_redundant", "Zonal GKE cluster declares node locations in at least three distinct zones", severity="low", control="CP-10",
     remediation="Use a regional cluster or configure node locations across at least three zones.")
def gke_zones(item, index):
    location = get(item, "location", str)
    region_pattern = r"[a-z]+(?:-[a-z]+)+[0-9]+"
    if re.fullmatch(region_pattern, location):
        return "NOT_APPLICABLE", {"reason": "Regional cluster (control plane replicated across zones)", "location": location}
    if not re.fullmatch(region_pattern + r"-[a-z]", location):
        raise Unavailable("unrecognized GKE cluster location")
    locations = strings(get(item, "locations", list), "cluster locations")
    region = location.rsplit("-", 1)[0]
    if any(not re.fullmatch(region_pattern + r"-[a-z]", zone) or zone.rsplit("-", 1)[0] != region for zone in locations):
        raise Unavailable("node location is malformed or outside the cluster Region")
    if locations and location not in locations:
        raise Unavailable("zonal cluster's primary zone is absent from node locations")
    distinct = sorted(set(locations))
    return result(len(distinct) < 3, node_locations=distinct, distinct_zone_count=len(distinct),
                  semantics="Configured node locations only; actual node or workload placement unverified")


cases(track(gid("gke.zone_redundant")), {"location": "us-central1-a", "locations": ["us-central1-a", "us-central1-b", "us-central1-c"]},
      {"location": "us-central1-a", "locations": ["us-central1-a"]}, not_applicable={"location": "us-central1", "locations": []},
      malformed={"location": "us-central1-a", "locations": "us-central1-a"})


@gke("gke.subnetwork_private_google_access", "GKE cluster subnetwork has Private Google Access enabled", control="SC-7", category="network",
     dependencies=["gke_cluster", "subnetwork"],
     remediation="Enable privateIpGoogleAccess on the subnetwork used by the cluster.")
def gke_subnet_pga(item, index):
    reference = get(item, "networkConfig.subnetwork", str)
    matches = [s for s in complete_items(index, "subnetwork")
               if get(s, "selfLink", str).split("/compute/v1/", 1)[-1] == reference]
    if len(matches) != 1:
        raise Unavailable("cluster subnetwork not found in the complete subnetwork inventory")
    enabled = optional(matches[0], "privateIpGoogleAccess", False, bool)
    return result(not enabled, subnetwork=reference, private_ip_google_access=enabled)


_subnet = "projects/p/regions/us-central1/subnetworks/s"
cases(track(gid("gke.subnetwork_private_google_access")), {"networkConfig": {"subnetwork": _subnet}}, {"networkConfig": {"subnetwork": _subnet}},
      pass_index=scope_index({"subnetwork": [{"selfLink": "https://www.googleapis.com/compute/v1/" + _subnet, "privateIpGoogleAccess": True}]}),
      fail_index=scope_index({"subnetwork": [{"selfLink": "https://www.googleapis.com/compute/v1/" + _subnet}]}),
      malformed={"networkConfig": {"subnetwork": 1}})


@gke("gke.network_no_untargeted_public_ingress", "GKE cluster network has no untargeted firewall rule allowing internet ingress",
     severity="high", control="SC-7", category="network", dependencies=["gke_cluster", "firewall"],
     remediation="Restrict firewall rules on the cluster network to approved sources, or scope them with target tags/service accounts.")
def gke_open_network(item, index):
    network = get(item, "networkConfig.network", str)
    untargeted, targeted = [], []
    for rule in complete_items(index, "firewall"):
        if get(rule, "network", str).split("/compute/v1/", 1)[-1] != network:
            continue
        if active_ingress(rule) or not optional(rule, "allowed", [], list) or not is_public(rule):
            continue
        if opt_strings(rule, "targetTags") or opt_strings(rule, "targetServiceAccounts"):
            targeted.append(get(rule, "name", str))
        else:
            untargeted.append(get(rule, "name", str))
    if targeted and not untargeted:
        return "MANUAL", {"targeted_public_rules": targeted, "reason": "Public rules are scoped to tags/service accounts; node tag match not evaluated"}
    return result(bool(untargeted), untargeted_public_rules=untargeted, targeted_public_rules=targeted)


_vpc = "projects/p/global/networks/vpc"
_rule = lambda sources: {"network": "https://www.googleapis.com/compute/v1/" + _vpc, **fw(sources, [{"IPProtocol": "tcp", "ports": ["443"]}])}
cases(track(gid("gke.network_no_untargeted_public_ingress")), {"networkConfig": {"network": _vpc}}, {"networkConfig": {"network": _vpc}},
      pass_index=scope_index({"firewall": [_rule(["10.0.0.0/8"])]}), fail_index=scope_index({"firewall": [_rule(["0.0.0.0/0"])]}),
      malformed={"networkConfig": {"network": None}})


@gke("gke.master_authorized_networks_restricted", "GKE control plane authorized networks are enabled and exclude 0.0.0.0/0",
     severity="high", control="SC-7", category="network",
     remediation="Enable master authorized networks with specific CIDR blocks (or use a private endpoint).")
def gke_man(item, index):
    config = optional(item, "masterAuthorizedNetworksConfig", None, dict)
    if config is None or not optional(config, "enabled", False, bool):
        return result(True, enabled=False)
    blocks = [get(b, "cidrBlock", str) for b in list_of_objects(optional(config, "cidrBlocks", [], list))]
    return result(any(b in ("0.0.0.0/0", "::/0") for b in blocks), cidr_blocks=blocks)


cases(track(gid("gke.master_authorized_networks_restricted")),
      {"masterAuthorizedNetworksConfig": {"enabled": True, "cidrBlocks": [{"cidrBlock": "203.0.113.0/24"}]}},
      {"masterAuthorizedNetworksConfig": {"enabled": True, "cidrBlocks": [{"cidrBlock": "0.0.0.0/0"}]}},
      malformed={"masterAuthorizedNetworksConfig": {"enabled": True, "cidrBlocks": [{"cidrBlock": 1}]}})


@gke("gke.private_nodes", "GKE cluster nodes have private IP addresses only", severity="high", control="SC-7", category="network",
     remediation="Enable private nodes (privateClusterConfig.enablePrivateNodes or networkConfig.defaultEnablePrivateNodes).")
def gke_private_nodes(item, index):
    private = optional(optional(item, "privateClusterConfig", {}, dict), "enablePrivateNodes", False, bool) or \
        optional(optional(item, "networkConfig", {}, dict), "defaultEnablePrivateNodes", False, bool)
    return result(not private, private_nodes=private)


cases(track(gid("gke.private_nodes")), {"networkConfig": {"defaultEnablePrivateNodes": True}}, {"privateClusterConfig": {}},
      malformed={"privateClusterConfig": {"enablePrivateNodes": "true"}})
