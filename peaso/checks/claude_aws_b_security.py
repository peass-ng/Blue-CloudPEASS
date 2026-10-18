"""claude_aws_b security services: Inspector2, Macie, RAM, Resource Explorer, Roles Anywhere,
Route 53, Secrets Manager, Service Catalog, Shield, SSM, SSM Incidents, Trusted Advisor,
WAF Classic (global/regional), WAFv2 and Well-Architected."""
from __future__ import annotations

from datetime import timedelta
import re

from . import result
from .facts import Unavailable, get, list_of_objects, complete_items, guard
from .fixtures import CASES
from .claude_aws_b_common import (install, flag, absent_or, strings, policy_document, kms_manager, turbot_public_statements,
    is_policy_public, scope_of, inventory, indexes, account, clock, parse_time, CONTEXT, SCOPE, ACCOUNT, IDS)

_FIRST = len(IDS)
P, C, X = "prowler.aws.", "aws-compliance.control.", "aws-perimeter.control."
ANCHOR = {"scope": SCOPE}
ABSENT = {"collection_status": "empty", "absent": True, "error": {"code": "ResourceNotFoundException"}}
KMS_ARN = "arn:aws:kms:us-east-1:111111111111:key/k1"


def _manual_case(cid, manual, manual_index=None):
    case = CASES[cid]
    case.pop("fail", None)
    case["manual"] = manual
    if manual_index is not None:
        case["manual_index"] = manual_index


def detail(item, key):
    """A detail-call container: None for a documented not-found marker, else the collected response."""
    container = get(item, key, dict)
    if container.get("collection_status") == "empty" and container.get("absent") is True:
        return None
    if container.get("collection_status") not in (None, "collected"):
        raise Unavailable("detail not collected: " + key)
    return container


def region_of(index):
    context = index.get("context", {}) if isinstance(index, dict) else {}
    scope = context.get("scope") if isinstance(context, dict) else None
    if not isinstance(scope, str) or "/" not in scope:
        raise Unavailable("audited region unavailable")
    return scope.split("/", 1)[1]


def days_between(later, earlier):
    """Calendar-day difference, as steampipe date(a) - date(b)."""
    return (later.date() - earlier.date()).days


# =========================================================================== Inspector2
D_INSP = "https://docs.aws.amazon.com/inspector/v2/APIReference/API_BatchGetAccountStatus.html"


def _insp_status(state="ENABLED", **resources):
    base = {r: {"status": "ENABLED"} for r in ("ec2", "ecr", "lambda", "lambdaCode")}
    base.update({k: {"status": v} for k, v in resources.items()})
    return inventory("inspector2_account_status", [{"accountId": ACCOUNT, "State": {"status": state}, "ResourceState": base}])


def _inspector(index):
    rows = complete_items(index, "inspector2_account_status")
    if len(rows) != 1:
        raise Unavailable("expected one Inspector2 account status per region")
    return rows[0]


_TRIGGERS = (("ec2", "instance", "EC2"), ("ecr", "ecr_repository", "ECR"), ("lambda", "lambda_function", "Lambda"), ("lambdaCode", "lambda_function", "Lambda Code"))
_SOME = indexes(inventory("instance", [{"InstanceId": "i-1"}]), inventory("ecr_repository", []), inventory("lambda_function", []))
_NONE = indexes(inventory("instance", []), inventory("ecr_repository", []), inventory("lambda_function", []))


@install("aws.cb.inspector2.enabled_for_present_resources", "inspector2_account_status", "Inspector2 is enabled for every resource type present in the region",
    ANCHOR, ANCHOR, rows=[P + "inspector2_is_enabled"], severity="medium", control="RA-5", target="scope",
    dependencies=["inspector2_account_status", "instance", "ecr_repository", "lambda_function"],
    remediation="Activate Amazon Inspector (EC2, ECR, Lambda and Lambda code scanning) in the region.", docs=[D_INSP],
    extra={"pass_index": indexes(_insp_status(), _SOME), "fail_index": indexes(_insp_status(ec2="DISABLED"), _SOME),
           "not_applicable_index": indexes(_insp_status("DISABLED", ec2="DISABLED", ecr="DISABLED", **{"lambda": "DISABLED", "lambdaCode": "DISABLED"}), _NONE)},
    note="Prowler FAILs any region where Inspector2 is not ENABLED and per-type when resources exist; here only resource types with resources in the region are required (no EC2/ECR/Lambda resources = NOT_APPLICABLE) to avoid findings in unused regions.")
def insp_enabled(item, index):
    scope = scope_of(item)
    status = _inspector(index)
    account_on = get(status, "State.status", str) == "ENABLED"
    failed, present = [], []
    for key, kind, label in _TRIGGERS:
        if not complete_items(index, kind):
            continue
        present.append(label)
        if not account_on or get(status, "ResourceState." + key + ".status", str) != "ENABLED":
            failed.append(label)
    if not present:
        return "NOT_APPLICABLE", {"scope": scope, "reason": "no EC2, ECR or Lambda resources in region"}
    return result(bool(failed), scope=scope, not_enabled_for=failed)


def _findings(*rows):
    return inventory("inspector2_finding", list(rows))


def _finding(arn="arn:aws:inspector2:us-east-1:111111111111:finding/f", first="2026-01-01T00:00:00+00:00", vuln="CVE-2024-0001", cisa=None):
    details = {"findingArn": arn, **({"cisaData": cisa} if cisa else {})}
    return {"findingArn": arn, "firstObservedAt": first, "packageVulnerabilityDetails": {"vulnerabilityId": vuln}, "Details": details}


def _insp_scope(cid, title, row, evaluate_rows, good, bad, *, sev, rem, note, docs):
    @install(cid, "inspector2_finding", title, ANCHOR, ANCHOR, rows=[P + row], severity=sev, control="RA-5", target="scope",
        dependencies=["inspector2_account_status", "inspector2_finding"], remediation=rem, docs=docs, note=note,
        extra={"pass_index": indexes(_insp_status(), good), "fail_index": indexes(_insp_status(), bad),
               "not_applicable_index": indexes(_insp_status("DISABLED"), bad)})
    def evaluate(item, index):
        scope = scope_of(item)
        if get(_inspector(index), "State.status", str) != "ENABLED":
            return "NOT_APPLICABLE", {"scope": scope, "reason": "Inspector2 not enabled"}
        return evaluate_rows(scope, complete_items(index, "inspector2_finding"), index)
    return evaluate


D_FIND = "https://docs.aws.amazon.com/inspector/v2/APIReference/API_ListFindings.html"
D_FDET = "https://docs.aws.amazon.com/inspector/v2/APIReference/API_BatchGetFindingDetails.html"


def _exist(scope, rows, index):
    return result(bool(rows), scope=scope, active_findings=len(rows))


_insp_scope("aws.cb.inspector2.no_active_findings", "Enabled Inspector2 has no active findings", "inspector2_active_findings_exist", _exist,
    _findings(), _findings(_finding()), sev="medium", rem="Remediate or suppress the active Inspector2 findings.", docs=[D_FIND],
    note="list_findings with findingStatus ACTIVE; regions where Inspector2 is not enabled are NOT_APPLICABLE.")


def _max_age(scope, rows, index):
    now = clock({}, index)
    stale = [r.get("findingArn") for r in rows if now - parse_time(get(r, "firstObservedAt", str)) > timedelta(days=192)]
    return result(bool(stale), scope=scope, max_age_days=192, stale_findings=len(stale))


_insp_scope("aws.cb.inspector2.findings_within_max_age", "Active Inspector2 findings are younger than 192 days", "inspector2_active_findings_within_max_age", _max_age,
    _findings(_finding(first="2025-12-01T00:00:00+00:00")), _findings(_finding(first="2025-01-01T00:00:00+00:00")),
    sev="medium", rem="Remediate active Inspector2 findings older than the maximum age.", docs=[D_FIND],
    note="Prowler default inspector2_active_finding_max_age_days = 192, measured against the snapshot capture time.")


def _cisa(row):
    details = get(row, "Details", dict)
    if details.get("collection_status") not in (None, "collected"):
        raise Unavailable("finding details not collected")
    return details.get("cisaData") if isinstance(details.get("cisaData"), dict) else None


def _kev(scope, rows, index):
    kev = sorted({get(r, "packageVulnerabilityDetails.vulnerabilityId", str) for r in rows if _cisa(r)})
    return result(bool(kev), scope=scope, known_exploited=kev)


_KEV = {"dateAdded": "2025-01-01T00:00:00+00:00", "dateDue": "2025-01-22T00:00:00+00:00", "action": "Apply updates"}
_insp_scope("aws.cb.inspector2.no_known_exploited_findings", "Active Inspector2 findings contain no CISA Known Exploited Vulnerabilities",
    "inspector2_active_findings_no_known_exploited_vulnerabilities", _kev, _findings(_finding()), _findings(_finding(cisa=_KEV)),
    sev="high", rem="Prioritise remediation of findings listed in the CISA KEV catalog.", docs=[D_FIND, D_FDET],
    note="KEV membership comes from BatchGetFindingDetails cisaData; a finding whose details were not read is UNKNOWN (prowler MANUAL).")


def _kev_due(scope, rows, index):
    now = clock({}, index)
    overdue = []
    for r in rows:
        data = _cisa(r)
        if data and isinstance(data.get("dateDue"), str) and parse_time(data["dateDue"]) < now:
            overdue.append(get(r, "packageVulnerabilityDetails.vulnerabilityId", str))
    return result(bool(overdue), scope=scope, overdue=sorted(set(overdue)))


_insp_scope("aws.cb.inspector2.kev_findings_within_due_date", "Active CISA KEV Inspector2 findings are not past their CISA due date",
    "inspector2_active_findings_kev_within_due_date", _kev_due,
    _findings(_finding(cisa={**_KEV, "dateDue": "2026-06-01T00:00:00+00:00"})), _findings(_finding(cisa=_KEV)),
    sev="high", rem="Remediate KEV findings before their CISA remediation due date.", docs=[D_FIND, D_FDET],
    note="Overdue when cisaData.dateDue is before the snapshot capture time.")

D_COV = "https://docs.aws.amazon.com/inspector/v2/APIReference/API_CoveredResource.html"
COV = {"resourceId": "i-1", "resourceType": "AWS_EC2_INSTANCE", "accountId": ACCOUNT}
_NA_REASONS = {"EC2_INSTANCE_STOPPED", "EXCLUDED_BY_TAG", "NO_RESOURCES_FOUND", "PENDING_DISABLE", "RESOURCE_TERMINATED", "SCAN_ELIGIBILITY_EXPIRED"}
_PENDING = {"PENDING_INITIAL_SCAN", "PENDING_REVIVAL_SCAN", "SCAN_IN_PROGRESS"}


@install("aws.cb.inspector2.coverage_scan_active", "inspector2_coverage", "Inspector2 is actively scanning the covered resource",
    {**COV, "scanStatus": {"statusCode": "ACTIVE", "reason": "SUCCESSFUL"}}, {**COV, "scanStatus": {"statusCode": "INACTIVE", "reason": "UNMANAGED_EC2_INSTANCE"}},
    rows=[P + "inspector2_coverage_scan_status_active"], severity="medium", control="RA-5",
    remediation="Fix the scan status reason (SSM agent, permissions, unsupported OS) so Inspector can scan the resource.", docs=[D_COV],
    extra={"not_applicable": {**COV, "scanStatus": {"statusCode": "INACTIVE", "reason": "EC2_INSTANCE_STOPPED"}}})
def cov_active(item, index):
    code = get(item, "scanStatus.statusCode", str)
    reason = absent_or(item, "resourceId", "scanStatus.reason", None, str)
    if reason in _NA_REASONS:
        return "NOT_APPLICABLE", {"reason": reason}
    return result(code != "ACTIVE", status_code=code, reason=reason)


@install("aws.cb.inspector2.coverage_recently_scanned", "inspector2_coverage", "Actively covered resource was scanned by Inspector2 within 3 days",
    {**COV, "scanStatus": {"statusCode": "ACTIVE"}, "lastScannedAt": "2025-12-31T00:00:00+00:00"},
    {**COV, "scanStatus": {"statusCode": "ACTIVE"}, "lastScannedAt": "2025-12-01T00:00:00+00:00"},
    rows=[P + "inspector2_coverage_recently_scanned"], severity="medium", control="RA-5",
    remediation="Investigate why Inspector2 has not rescanned the resource recently.", docs=[D_COV],
    extra={"not_applicable": {**COV, "scanStatus": {"statusCode": "ACTIVE", "reason": "PENDING_INITIAL_SCAN"}}},
    note="Prowler default inspector2_max_days_since_last_scan = 3; non-ACTIVE coverage and pending scans without a timestamp are NOT_APPLICABLE.")
def cov_recent(item, index):
    code = get(item, "scanStatus.statusCode", str)
    if code != "ACTIVE":
        return "NOT_APPLICABLE", {"status_code": code}
    scanned = absent_or(item, "resourceId", "lastScannedAt", None, str)
    reason = absent_or(item, "resourceId", "scanStatus.reason", None, str)
    if scanned is None:
        if reason in _PENDING:
            return "NOT_APPLICABLE", {"reason": reason}
        return result(True, last_scanned_at=None)
    return result(clock(item, index) - parse_time(scanned) > timedelta(days=3), last_scanned_at=scanned)


# =========================================================================== Macie
D_MACIE = "https://docs.aws.amazon.com/macie/latest/APIReference/macie-session.html"


def _bucket(region):
    return {"Name": "b-" + str(region), "Location": {"LocationConstraint": region}}


def _bucket_region(bucket):
    constraint = get(bucket, "Location", dict).get("LocationConstraint")
    if constraint in (None, ""):
        return "us-east-1"
    if constraint == "EU":
        return "eu-west-1"
    if not isinstance(constraint, str):
        raise Unavailable("malformed bucket location")
    return constraint


def _macie(status=None, discovery=None):
    row = {"accountId": ACCOUNT, "Session": {"status": status} if status else dict(ABSENT)}
    if discovery is not None:
        row["AutomatedDiscovery"] = {"status": discovery}
    return inventory("macie_session", [row])


def _macie_row(index):
    rows = complete_items(index, "macie_session")
    if len(rows) != 1:
        raise Unavailable("expected one Macie session record per region")
    return rows[0]


@install("aws.cb.macie.enabled_where_buckets", "macie_session", "Macie is enabled in regions that hold S3 buckets",
    ANCHOR, ANCHOR, rows=[P + "macie_is_enabled"], severity="medium", control="SI-4", target="scope",
    dependencies=["macie_session", "bucket"], remediation="Enable Amazon Macie in the region.", docs=[D_MACIE],
    extra={"pass_index": indexes(_macie("ENABLED"), inventory("bucket", [_bucket("us-east-1")])),
           "fail_index": indexes(_macie("PAUSED"), inventory("bucket", [_bucket(None)])),
           "not_applicable_index": indexes(_macie(), inventory("bucket", [_bucket("eu-west-1")]))},
    note="Prowler (scan_unused_services off): ENABLED passes; otherwise FAIL only in regions with S3 buckets (bucket region from GetBucketLocation; null = us-east-1, EU = eu-west-1). GetMacieSession not-found/access-denied-for-disabled is the documented 'not enabled' state.")
def macie_enabled(item, index):
    scope = scope_of(item)
    session = detail(_macie_row(index), "Session")
    status = get(session, "status", str) if session is not None else "DISABLED"
    if status == "ENABLED":
        return result(False, scope=scope, status=status)
    region = region_of(index)
    if not any(_bucket_region(b) == region for b in complete_items(index, "bucket")):
        return "NOT_APPLICABLE", {"scope": scope, "status": status, "reason": "no S3 buckets in region"}
    return result(True, scope=scope, status=status)


@install("aws.cb.macie.automated_discovery", "macie_session", "Enabled Macie has automated sensitive data discovery enabled",
    ANCHOR, ANCHOR, rows=[P + "macie_automated_sensitive_data_discovery_enabled"], severity="medium", control="SI-4", target="scope",
    dependencies=["macie_session"], remediation="Enable automated sensitive data discovery in Macie.", docs=["https://docs.aws.amazon.com/macie/latest/APIReference/automated-discovery-configuration.html"],
    extra={"pass_index": _macie("ENABLED", "ENABLED"), "fail_index": _macie("ENABLED", "DISABLED"), "not_applicable_index": _macie()})
def macie_discovery(item, index):
    scope = scope_of(item)
    row = _macie_row(index)
    session = detail(row, "Session")
    if session is None or get(session, "status", str) != "ENABLED":
        return "NOT_APPLICABLE", {"scope": scope, "reason": "Macie not enabled"}
    status = get(row, "AutomatedDiscovery.status", str)
    return result(status != "ENABLED", scope=scope, automated_discovery=status)


# =========================================================================== RAM (perimeter, trusted lists)
D_RAM = "https://docs.aws.amazon.com/ram/latest/APIReference/API_GetResourceShareAssociations.html"
SHARE = {"resourceShareArn": "arn:aws:ram:us-east-1:111111111111:resource-share/s", "name": "s", "status": "ACTIVE"}


def _share(principals, resources=("arn:aws:ec2:us-east-1:111111111111:subnet/subnet-1",)):
    return {**SHARE,
            "PrincipalAssociations": {"resourceShareAssociations": [{"associatedEntity": p, "status": "ASSOCIATED"} for p in principals]},
            "ResourceAssociations": {"resourceShareAssociations": [{"associatedEntity": r, "status": "ASSOCIATED"} for r in resources]}}


def _ram(kind_label, row, matcher, example):
    cid = "aws.cb.ram.shared_with_" + kind_label + "_review"

    @install(cid, "ram_resource_share", "RAM resource share principals of type " + kind_label.replace("_", " ") + " are reviewed against a trusted list",
        _share([]), None, rows=[X + row], severity="medium", category="exposure", control="AC-3",
        remediation="Confirm every " + kind_label.replace("_", " ") + " the share grants access to is trusted, or remove the association.", docs=[D_RAM],
        extra={"not_applicable": _share([example], resources=())},
        note="aws-perimeter compares principals with operator-supplied trusted lists (placeholder defaults). Without a configured list the native check reports MANUAL with the principals to review; shares without such principals PASS; shares without resources are NOT_APPLICABLE. FAILED associations are ignored as upstream.")
    def evaluate(item, index):
        resources = [r for r in list_of_objects(get(item, "ResourceAssociations.resourceShareAssociations", list)) if r.get("status") != "FAILED"]
        if not resources:
            return "NOT_APPLICABLE", {"reason": "share has no resources"}
        principals = [get(p, "associatedEntity", str) for p in list_of_objects(get(item, "PrincipalAssociations.resourceShareAssociations", list)) if p.get("status") != "FAILED"]
        hits = sorted({p for p in principals if matcher(p)})
        if hits:
            return "MANUAL", {"principals_to_review": hits, "question": "Are all of these principals on your trusted list?"}
        return result(False, principals_to_review=[])
    _manual_case(cid, _share([example]))


_ram("accounts", "ram_resource_shared_with_trusted_accounts", lambda p: p.isdigit(), "222222222222")
_ram("organizations", "ram_resource_shared_with_trusted_organizations", lambda p: p.split("/", 1)[0].endswith(":organization"),
     "arn:aws:organizations::222222222222:organization/o-abc")
_ram("organization_units", "ram_resource_shared_with_trusted_organization_units", lambda p: p.split("/", 1)[0].endswith(":ou"),
     "arn:aws:organizations::222222222222:ou/o-abc/ou-abc-1")


# =========================================================================== Resource Explorer
@install("aws.cb.resourceexplorer2.index_exists", "resourceexplorer2_index", "Resource Explorer has at least one index in the account",
    ANCHOR, ANCHOR, rows=[P + "resourceexplorer2_indexes_found"], severity="low", control="CM-8", target="scope",
    dependencies=["resourceexplorer2_index"], remediation="Turn on AWS Resource Explorer (create an aggregator or local index).",
    docs=["https://docs.aws.amazon.com/resource-explorer/latest/apireference/API_ListIndexes.html"],
    extra={"pass_index": inventory("resourceexplorer2_index", [{"Arn": "arn:aws:resource-explorer-2:us-east-1:111111111111:index/i", "Region": "us-east-1", "Type": "LOCAL"}]),
           "fail_index": inventory("resourceexplorer2_index", [])},
    note="ListIndexes returns the account's indexes in every Region, so each regional result reflects the account.")
def rex(item, index):
    rows = complete_items(index, "resourceexplorer2_index")
    return result(not rows, scope=scope_of(item), indexes=len(rows))


# =========================================================================== Roles Anywhere
D_RA = "https://docs.aws.amazon.com/rolesanywhere/latest/APIReference/API_TrustAnchorDetail.html"
CA = "arn:aws:acm-pca:us-east-1:111111111111:certificate-authority/ca"


def _anchor(source="AWS_ACM_PCA"):
    data = {"acmPcaArn": CA} if source == "AWS_ACM_PCA" else {"x509CertificateData": "[redacted]"}
    return {"trustAnchorArn": "arn:aws:rolesanywhere:us-east-1:111111111111:trust-anchor/t", "source": {"sourceType": source, "sourceData": data}}


def _ca(algorithm="ML_DSA_65", status="ACTIVE"):
    return inventory("acmpca_certificate_authority", [{"Arn": CA, "Status": status, "CertificateAuthorityConfiguration": {"KeyAlgorithm": algorithm}}])


@install("aws.cb.rolesanywhere.trust_anchor_pqc", "rolesanywhere_trust_anchor", "Roles Anywhere trust anchor is an active ML-DSA AWS Private CA",
    _anchor(), _anchor(), rows=[P + "rolesanywhere_trust_anchor_pqc_pki"], severity="low", control="SC-13", dependencies=["rolesanywhere_trust_anchor", "acmpca_certificate_authority"],
    remediation="Back the trust anchor with an AWS Private CA that uses an ML-DSA key algorithm.", docs=[D_RA, "https://docs.aws.amazon.com/privateca/latest/APIReference/API_CertificateAuthorityConfiguration.html"],
    extra={"pass_index": _ca(), "fail_index": _ca("RSA_2048"), "bundle": _anchor("CERTIFICATE_BUNDLE")},
    note="Prowler default rolesanywhere_pqc_pca_key_algorithms [ML_DSA_44, ML_DSA_65, ML_DSA_87]; CERTIFICATE_BUNDLE anchors FAIL by design; a linked CA not in the complete (same-account) CA inventory is MANUAL as upstream.")
def ra_pqc(item, index):
    source = get(item, "source.sourceType", str)
    if source != "AWS_ACM_PCA":
        return result(True, source_type=source)
    arn = get(item, "source.sourceData.acmPcaArn", str)
    cas = [c for c in complete_items(index, "acmpca_certificate_authority") if get(c, "Arn", str) == arn]
    if not cas:
        return "MANUAL", {"acm_pca_arn": arn, "question": "Does the (cross-account) Private CA use an ML-DSA key algorithm?"}
    status = get(cas[0], "Status", str)
    algorithm = get(cas[0], "CertificateAuthorityConfiguration.KeyAlgorithm", str)
    return result(status != "ACTIVE" or algorithm not in ("ML_DSA_44", "ML_DSA_65", "ML_DSA_87"), status=status, key_algorithm=algorithm)


CASES["aws.cb.rolesanywhere.trust_anchor_pqc"]["bundle_index"] = _ca()

# =========================================================================== Route 53
D_DOM = "https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_GetDomainDetail.html"
DOMAIN = {"DomainName": "example.com"}


def _domain(**detail_fields):
    return {**DOMAIN, "Detail": {"DomainName": "example.com", **detail_fields}}


for _cid, _field, _row_list, _title, _rem in (
        ("aws.cb.route53.domain_auto_renew", "AutoRenew", [C + "route53_domain_auto_renew_enabled"], "Route 53 domain has auto renew enabled", "Enable auto renew for the domain."),
        ("aws.cb.route53.domain_privacy_protection", "AdminPrivacy", [C + "route53_domain_privacy_protection_enabled", P + "route53_domains_privacy_protection_enabled"],
         "Route 53 domain admin contact privacy protection is enabled", "Enable privacy protection for the domain contacts.")):
    flag(_cid, "route53_domain", _title, "Detail." + _field, rows=_row_list, severity="low", remediation=_rem, sentinel="DomainName", base=DOMAIN, docs=[D_DOM],
         note="GetDomainDetail " + _field + "; both sources treat only true as compliant.")


@install("aws.cb.route53.domain_transfer_lock", "route53_domain", "Route 53 domain has the clientTransferProhibited lock",
    _domain(StatusList=["clientTransferProhibited"]), _domain(StatusList=["ok"]),
    rows=[C + "route53_domain_transfer_lock_enabled", P + "route53_domains_transferlock_enabled"], severity="medium", control="CM-6",
    remediation="Enable transfer lock for the domain.", docs=[D_DOM],
    note="Prowler checks clientTransferProhibited in StatusList; steampipe transfer_lock is derived from the same EPP status (merged).")
def dom_lock(item, index):
    statuses = strings(absent_or(get(item, "Detail", dict), "DomainName", "StatusList", [], list))
    return result("clientTransferProhibited" not in statuses, status_list=statuses)


def _expiry(cid, row, title, days):
    @install(cid, "route53_domain", title, _domain(ExpirationDate="2027-01-01T00:00:00+00:00"), _domain(ExpirationDate="2026-01-0%dT00:00:00+00:00" % (min(days, 9) if days else 1)),
        rows=[C + row], severity="medium" if days else "high", control="CM-6", remediation="Renew the domain registration (or enable auto renew).", docs=[D_DOM],
        note="Calendar-day comparison against the snapshot capture time, as the pinned SQL." if days else "Expired when ExpirationDate is before the snapshot capture time.")
    def evaluate(item, index):
        expiry = parse_time(get(item, "Detail.ExpirationDate", str))
        now = clock(item, index)
        if days:
            remaining = days_between(expiry, now)
            return result(remaining < days, days_to_expiry=remaining)
        return result(expiry < now - timedelta(minutes=1), expiration_date=expiry.isoformat())
    return evaluate


_expiry("aws.cb.route53.domain_expires_after_30_days", "route53_domain_expires_30_days", "Route 53 domain expires in 30 days or more", 30)
_expiry("aws.cb.route53.domain_expires_after_7_days", "route53_domain_expires_7_days", "Route 53 domain expires in 7 days or more", 7)
_expiry("aws.cb.route53.domain_not_expired", "route53_domain_not_expired", "Route 53 domain is not expired", 0)
CASES["aws.cb.route53.domain_not_expired"]["fail"] = _domain(ExpirationDate="2025-06-01T00:00:00+00:00")

ZONE = {"Id": "/hostedzone/Z1", "Name": "example.com.", "Config": {"PrivateZone": False}}


@install("aws.cb.route53.public_zone_query_logging", "route53_zone", "Public Route 53 hosted zone has DNS query logging to CloudWatch Logs",
    {**ZONE, "QueryLoggingConfigs": {"QueryLoggingConfigs": [{"Id": "q", "HostedZoneId": "Z1", "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:111111111111:log-group:/aws/route53/example.com"}]}},
    {**ZONE, "QueryLoggingConfigs": {"QueryLoggingConfigs": []}},
    rows=[P + "route53_public_hosted_zones_cloudwatch_logging_enabled", C + "route53_zone_query_logging_enabled"], severity="medium", control="AU-2",
    remediation="Configure query logging for the public hosted zone to a CloudWatch Logs log group.", docs=["https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListQueryLoggingConfigs.html"],
    extra={"not_applicable": {**ZONE, "Config": {"PrivateZone": True}}},
    note="Both skip private zones and require a query logging configuration (prowler: with a CloudWatch log group ARN, which the API always returns).")
def zone_logging(item, index):
    if get(item, "Config.PrivateZone", bool):
        return "NOT_APPLICABLE", {"private_zone": True}
    configs = list_of_objects(get(item, "QueryLoggingConfigs.QueryLoggingConfigs", list))
    groups = [c.get("CloudWatchLogsLogGroupArn") for c in configs if isinstance(c.get("CloudWatchLogsLogGroupArn"), str) and c.get("CloudWatchLogsLogGroupArn")]
    return result(not groups, log_groups=groups)


# =========================================================================== Secrets Manager
D_SEC = "https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_SecretListEntry.html"
SECRET = {"ARN": "arn:aws:secretsmanager:us-east-1:111111111111:secret:s-abc", "Name": "s", "CreatedDate": "2025-01-01T00:00:00+00:00"}
RULES = {"AutomaticallyAfterDays": 30}


def _secret(policy=None, **fields):
    out = {**SECRET, **fields}
    out["Policy"] = {"ARN": SECRET["ARN"], "Name": "s", "collection_status": "collected", **({"ResourcePolicy": policy} if policy is not None else {})}
    return out


def secret_policy(item):
    container = detail(item, "Policy")
    if container is None or "ResourcePolicy" not in container:
        return None
    return policy_document(container["ResourcePolicy"])


def _opt(item, field, expected=str):
    return absent_or(item, "ARN", field, None, expected)


def _rotation_rules(item, index):
    """Honor a proven DescribeSecret omission when rotation is disabled."""
    marker = item.get("_coverage", {}).get("RotationRules")
    flag_marker = item.get("_coverage", {}).get("RotationEnabled")
    if "RotationRules" not in item and marker is None and flag_marker is not None:
        raise Unavailable("RotationRules omission has no native coverage proof")
    if isinstance(marker, dict) and marker.get("status") == "empty" and "RotationRules" in item:
        raise Unavailable("contradictory RotationRules omission")
    if (item.get("RotationEnabled") is False and "RotationRules" not in item
            and isinstance(marker, dict) and marker.get("status") == "empty"
            and marker.get("source_operation") == "secretsmanager:DescribeSecret"
            and marker.get("native_member_present") is False):
        arn = item.get("ARN")
        matched = re.fullmatch(r"arn:(aws|aws-us-gov|aws-cn):secretsmanager:([^:]+):([0-9]{12}):secret:[^:]+", arn) if isinstance(arn, str) else None
        context = index.get("context", {}) if isinstance(index, dict) else {}
        scope = context.get("scope") if isinstance(context, dict) else None
        primary = item.get("PrimaryRegion")
        identity_bound = (matched is not None and isinstance(scope, str)
            and scope == matched.group(3) + "/" + matched.group(2)
            and item.get("AccountId") == matched.group(3)
            and item.get("Region") == matched.group(2)
            and item.get("id") == arn)
        # Do not infer a disabled setting from an absent or denied flag read.
        if (identity_bound and primary in (None, matched.group(2))
                and isinstance(flag_marker, dict) and flag_marker.get("status") == "collected"
                and flag_marker.get("source_operation") == "secretsmanager:DescribeSecret"
                and _opt(item, "RotationEnabled", bool) is False):
            return None
    return _opt(item, "RotationRules", dict)


@install("aws.cb.secretsmanager.rotation_rules_present", "secret", "Secret has automatic rotation rules",
    _secret(RotationRules=RULES), _secret(), rows=[C + "secretsmanager_secret_automatic_rotation_enabled"], severity="medium", control="IA-5",
    remediation="Configure automatic rotation for the secret.", docs=[D_SEC], note="Steampipe alarms when rotation_rules is null (distinct from prowler's RotationEnabled, merged into aws.secretsmanager.rotation).")
def sec_rules(item, index):
    rules = _rotation_rules(item, index)
    return result(rules is None, rotation_rules=rules)


@install("aws.cb.secretsmanager.rotation_lambda", "secret", "Secret rotation is scheduled with a rotation Lambda function",
    _secret(RotationRules=RULES, RotationLambdaARN="arn:aws:lambda:us-east-1:111111111111:function:rot"), _secret(RotationRules=RULES),
    rows=[C + "secretsmanager_secret_automatic_rotation_lambda_enabled"], severity="medium", control="IA-5",
    remediation="Configure a rotation Lambda function and rotation schedule for the secret.", docs=[D_SEC])
def sec_lambda(item, index):
    rules = _rotation_rules(item, index)
    if rules is None:
        return result(True, rotation_lambda=None)
    fn = _opt(item, "RotationLambdaARN")
    return result(not (rules is not None and fn), rotation_lambda=fn)


DEFAULT_SECRET_KMS = _secret(AccountId=ACCOUNT, Region="us-east-1", _coverage={"KmsKeyId": {
    "status": "empty", "source_operation": "secretsmanager:DescribeSecret",
    "native_member_present": False, "documented_default": "aws/secretsmanager"}})
DEFAULT_SECRET_KMS_INDEX = {
    "context": {**CONTEXT, "metadata": {"caller_identities": [
        {"Account": ACCOUNT, "Arn": "arn:aws:iam::" + ACCOUNT + ":user/fixture"}]}},
    "collections": {"secret": [{"type": "secret", "scope": SCOPE, "account_id": ACCOUNT,
        "global": False, "status": "collected", "items": [DEFAULT_SECRET_KMS]}]},
    "secret": [{"type": "secret", "scope": SCOPE, "provider": "aws", "data": DEFAULT_SECRET_KMS}],
}


@install("aws.cb.secretsmanager.cmk_encryption", "secret", "Secret is encrypted with a customer managed KMS key",
    _secret(KmsKeyId=KMS_ARN), _secret(KmsKeyId="alias/aws/secretsmanager"), rows=[C + "secretsmanager_secret_encrypted_with_kms_cmk"], severity="medium", control="SC-28",
    remediation="Re-encrypt the secret with a customer managed KMS key.", docs=[D_SEC], dependencies=["secret", "kms_key"],
    extra={"index": inventory("kms_key", [{"Metadata": {"KeyMetadata": {"Arn": KMS_ARN, "KeyId": "k1", "KeyManager": "CUSTOMER"}}}]),
           "default_key": DEFAULT_SECRET_KMS,
           "default_key_index": DEFAULT_SECRET_KMS_INDEX},
    note="Steampipe alarms on a null KmsKeyId, alias/aws/secretsmanager, or a key whose aliases include it; the alias join is replaced by KeyManager = AWS (the only AWS managed key Secrets Manager uses).")
def sec_cmk(item, index):
    collections = index.get("collections") if isinstance(index, dict) else None
    if "KmsKeyId" not in item or (isinstance(collections, dict) and "secret" in collections):
        # Validate actual native inventory for either key form. Historical
        # explicit-key fixtures without a secret envelope keep their old path.
        from .remaining_aws_gcp_native import _secret_index
        secrets, _, _, _ = _secret_index(index)
        arn = get(item, "ARN", str)
        if secrets.get(arn) != item:
            raise Unavailable("secret absent from unique scoped inventory")
    if "KmsKeyId" not in item:
        coverage = get(item, "_coverage", dict).get("KmsKeyId") if "_coverage" in item else None
        if not isinstance(coverage, dict) or coverage.get("status") != "empty" or coverage.get("source_operation") != "secretsmanager:DescribeSecret" or coverage.get("native_member_present") is not False or coverage.get("documented_default") != "aws/secretsmanager":
            raise Unavailable("KMS key omission lacks identity-bound DescribeSecret evidence")
        # DescribeSecret omits KmsKeyId for the AWS managed aws/secretsmanager key.
        return result(True, kms_key_id=None, key_manager="AWS")
    key = _opt(item, "KmsKeyId")
    if not key:
        raise Unavailable("empty KMS key reference is not a documented omission")
    if key == "alias/aws/secretsmanager":
        return result(True, kms_key_id=key)
    return result(kms_manager(index, key) != "CUSTOMER", kms_key_id=key)


def _changed(cid, row, days):
    @install(cid, "secret", "Secret was changed in the last %d days" % days, _secret(LastChangedDate="2025-12-15T00:00:00+00:00"), _secret(LastChangedDate="2024-01-01T00:00:00+00:00"),
        rows=[C + row], severity="medium", control="IA-5", remediation="Rotate or update the secret value.", docs=[D_SEC],
        extra={"never": _secret()}, note="Null LastChangedDate alarms (never rotated); calendar-day comparison against the snapshot capture time.")
    def evaluate(item, index):
        changed = _opt(item, "LastChangedDate")
        if changed is None:
            return result(True, last_changed=None)
        age = days_between(clock(item, index), parse_time(changed))
        return result(age > days, days_since_change=age)


_changed("aws.cb.secretsmanager.changed_within_365_days", "secretsmanager_secret_last_changed_365_day", 365)
_changed("aws.cb.secretsmanager.changed_within_90_days", "secretsmanager_secret_last_changed_90_day", 90)


@install("aws.cb.secretsmanager.used_after_creation_day", "secret", "Secret was accessed at least one day after creation",
    _secret(LastAccessedDate="2025-06-01T00:00:00+00:00"), _secret(LastAccessedDate="2025-01-01T00:00:00+00:00"),
    rows=[C + "secretsmanager_secret_last_used_1_day"], severity="low", control="AC-2", remediation="Review whether the secret is still needed and delete unused secrets.", docs=[D_SEC],
    note="Faithful to the pinned SQL: ok when date(last_accessed_date) - date(created_date) >= 1; never accessed alarms.")
def sec_used1(item, index):
    accessed = _opt(item, "LastAccessedDate")
    created = parse_time(get(item, "CreatedDate", str))
    if accessed is None:
        return result(True, last_accessed=None)
    gap = days_between(parse_time(accessed), created)
    return result(gap < 1, days_after_creation=gap)


@install("aws.cb.secretsmanager.rotated_as_scheduled", "secret", "Secret with rotation is rotated within its AutomaticallyAfterDays schedule",
    _secret(RotationRules=RULES, LastRotatedDate="2025-12-20T00:00:00+00:00"), _secret(RotationRules=RULES, LastRotatedDate="2025-10-01T00:00:00+00:00"),
    rows=[C + "secretsmanager_secret_rotated_as_scheduled"], severity="medium", control="IA-5", remediation="Fix the rotation function or schedule so the secret rotates on time.", docs=[D_SEC],
    extra={"not_applicable": _secret(PrimaryRegion="eu-west-1", RotationRules=RULES), "no_rules": _secret()},
    note="Replica secrets (PrimaryRegion set and different from the audited Region) are skipped; no rotation rules alarm; rules without AutomaticallyAfterDays (schedule expressions) are UNKNOWN. A rotated, on-schedule secret (no upstream branch, null status) is PASS here.")
def sec_sched(item, index):
    primary = _opt(item, "PrimaryRegion")
    if primary and primary != region_of(index):
        return "NOT_APPLICABLE", {"primary_region": primary}
    rules = _rotation_rules(item, index)
    if rules is None:
        return result(True, rotation_rules=None)
    after = rules.get("AutomaticallyAfterDays")
    if type(after) is not int:
        raise Unavailable("rotation schedule without AutomaticallyAfterDays")
    rotated = _opt(item, "LastRotatedDate")
    base = parse_time(rotated) if rotated else parse_time(get(item, "CreatedDate", str))
    age = days_between(clock(item, index), base)
    return result(age > after, days_since=age, automatically_after_days=after, rotated=bool(rotated))


CASES["aws.cb.secretsmanager.rotated_as_scheduled"]["no_rules_expect"] = "FAIL"


@install("aws.cb.secretsmanager.rotated_within_90_days", "secret", "Secret was rotated within the last 90 days",
    _secret(LastRotatedDate="2025-12-01T00:00:00+00:00"), _secret(), rows=[P + "secretsmanager_secret_rotated_periodically"], severity="medium", control="IA-5",
    remediation="Rotate the secret (configure automatic rotation).", docs=[D_SEC], note="Prowler default max_days_secret_unrotated = 90; never rotated FAILs.")
def sec_rot90(item, index):
    rotated = _opt(item, "LastRotatedDate")
    if rotated is None:
        return result(True, last_rotated=None)
    age = (clock(item, index) - parse_time(rotated)).days
    return result(age > 90, days_since_rotation=age)


@install("aws.cb.secretsmanager.accessed_within_90_days", "secret", "Secret was accessed within the last 90 days (prowler)",
    _secret(LastAccessedDate="2025-12-01T00:00:00+00:00"), _secret(), rows=[P + "secretsmanager_secret_unused"], severity="low", control="AC-2",
    remediation="Delete secrets that are no longer used.", docs=[D_SEC], note="Prowler default max_days_secret_unused = 90 (timedelta > 90 days); never accessed FAILs.")
def sec_unused_p(item, index):
    accessed = _opt(item, "LastAccessedDate")
    if accessed is None:
        return result(True, last_accessed=None)
    return result(clock(item, index) - parse_time(accessed) > timedelta(days=90), last_accessed=accessed)


@install("aws.cb.secretsmanager.accessed_within_90_calendar_days", "secret", "Secret was accessed within the last 90 calendar days (steampipe)",
    _secret(LastAccessedDate="2025-12-01T00:00:00+00:00"), _secret(LastAccessedDate="2025-06-01T00:00:00+00:00"), rows=[C + "secretsmanager_secret_unused_90_day"],
    severity="low", control="AC-2", remediation="Delete secrets that are no longer used.", docs=[D_SEC],
    note="Steampipe: calendar-day difference <= 90 is ok, never accessed alarms (kept apart from prowler's timedelta threshold).")
def sec_unused_c(item, index):
    accessed = _opt(item, "LastAccessedDate")
    if accessed is None:
        return result(True, last_accessed=None)
    age = days_between(clock(item, index), parse_time(accessed))
    return result(age > 90, days_since_access=age)


_PUB = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]}
_PRIV = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111111111111:role/app"}, "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]}


@install("aws.cb.secretsmanager.policy_not_public", "secret", "Secret resource policy does not allow public access (prowler)",
    _secret(_PRIV), _secret(_PUB), rows=[P + "secretsmanager_not_publicly_accessible"], severity="critical", category="exposure", control="AC-3",
    remediation="Remove public principals from the secret resource policy or restrict them with conditions.", docs=["https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetResourcePolicy.html"],
    extra={"not_applicable": _secret()}, note="Prowler is_policy_public with the audited account; secrets without a resource policy are not reported (NOT_APPLICABLE).")
def sec_public_p(item, index):
    statements = secret_policy(item)
    if statements is None:
        return "NOT_APPLICABLE", {"policy": None}
    return result(is_policy_public(statements, account(index)), statements=len(statements))


CASES["aws.cb.secretsmanager.policy_not_public"]["index"] = {"context": dict(CONTEXT)}


@install("aws.cb.secretsmanager.policy_prohibit_public_access_perimeter", "secret", "Secret resource policy does not allow public access (perimeter)",
    _secret(_PRIV), _secret(_PUB), rows=[X + "secretsmanager_secret_policy_prohibit_public_access"], severity="critical", category="exposure", control="AC-3",
    remediation="Remove wildcard principals or add restricting conditions to the secret policy.", docs=["https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetResourcePolicy.html"],
    extra={"not_applicable": _secret()}, note="aws-perimeter resource_policy_public_sql; no policy is info (NOT_APPLICABLE).")
def sec_public_x(item, index):
    statements = secret_policy(item)
    if statements is None:
        return "NOT_APPLICABLE", {"policy": None}
    hits = turbot_public_statements(statements)
    return result(bool(hits), statements=len(hits))


# =========================================================================== Service Catalog
D_SC = "https://docs.aws.amazon.com/servicecatalog/latest/dg/API_DescribePortfolioShares.html"
PORT = {"Id": "port-1", "ARN": "arn:aws:catalog:us-east-1:111111111111:portfolio/port-1", "DisplayName": "p"}


def _portfolio(account_shares=(), org_shares=()):
    def _resp(rows):
        return {"PortfolioShareDetails": [{"PrincipalId": r, "Type": t, "Accepted": True} for r, t in rows], "collection_status": "collected"}
    return {**PORT, "Shares": {"ACCOUNT": _resp([(a, "ACCOUNT") for a in account_shares]), "ORGANIZATION": _resp([(o, "ORGANIZATION") for o in org_shares]),
                               "ORGANIZATIONAL_UNIT": _resp([]), "ORGANIZATION_MEMBER_ACCOUNT": _resp([])}}


def _account_shares(item):
    response = get(item, "Shares.ACCOUNT", dict)
    if response.get("collection_status") not in (None, "collected"):
        raise Unavailable("portfolio ACCOUNT shares not read")
    return [get(s, "PrincipalId", str) for s in list_of_objects(get(response, "PortfolioShareDetails", list))]


@install("aws.cb.servicecatalog.no_account_shares", "servicecatalog_portfolio", "Service Catalog portfolio is not shared with individual accounts",
    _portfolio(org_shares=["o-abc"]), _portfolio(account_shares=["222222222222"]), rows=[C + "servicecatalog_portfolio_shared_only_with_aws_organization"],
    severity="medium", category="exposure", control="AC-3", remediation="Share portfolios through AWS Organizations instead of with individual account IDs.", docs=[D_SC],
    note="Steampipe alarms on every ACCOUNT-type portfolio share regardless of Organizations membership.")
def sc_c(item, index):
    shares = _account_shares(item)
    return result(bool(shares), account_shares=shares)


ORG = inventory("organization", [{"Organization": {"Id": "o-abc", "Arn": "arn:aws:organizations::111111111111:organization/o-abc"}}])


@install("aws.cb.servicecatalog.org_member_no_account_shares", "servicecatalog_portfolio", "In an organization, Service Catalog portfolio is not shared with individual accounts",
    _portfolio(), _portfolio(account_shares=["222222222222"]), rows=[P + "servicecatalog_portfolio_shared_within_organization_only"],
    severity="medium", category="exposure", control="AC-3", remediation="Share portfolios through AWS Organizations instead of with individual account IDs.", docs=[D_SC],
    dependencies=["servicecatalog_portfolio", "organization"], extra={"index": ORG, "not_applicable_index": inventory("organization", []), "not_applicable": _portfolio(account_shares=["222222222222"])},
    note="Prowler evaluates only when the account belongs to an organization (DescribeOrganization succeeds); otherwise NOT_APPLICABLE.")
def sc_p(item, index):
    if not complete_items(index, "organization"):
        return "NOT_APPLICABLE", {"reason": "account not in an organization"}
    shares = _account_shares(item)
    return result(bool(shares), account_shares=shares)


# =========================================================================== Shield Advanced
D_SHIELD = "https://docs.aws.amazon.com/waf/latest/DDOSAPIReference/API_ListProtections.html"


def _strip(arn):
    parts = arn.split(":", 2)
    return parts[2] if len(parts) == 3 and parts[0] == "arn" else arn


def _shield(state="ACTIVE", *arns):
    return indexes(inventory("shield_subscription", [{"SubscriptionState": state}]),
                   inventory("shield_protection", [{"Id": "p%d" % i, "ResourceArn": a} for i, a in enumerate(arns)]))


def _protected(index):
    rows = complete_items(index, "shield_subscription")
    if len(rows) != 1:
        raise Unavailable("Shield subscription state unavailable")
    if get(rows[0], "SubscriptionState", str) != "ACTIVE":
        return None
    return {_strip(get(p, "ResourceArn", str)) for p in complete_items(index, "shield_protection")}


def _shield_check(cid, kind, row, title, item, arn_of, protected_arn, applies=None, na_item=None):
    @install(cid, kind, title, item, item, rows=[P + row], severity="medium", category="network", control="SC-5",
        dependencies=[kind, "shield_subscription", "shield_protection"], remediation="Add a Shield Advanced protection for the resource.", docs=[D_SHIELD],
        extra={"pass_index": _shield("ACTIVE", protected_arn), "fail_index": _shield("ACTIVE"), "not_applicable_index": _shield("INACTIVE"),
               **({"not_applicable": na_item} if na_item else {})},
        note="Evaluated only when the Shield Advanced subscription is ACTIVE (otherwise NOT_APPLICABLE); ARNs compared without the partition prefix.")
    def evaluate(resource, index):
        if applies is not None:
            skip = applies(resource)
            if skip is not None:
                return "NOT_APPLICABLE", skip
        arn = arn_of(resource, index)
        protected = _protected(index)
        if protected is None:
            return "NOT_APPLICABLE", {"reason": "Shield Advanced not subscribed"}
        return result(_strip(arn) not in protected, resource_arn=arn)
    return evaluate


def _regional_arn(service, suffix):
    def build(resource, index):
        return "arn:aws:%s:%s:%s:%s" % (service, region_of(index), account(index), suffix(resource))
    return build


EIP = {"AllocationId": "eipalloc-1", "PublicIp": "203.0.113.10", "Domain": "vpc"}
_shield_check("aws.cb.shield.elastic_ip_protected", "elastic_ip", "shield_advanced_protection_in_associated_elastic_ips", "Elastic IP is protected by Shield Advanced",
    EIP, _regional_arn("ec2", lambda r: "eip-allocation/" + get(r, "AllocationId", str)), "arn:aws:ec2:us-east-1:111111111111:eip-allocation/eipalloc-1")
CLB = {"LoadBalancerName": "clb", "Scheme": "internet-facing"}
_shield_check("aws.cb.shield.classic_load_balancer_protected", "classic_load_balancer", "shield_advanced_protection_in_classic_load_balancers", "Classic Load Balancer is protected by Shield Advanced",
    CLB, _regional_arn("elasticloadbalancing", lambda r: "loadbalancer/" + get(r, "LoadBalancerName", str)), "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/clb")
CF = {"Id": "E1", "ARN": "arn:aws:cloudfront::111111111111:distribution/E1"}
_shield_check("aws.cb.shield.cloudfront_protected", "cloudfront_distribution", "shield_advanced_protection_in_cloudfront_distributions", "CloudFront distribution is protected by Shield Advanced",
    CF, lambda r, i: get(r, "ARN", str), CF["ARN"])
GA = {"AcceleratorArn": "arn:aws:globalaccelerator::111111111111:accelerator/a", "Name": "a"}
_shield_check("aws.cb.shield.global_accelerator_protected", "globalaccelerator_accelerator", "shield_advanced_protection_in_global_accelerators", "Global Accelerator is protected by Shield Advanced",
    GA, lambda r, i: get(r, "AcceleratorArn", str), GA["AcceleratorArn"])
ALB = {"LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/a/1", "Type": "application", "Scheme": "internet-facing"}


def _alb_applies(resource):
    kind, scheme = get(resource, "Type", str), get(resource, "Scheme", str)
    return None if kind == "application" and scheme == "internet-facing" else {"type": kind, "scheme": scheme}


_shield_check("aws.cb.shield.internet_facing_alb_protected", "load_balancer", "shield_advanced_protection_in_internet_facing_load_balancers",
    "Internet-facing Application Load Balancer is protected by Shield Advanced", ALB, lambda r, i: get(r, "LoadBalancerArn", str), ALB["LoadBalancerArn"],
    applies=_alb_applies, na_item={**ALB, "Scheme": "internal"})
_shield_check("aws.cb.shield.route53_zone_protected", "route53_zone", "shield_advanced_protection_in_route53_hosted_zones", "Route 53 hosted zone is protected by Shield Advanced",
    ZONE, lambda r, i: "arn:aws:route53:::hostedzone/" + get(r, "Id", str).rsplit("/", 1)[-1], "arn:aws:route53:::hostedzone/Z1")

# =========================================================================== SSM
D_SSM_SET = "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetServiceSetting.html"


def _settings(setting_id, value):
    return inventory("ssm_service_settings", [{"id": "s", "ServiceSetting": {"SettingId": setting_id, "SettingValue": value, "Status": "Default"}}])


def _setting(index, suffix):
    rows = [r for r in complete_items(index, "ssm_service_settings") if get(r, "ServiceSetting.SettingId", str).endswith(suffix)]
    if len(rows) != 1:
        raise Unavailable("service setting not collected: " + suffix)
    return get(rows[0], "ServiceSetting.SettingValue", str)


SHARE_ID = "/ssm/documents/console/public-sharing-permission"
LOG_ID = "/ssm/automation/customer-script-log-destination"


@install("aws.cb.ssm.block_public_document_sharing", "ssm_service_settings", "SSM block public sharing for documents is turned on",
    ANCHOR, ANCHOR, rows=[C + "ssm_document_block_public_sharing_setting_enabled"], severity="medium", category="exposure", control="AC-3", target="scope",
    dependencies=["ssm_service_settings"], remediation="Set /ssm/documents/console/public-sharing-permission to Disable (Block public sharing).",
    docs=[D_SSM_SET, "https://docs.aws.amazon.com/systems-manager/latest/userguide/documents-ssm-sharing.html#block-public-access"],
    extra={"pass_index": _settings(SHARE_ID, "Disable"), "fail_index": _settings(SHARE_ID, "Enable")},
    note="Same question, corrected value: the pinned SQL treats SettingValue 'Enable' as ok, but AWS documents that block public sharing is turned on with --setting-value Disable ('Enable' allows public sharing). Native PASS = Disable.")
def ssm_block(item, index):
    value = _setting(index, SHARE_ID)
    return result(value != "Disable", scope=scope_of(item), setting_value=value)


@install("aws.cb.ssm.automation_logs_to_cloudwatch", "ssm_service_settings", "SSM Automation customer script output is sent to CloudWatch Logs",
    ANCHOR, ANCHOR, rows=[C + "ssm_automation_cloudwatch_logging_enabled"], severity="low", control="AU-2", target="scope",
    dependencies=["ssm_service_settings"], remediation="Set /ssm/automation/customer-script-log-destination to CloudWatch.",
    docs=[D_SSM_SET, "https://docs.aws.amazon.com/systems-manager/latest/userguide/automation-action-logging.html"],
    extra={"pass_index": _settings(LOG_ID, "CloudWatch"), "fail_index": _settings(LOG_ID, "NONE")})
def ssm_autolog(item, index):
    value = _setting(index, LOG_ID)
    return result(value != "CloudWatch", scope=scope_of(item), setting_value=value)


DOC = {"Name": "doc", "Owner": ACCOUNT, "DocumentType": "Command"}


def _doc(*accounts):
    return {**DOC, "Permissions": {"AccountIds": list(accounts), "collection_status": "collected"}}


@install("aws.cb.ssm.document_shared_only_with_trusted", "ssm_document_metadata", "SSM document is not public and is shared only with trusted accounts",
    _doc(), _doc("all"), rows=[P + "ssm_documents_set_as_public"], severity="high", category="exposure", control="AC-3",
    remediation="Stop sharing the document publicly or with untrusted accounts.", docs=["https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DescribeDocumentPermission.html"],
    extra={"index": {"context": dict(CONTEXT)}, "other_account": _doc("222222222222")},
    note="Prowler: PASS when unshared or shared only with the audited account / trusted_account_ids (default empty), FAIL when 'all' or any other account.")
def ssm_doc(item, index):
    perms = detail(item, "Permissions")
    owners = strings(absent_or(perms, "collection_status", "AccountIds", [], list)) if perms else []
    trusted = {account(index)}
    return result(bool(owners) and not set(owners) <= trusted, account_ids=owners)


CASES["aws.cb.ssm.document_shared_only_with_trusted"]["other_account_expect"] = "FAIL"
D_COMP = "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_ResourceComplianceSummaryItem.html"


@install("aws.cb.ssm.resource_compliance_summary_compliant", "ssm_resource_compliance_summary", "SSM resource compliance summary is COMPLIANT",
    {"ResourceId": "i-1", "ResourceType": "ManagedInstance", "ComplianceType": "Patch", "Status": "COMPLIANT"},
    {"ResourceId": "i-1", "ResourceType": "ManagedInstance", "ComplianceType": "Patch", "Status": "NON_COMPLIANT"},
    rows=[P + "ssm_managed_compliant_patching"], severity="high", control="SI-2", remediation="Install missing patches / fix failed associations on the managed instance.", docs=[D_COMP],
    note="Prowler evaluates every ListResourceComplianceSummaries item (all compliance types) on its Status.")
def ssm_summary(item, index):
    status = get(item, "Status", str)
    return result(status != "COMPLIANT", compliance_type=item.get("ComplianceType"), status=status)


MI = {"InstanceId": "i-1", "PingStatus": "Online"}


def _mi(*items):
    return {**MI, "ComplianceItems": {"ComplianceItems": [{"ComplianceType": t, "Status": s, "Id": str(i)} for i, (t, s) in enumerate(items)], "collection_status": "collected"}}


def _compliance(cid, row, ctype, title, rem, skip_empty):
    @install(cid, "ssm_managed_instance", title, _mi((ctype, "COMPLIANT")), _mi((ctype, "NON_COMPLIANT")), rows=[C + row], severity="medium", control="SI-2",
        remediation=rem, docs=["https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_ListComplianceItems.html"],
        extra={"not_applicable": _mi(("Custom:x", "NON_COMPLIANT"))},
        note="Steampipe joins ListComplianceItems rows of ComplianceType " + ctype + " (one row per item); any non-COMPLIANT item fails; instances without such items are NOT_APPLICABLE" + ("; empty status items are skipped." if skip_empty else "."))
    def evaluate(item, index):
        response = detail(item, "ComplianceItems")
        if response is None:
            return "NOT_APPLICABLE", {"reason": "no compliance items"}
        rows = [r for r in list_of_objects(get(response, "ComplianceItems", list)) if r.get("ComplianceType") == ctype]
        statuses = [get(r, "Status", str) if "Status" in r else "" for r in rows]
        if skip_empty:
            statuses = [s for s in statuses if s != ""]
        if not statuses:
            return "NOT_APPLICABLE", {"reason": "no " + ctype + " compliance items"}
        bad = [s for s in statuses if s != "COMPLIANT"]
        return result(bool(bad), items=len(statuses), non_compliant=len(bad))


_compliance("aws.cb.ssm.instance_association_compliant", "ssm_managed_instance_compliance_association_compliant", "Association",
    "SSM managed instance association compliance items are COMPLIANT", "Fix failing State Manager associations on the instance.", False)
_compliance("aws.cb.ssm.instance_patch_compliant", "ssm_managed_instance_compliance_patch_compliant", "Patch",
    "SSM managed instance patch compliance items are COMPLIANT", "Install missing patches on the managed instance.", True)

# =========================================================================== SSM Incident Manager
ACC = {"AccountId": ACCOUNT}


def _incidents(sets, plans):
    return {**ACC, "ReplicationSets": {"collection_status": "collected", "items": [{"arn": "arn:aws:ssm-incidents::111111111111:replication-set/r", "status": s} for s in sets]},
            "ResponsePlans": {"collection_status": "collected", "items": [{"arn": "arn:aws:ssm-incidents::111111111111:response-plan/p%d" % i} for i in range(plans)]}}


@install("aws.cb.ssmincidents.active_with_response_plans", "ssmincidents_account", "Incident Manager has an ACTIVE replication set and response plans",
    _incidents(["ACTIVE"], 1), _incidents(["ACTIVE"], 0), rows=[P + "ssmincidents_enabled_with_plans"], severity="low", control="IR-4",
    remediation="Create an Incident Manager replication set and at least one response plan.", docs=["https://docs.aws.amazon.com/incident-manager/latest/APIReference/API_GetReplicationSet.html"],
    extra={"no_set": _incidents([], 1)}, note="Prowler: no replication set FAILs; only the first set is considered, which must be ACTIVE with response plans.")
def incidents(item, index):
    sets, plans = (get(item, k, dict) for k in ("ReplicationSets", "ResponsePlans"))
    for container in (sets, plans):
        if container.get("collection_status") not in ("collected", "empty"):
            raise Unavailable("incident manager inventory not collected")
    rows = list_of_objects(get(sets, "items", list))
    if not rows:
        return result(True, replication_set=None)
    status = get(rows[0], "status", str)
    count = len(list_of_objects(get(plans, "items", list)))
    return result(not (status == "ACTIVE" and count), status=status, response_plans=count)


CASES["aws.cb.ssmincidents.active_with_response_plans"]["no_set_expect"] = "FAIL"

# =========================================================================== Trusted Advisor
flag("aws.cb.trustedadvisor.premium_support", "trustedadvisor_support", "Account has a Business/Enterprise (premium) support plan", "PremiumSupport",
     rows=[P + "trustedadvisor_premium_support_plan_subscribed"], severity="low", control="CM-6", remediation="Subscribe to a Business, Enterprise On-Ramp or Enterprise support plan.",
     sentinel="AccountId", base=ACC, docs=["https://docs.aws.amazon.com/awssupport/latest/APIReference/API_DescribeTrustedAdvisorChecks.html"],
     note="Premium support = support:DescribeServices succeeds; SubscriptionRequiredException = no premium plan (collector fact). Other errors are UNKNOWN.")


@install("aws.cb.trustedadvisor.check_ok", "trustedadvisor_check", "Trusted Advisor check reports no errors or warnings",
    {"id": "c1", "name": "n", "Result": {"status": "ok"}}, {"id": "c1", "name": "n", "Result": {"status": "warning"}}, rows=[P + "trustedadvisor_errors_and_warnings"],
    severity="medium", control="CA-7", remediation="Review and resolve the Trusted Advisor recommendation.", docs=["https://docs.aws.amazon.com/awssupport/latest/APIReference/API_TrustedAdvisorCheckResult.html"],
    extra={"not_applicable": {"id": "c1", "name": "n", "Result": {"status": "not_available"}}},
    note="Prowler: not_available results are skipped; anything but ok FAILs. Without premium support no check rows exist (prowler MANUAL; see aws.cb.trustedadvisor.premium_support).")
def ta(item, index):
    status = get(item, "Result.status", str)
    if status == "not_available":
        return "NOT_APPLICABLE", {"status": status}
    return result(status != "ok", status=status)


# =========================================================================== WAF Classic
D_WAF = "https://docs.aws.amazon.com/waf/latest/APIReference/API_Operations_AWS_WAF.html"


def _waf_family(prefix, label, scope_rows):
    """scope_rows: (rule rows, rule group rows, web ACL rows, logging rows)."""
    rule_rows, group_rows, acl_rows, log_rows = scope_rows
    kind = prefix
    flag_rule = {"RuleId": "r1", "Rule": {"RuleId": "r1", "Name": "r", "MetricName": "r", "Predicates": [{"Negated": False, "Type": "IPMatch", "DataId": "d"}]}}

    @install("aws.cb.%s.rule_has_conditions" % prefix, kind + "_rule", "WAF Classic %s rule has at least one condition" % label,
        flag_rule, {"RuleId": "r1", "Rule": {"RuleId": "r1", "Predicates": []}}, rows=rule_rows, severity="medium", category="network", control="SC-7",
        remediation="Add conditions to the rule or delete it.", docs=[D_WAF])
    def rule(item, index):
        predicates = list_of_objects(get(item, "Rule.Predicates", list))
        return result(not predicates, predicates=len(predicates))

    @install("aws.cb.%s.rule_group_not_empty" % prefix, kind + "_rule_group", "WAF Classic %s rule group has at least one rule" % label,
        {"RuleGroupId": "g1", "ActivatedRules": {"ActivatedRules": [{"Priority": 1, "RuleId": "r1"}], "collection_status": "collected"}},
        {"RuleGroupId": "g1", "ActivatedRules": {"ActivatedRules": [], "collection_status": "collected"}}, rows=group_rows, severity="medium", category="network", control="SC-7",
        remediation="Add rules to the rule group or delete it.", docs=[D_WAF], note="ListActivatedRulesInRuleGroup result.")
    def group(item, index):
        rules = list_of_objects(get(detail(item, "ActivatedRules") or {}, "ActivatedRules", list))
        return result(not rules, activated_rules=len(rules))

    acl = {"WebACLId": "w1", "WebACL": {"WebACLId": "w1", "WebACLArn": "arn:aws:waf::111111111111:webacl/w1", "DefaultAction": {"Type": "ALLOW"}}}

    @install("aws.cb.%s.web_acl_has_rules" % prefix, kind + "_web_acl", "WAF Classic %s web ACL has rules or rule groups" % label,
        {**acl, "WebACL": {**acl["WebACL"], "Rules": [{"Priority": 1, "RuleId": "r1", "Type": "REGULAR"}]}}, {**acl, "WebACL": {**acl["WebACL"], "Rules": []}},
        rows=acl_rows, severity="medium", category="network", control="SC-7", remediation="Add rules or rule groups to the web ACL.", docs=[D_WAF],
        note="Prowler rules or rule_groups both come from WebACL.Rules (GROUP entries are rule groups); steampipe checks the same list.")
    def acl_rules(item, index):
        rules = list_of_objects(get(item, "WebACL.Rules", list))
        return result(not rules, rules=len(rules))

    @install("aws.cb.%s.web_acl_logging" % prefix, kind + "_web_acl", "WAF Classic %s web ACL has logging configured" % label,
        {**acl, "LoggingConfiguration": {"LoggingConfiguration": {"ResourceArn": "x", "LogDestinationConfigs": ["arn:aws:firehose:us-east-1:111111111111:deliverystream/aws-waf-logs-x"]}, "collection_status": "collected"}},
        {**acl, "LoggingConfiguration": dict(ABSENT)}, rows=log_rows, severity="medium", control="AU-2",
        remediation="Configure web ACL logging to a Kinesis Data Firehose stream.", docs=["https://docs.aws.amazon.com/waf/latest/APIReference/API_waf_GetLoggingConfiguration.html"],
        note="GetLoggingConfiguration WAFNonexistentItemException = not configured; a configuration needs at least one LogDestinationConfigs entry.")
    def acl_logging(item, index):
        response = detail(item, "LoggingConfiguration")
        destinations = strings(get(response, "LoggingConfiguration.LogDestinationConfigs", list)) if response else []
        return result(not destinations, destinations=len(destinations))


_waf_family("waf", "global", ([P + "waf_global_rule_with_conditions", C + "waf_rule_condition_attached"], [P + "waf_global_rulegroup_not_empty", C + "waf_rule_group_rule_attached"],
            [P + "waf_global_webacl_with_rules", C + "waf_web_acl_rule_attached"], [P + "waf_global_webacl_logging_enabled", C + "waf_web_acl_logging_enabled"]))
_waf_family("wafregional", "regional", ([P + "waf_regional_rule_with_conditions", C + "waf_regional_rule_condition_attached"],
            [P + "waf_regional_rulegroup_not_empty", C + "waf_regional_rule_group_rule_attached"],
            [P + "waf_regional_webacl_with_rules", C + "waf_regional_web_acl_rule_attached"], [P + "waf_regional_webacl_logging_enabled"]))


@install("aws.cb.wafregional.web_acl_associated", "wafregional_web_acl", "WAF Classic regional web ACL is associated with a resource",
    {"WebACLId": "w1", "ResourceArns": {"ResourceArns": ["arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/a/1"], "collection_status": "collected"}},
    {"WebACLId": "w1", "ResourceArns": {"ResourceArns": [], "collection_status": "collected"}}, rows=[C + "waf_web_acl_resource_associated"], severity="low", category="network", control="SC-7",
    remediation="Associate the web ACL with a resource or delete it.", docs=["https://docs.aws.amazon.com/waf/latest/APIReference/API_wafRegional_ListResourcesForWebACL.html"])
def wafr_assoc(item, index):
    arns = strings(get(detail(item, "ResourceArns") or {}, "ResourceArns", list))
    return result(not arns, resources=len(arns))


# =========================================================================== WAFv2
D_V2 = "https://docs.aws.amazon.com/waf/latest/APIReference/API_WebACL.html"
V2 = {"ARN": "arn:aws:wafv2:us-east-1:111111111111:regional/webacl/a/1", "Name": "a", "Id": "1"}


def _v2(rules=(), fms=(), logging=None):
    acl = {**V2, "WebACL": {"ARN": V2["ARN"], "Name": "a", "Rules": [{"Name": n, "Priority": i, "VisibilityConfig": {"CloudWatchMetricsEnabled": m}, "Statement": {}} for i, (n, m) in enumerate(rules)],
                            "PreProcessFirewallManagerRuleGroups": [{"Name": n, "VisibilityConfig": {"CloudWatchMetricsEnabled": m}} for n, m in fms]}}
    acl["LoggingConfiguration"] = dict(ABSENT) if logging is None else {"LoggingConfiguration": {"ResourceArn": V2["ARN"], "LogDestinationConfigs": [logging]}, "collection_status": "collected"}
    return acl


def _v2_rules(item, with_fms):
    acl = get(item, "WebACL", dict)
    rules = list(list_of_objects(get(acl, "Rules", list)))
    if with_fms:
        for key in ("PreProcessFirewallManagerRuleGroups", "PostProcessFirewallManagerRuleGroups"):
            rules += list_of_objects(absent_or(acl, "ARN", key, [], list))
    return rules


@install("aws.cb.wafv2.web_acl_has_rules_or_fms_groups", "wafv2_web_acl", "WAFv2 web ACL has rules, rule groups or Firewall Manager rule groups (prowler)",
    _v2(fms=[("fms", True)]), _v2(), rows=[P + "wafv2_webacl_with_rules"], severity="medium", category="network", control="SC-7",
    remediation="Add rules or rule groups to the web ACL.", docs=[D_V2], note="Prowler also counts Firewall Manager pre/post-process rule groups.")
def v2_rules_p(item, index):
    rules = _v2_rules(item, True)
    return result(not rules, rules=len(rules))


@install("aws.cb.wafv2.web_acl_has_rules", "wafv2_web_acl", "WAFv2 web ACL Rules list is not empty (steampipe)",
    _v2(rules=[("r", True)]), _v2(fms=[("fms", True)]), rows=[C + "wafv2_web_acl_rule_attached"], severity="medium", category="network", control="SC-7",
    remediation="Add rules or rule groups to the web ACL.", docs=[D_V2], note="Steampipe checks only WebACL.Rules (Firewall Manager groups do not count), so it is kept apart from the prowler predicate.")
def v2_rules_c(item, index):
    rules = _v2_rules(item, False)
    return result(not rules, rules=len(rules))


@install("aws.cb.wafv2.web_acl_logging", "wafv2_web_acl", "WAFv2 web ACL has logging configured",
    _v2(rules=[("r", True)], logging="arn:aws:logs:us-east-1:111111111111:log-group:aws-waf-logs-a"), _v2(rules=[("r", True)]),
    rows=[P + "wafv2_webacl_logging_enabled", C + "wafv2_web_acl_logging_enabled"], severity="medium", control="AU-2",
    remediation="Enable logging for the web ACL (CloudWatch Logs, S3 or Firehose).", docs=["https://docs.aws.amazon.com/waf/latest/APIReference/API_GetLoggingConfiguration.html"],
    note="WAFNonexistentItemException = not configured; both sources require a logging configuration (with LogDestinationConfigs).")
def v2_logging(item, index):
    response = detail(item, "LoggingConfiguration")
    destinations = strings(get(response, "LoggingConfiguration.LogDestinationConfigs", list)) if response else []
    return result(not destinations, destinations=len(destinations))


@install("aws.cb.wafv2.web_acl_rule_metrics", "wafv2_web_acl", "Every WAFv2 web ACL rule and rule group has CloudWatch metrics enabled",
    _v2(rules=[("r", True)], fms=[("f", True)]), _v2(rules=[("r", True)], fms=[("f", False)]), rows=[P + "wafv2_webacl_rule_logging_enabled"], severity="low", control="AU-2",
    remediation="Enable CloudWatchMetricsEnabled in each rule's VisibilityConfig.", docs=[D_V2], extra={"not_applicable": _v2()},
    note="Prowler skips web ACLs without rules; a rule without VisibilityConfig.CloudWatchMetricsEnabled counts as disabled (API requires the member).")
def v2_metrics(item, index):
    rules = _v2_rules(item, True)
    if not rules:
        return "NOT_APPLICABLE", {"reason": "web ACL has no rules"}
    disabled = [r.get("Name") for r in rules if (r.get("VisibilityConfig") or {}).get("CloudWatchMetricsEnabled") is not True]
    return result(bool(disabled), metrics_disabled=disabled)


def _v2_group_fixture(enabled):
    arn = "arn:aws:wafv2:us-east-1:111111111111:regional/rulegroup/g/1"
    row = {"ARN": arn, "Scope": "REGIONAL", "RuleGroup": {"ARN": arn,
           "VisibilityConfig": {"CloudWatchMetricsEnabled": enabled}}}
    index = {"context": dict(CONTEXT),
             "collections": {"wafv2_rule_group": [{"type": "wafv2_rule_group", "scope": SCOPE,
                 "status": "collected", "items": [row]}]},
             "wafv2_rule_group": [{"type": "wafv2_rule_group", "scope": SCOPE, "data": row}]}
    return row, index


_V2_GROUP_PASS, _V2_GROUP_PASS_INDEX = _v2_group_fixture(True)
_V2_GROUP_FAIL, _V2_GROUP_FAIL_INDEX = _v2_group_fixture(False)


@install("aws.cb.wafv2.rule_group_metrics", "wafv2_rule_group", "WAFv2 rule group has CloudWatch metrics enabled",
    _V2_GROUP_PASS, _V2_GROUP_FAIL,
    rows=[C + "wafv2_rule_group_logging_enabled"], severity="low", control="AU-2",
    remediation="Enable CloudWatchMetricsEnabled in the rule group VisibilityConfig.", docs=["https://docs.aws.amazon.com/waf/latest/APIReference/API_RuleGroup.html"],
    extra={"pass_index": _V2_GROUP_PASS_INDEX, "fail_index": _V2_GROUP_FAIL_INDEX})
def v2_group(item, index):
    from .wafv2_basic import group_metrics
    _, value = group_metrics(item, index)
    return result(not value, cloudwatch_metrics_enabled=value)


# =========================================================================== Well-Architected
@install("aws.cb.wellarchitected.no_high_or_medium_risks", "wellarchitected_workload", "Well-Architected workload has no high or medium risks",
    {"WorkloadArn": "arn:aws:wellarchitected:us-east-1:111111111111:workload/w", "RiskCounts": {"HIGH": 0, "MEDIUM": 0, "NONE": 10}},
    {"WorkloadArn": "arn:aws:wellarchitected:us-east-1:111111111111:workload/w", "RiskCounts": {"HIGH": 2, "NONE": 8}},
    rows=[P + "wellarchitected_workload_no_high_or_medium_risks"], severity="medium", control="CA-7",
    remediation="Address the high and medium risk items in the workload review.", docs=["https://docs.aws.amazon.com/wellarchitected/latest/APIReference/API_WorkloadSummary.html"],
    note="Prowler fails when HIGH or MEDIUM is a RiskCounts key; here a key with a zero count is not a risk (avoids a false positive).")
def wa(item, index):
    counts = get(item, "RiskCounts", dict)
    risky = {k: counts.get(k) for k in ("HIGH", "MEDIUM") if isinstance(counts.get(k), int) and counts.get(k) > 0}
    for k in ("HIGH", "MEDIUM"):
        if k in counts and type(counts[k]) is not int:
            raise Unavailable("malformed risk count")
    return result(bool(risky), risks=risky)


# Resource fixtures evaluate against the audited snapshot context (capture clock, account, region).
for _cid in IDS[_FIRST:]:
    CASES[_cid].setdefault("index", {"context": dict(CONTEXT)})
