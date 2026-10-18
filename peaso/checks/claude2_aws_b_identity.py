"""claude2_aws_b identity group: ACM, AWS Private CA, Amazon Bedrock, Cognito, Amazon Connect,
AWS Directory Service, Firewall Manager, Amplify and Data Pipeline.

Every predicate reads only documented, read-only API response shapes. Missing, denied or
partial facts are UNKNOWN; resources outside the source's applicability are NOT_APPLICABLE.
Kinds that the collector does not yet hydrate are listed in COLLECTOR_FACTS (and in the
coverage doc); their predicates stay UNKNOWN until the facts exist.
"""
from __future__ import annotations

from datetime import timedelta

from . import result, unknown
from .facts import Unavailable, get, list_of_objects, optional, complete_items
from .fixtures import nest
from .claude2_aws_b_common import (P, C, X, install, manual_case, detail, detail_list, clock, parse_time, days_between,
                                   policy_document, scope_of, inventory, indexes, _merge, ACCOUNT, SCOPE, CONTEXT)
from .claude_aws_a_iam import attached_arns, is_service_role

ANCHOR = {"scope": SCOPE}
NOW = "2026-01-01T00:00:00+00:00"
CLOCK_INDEX = {"context": dict(CONTEXT)}


def _value(obj, path, default, expected):
    """Documented-omission read below an already-proven response object."""
    parent = obj
    parts = path.split(".")
    for part in parts[:-1]:
        parent = optional(parent, part, {}, dict)
    value = optional(parent, parts[-1], default, expected)
    if expected in (bool, int) and type(value) is not expected:
        raise Unavailable("malformed fact: " + path)
    if expected not in (None, bool, int) and not isinstance(value, expected):
        raise Unavailable("malformed fact: " + path)
    return value


# =========================================================================== ACM (Prowler, in-use certificates)
D_ACM = "https://docs.aws.amazon.com/acm/latest/APIReference/API_CertificateDetail.html"
D_ACM_LIST = "https://docs.aws.amazon.com/acm/latest/APIReference/API_CertificateSummary.html"
CERT_ARN = "arn:aws:acm:us-east-1:111111111111:certificate/c1"


def _cert(**fields):
    body = {"CertificateArn": CERT_ARN, "Type": "AMAZON_ISSUED", "Status": "ISSUED", "KeyAlgorithm": "RSA-2048",
            "InUseBy": ["arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/a/1"],
            "NotAfter": "2026-06-01T00:00:00+00:00", "Options": {"CertificateTransparencyLoggingPreference": "ENABLED"}}
    body.update(fields)
    return {"CertificateArn": CERT_ARN, "Certificate": {"collection_status": "collected", "Certificate": body}}


def _acm_detail(item):
    container = detail(item, "Certificate")
    if container is None:
        raise Unavailable("certificate no longer exists")
    body = get(container, "Certificate", dict)
    get(body, "CertificateArn", str)
    return body


def _acm_in_use(body):
    """Prowler reports only in-use certificates (scan_unused_services defaults to false)."""
    in_use = _value(body, "InUseBy", [], list)
    return None if in_use else {"in_use": False, "reason": "Prowler only evaluates certificates that are in use"}


@install("aws.c2b.acm.in_use_not_expiring_7_days", "acm_certificate", "In-use ACM certificate expires in more than 7 days",
    _cert(), _cert(NotAfter="2026-01-05T00:00:00+00:00"), rows=[P + "acm_certificates_expiration_check"], severity="high", control="SC-17",
    remediation="Renew or re-import the certificate, or enable ACM managed renewal, before it expires.", docs=[D_ACM, D_ACM_LIST],
    extra={"index": CLOCK_INDEX, "not_applicable": _cert(InUseBy=[]), "expired": _cert(NotAfter="2025-12-01T00:00:00+00:00"), "expired_expect": "FAIL",
           "eight_days": _cert(NotAfter="2026-01-09T00:00:00+00:00"), "eight_days_expect": "PASS",
           "not_issued": _cert(NotAfter=None, Status="PENDING_VALIDATION"), "not_issued_expect": "NOT_APPLICABLE"},
    note="Prowler: (NotAfter - now).days > days_to_expire_threshold (default 7) passes. Prowler maps a missing NotAfter to 0 days (FAIL); "
         "here a certificate without NotAfter that is not ISSUED is NOT_APPLICABLE (never issued) and an ISSUED one without NotAfter is UNKNOWN.")
def acm_expiry(item, index):
    body = _acm_detail(item)
    skip = _acm_in_use(body)
    if skip:
        return "NOT_APPLICABLE", skip
    not_after = _value(body, "NotAfter", None, None)
    if not_after is None:
        status = get(body, "Status", str)
        if status != "ISSUED":
            return "NOT_APPLICABLE", {"certificate_status": status, "reason": "certificate has no validity period"}
        raise Unavailable("issued certificate without NotAfter")
    days = (parse_time(not_after) - clock(item, index)).days
    return result(days <= 7, expiration_days=days, threshold_days=7)


@install("aws.c2b.acm.in_use_transparency_logging", "acm_certificate", "In-use ACM certificate is imported or has Certificate Transparency logging enabled",
    _cert(), _cert(Options={"CertificateTransparencyLoggingPreference": "DISABLED"}), rows=[P + "acm_certificates_transparency_logs_enabled"],
    severity="medium", control="SC-17", remediation="Enable Certificate Transparency logging (UpdateCertificateOptions) for ACM-issued certificates.",
    docs=[D_ACM, "https://docs.aws.amazon.com/acm/latest/userguide/acm-concepts.html#concept-transparency"],
    extra={"not_applicable": _cert(InUseBy=[]), "imported": _cert(Type="IMPORTED", Options={"CertificateTransparencyLoggingPreference": "DISABLED"}),
           "imported_expect": "PASS"},
    note="Prowler: IMPORTED passes; otherwise Options.CertificateTransparencyLoggingPreference == ENABLED. Unlike aws.b.acm.transparency_logging "
         "(steampipe, imported = NOT_APPLICABLE, all certificates) this keeps Prowler's in-use applicability and imported PASS outcome.")
def acm_transparency(item, index):
    body = _acm_detail(item)
    skip = _acm_in_use(body)
    if skip:
        return "NOT_APPLICABLE", skip
    kind = get(body, "Type", str)
    if kind == "IMPORTED":
        return result(False, certificate_type=kind)
    preference = get(body, "Options.CertificateTransparencyLoggingPreference", str)
    if preference not in ("ENABLED", "DISABLED"):
        return unknown("unknown transparency logging preference")
    return result(preference != "ENABLED", certificate_type=kind, transparency_logging=preference)


_INSECURE_KEYS = {"RSA-1024", "P-192"}


@install("aws.c2b.acm.in_use_secure_key_algorithm", "acm_certificate", "In-use ACM certificate does not use an insecure key algorithm (RSA-1024, P-192)",
    _cert(), _cert(KeyAlgorithm="RSA_1024"), rows=[P + "acm_certificates_with_secure_key_algorithms"], severity="high", control="SC-12",
    remediation="Reissue the certificate with RSA 2048 or stronger, or an ECDSA P-256/P-384 key.", docs=[D_ACM, D_ACM_LIST],
    extra={"not_applicable": _cert(InUseBy=[]), "hyphen": _cert(KeyAlgorithm="RSA-1024"), "hyphen_expect": "FAIL",
           "ec": _cert(KeyAlgorithm="EC_prime256v1"), "ec_expect": "PASS"},
    note="Prowler insecure_key_algorithms default ['RSA-1024', 'P-192']. The ACM API reference spells the enum RSA_1024 while CLI output shows RSA-1024; "
         "both spellings are normalised (underscore -> hyphen) before comparison with the pinned list.")
def acm_key_algorithm(item, index):
    body = _acm_detail(item)
    skip = _acm_in_use(body)
    if skip:
        return "NOT_APPLICABLE", skip
    algorithm = get(body, "KeyAlgorithm", str)
    return result(algorithm.replace("_", "-") in _INSECURE_KEYS, key_algorithm=algorithm, insecure=sorted(_INSECURE_KEYS))


# =========================================================================== AWS Private CA
D_PCA = "https://docs.aws.amazon.com/privateca/latest/APIReference/API_CertificateAuthority.html"
PCA_ARN = "arn:aws:acm-pca:us-east-1:111111111111:certificate-authority/ca1"


def _ca(**fields):
    body = {"Arn": PCA_ARN, "Type": "ROOT", "Status": "DISABLED", "CertificateAuthorityConfiguration": {"KeyAlgorithm": "RSA_2048"}}
    body.update(fields)
    return body


@install("aws.c2b.acmpca.root_ca_disabled", "acmpca_certificate_authority", "AWS Private CA root certificate authority is disabled",
    _ca(), _ca(Status="ACTIVE"), rows=[C + "acmpca_root_certificate_authority_disabled", C + "foundational_security_pca_1"], severity="low", control="AC-6",
    remediation="Disable the root CA (UpdateCertificateAuthority Status=DISABLED) and keep it offline; issue from subordinate CAs.",
    docs=[D_PCA, "https://docs.aws.amazon.com/securityhub/latest/userguide/pca-controls.html"],
    extra={"not_applicable": _ca(Type="SUBORDINATE", Status="ACTIVE")},
    note="Steampipe: Type <> ROOT skips; Status DISABLED ok; any other status (including DELETED) alarms.")
def pca_root(item, index):
    get(item, "Arn", str)
    kind = get(item, "Type", str)
    if kind != "ROOT":
        return "NOT_APPLICABLE", {"type": kind}
    status = get(item, "Status", str)
    return result(status != "DISABLED", status=status)


_PQC = ("ML_DSA_44", "ML_DSA_65", "ML_DSA_87")


@install("aws.c2b.acmpca.pqc_key_algorithm", "acmpca_certificate_authority", "AWS Private CA uses a post-quantum (ML-DSA) key algorithm",
    _ca(Status="ACTIVE", CertificateAuthorityConfiguration={"KeyAlgorithm": "ML_DSA_65"}), _ca(Status="ACTIVE"),
    rows=[P + "acmpca_certificate_authority_pqc_key_algorithm"], severity="low", control="SC-12",
    remediation="Create a replacement CA with an ML-DSA key algorithm and migrate issuance to it.", docs=[D_PCA,
    "https://docs.aws.amazon.com/privateca/latest/APIReference/API_CertificateAuthorityConfiguration.html"],
    extra={"not_applicable": _ca(Status="DELETED")}, note="Prowler acmpca_pqc_key_algorithms default ML_DSA_44/65/87; DELETED CAs are skipped.")
def pca_pqc(item, index):
    get(item, "Arn", str)
    status = get(item, "Status", str)
    if status == "DELETED":
        return "NOT_APPLICABLE", {"status": status}
    algorithm = get(item, "CertificateAuthorityConfiguration.KeyAlgorithm", str)
    return result(algorithm not in _PQC, key_algorithm=algorithm, allowed=list(_PQC))


# =========================================================================== Cognito user pools (Prowler)
D_POOL = "https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UserPoolType.html"
D_CLIENT = "https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UserPoolClientType.html"
D_WAF_FOR = "https://docs.aws.amazon.com/waf/latest/APIReference/API_GetWebACLForResource.html"
POOL_ID = "us-east-1_abc"
POOL_ARN = "arn:aws:cognito-idp:us-east-1:111111111111:userpool/" + POOL_ID


def _up(pool=None, **extra):
    body = {"Id": POOL_ID, "Arn": POOL_ARN, **(pool or {})}
    return {"Id": POOL_ID, "Configuration": {"collection_status": "collected", "UserPool": body}, **extra}


def _pool(item):
    container = detail(item, "Configuration")
    if container is None:
        raise Unavailable("user pool no longer exists")
    pool = get(container, "UserPool", dict)
    get(pool, "Id", str)
    return pool


# The 12 Prowler cognito_user_pool_* password/MFA/deletion/threat-protection rows are held as ported by the
# active Codex shard reviewed_aws_b_cognito.json (aws.b.cognito.*), so they are dropped from this partition.


def _clients(item):
    _pool(item)
    out = []
    for client in detail_list(item, "Clients"):
        container = detail(client, "Configuration")
        if container is None:
            continue
        body = get(container, "UserPoolClient", dict)
        get(body, "ClientId", str)
        out.append(body)
    return out


def _with_clients(*bodies):
    return _up(Clients={"collection_status": "collected" if bodies else "empty", "items": [
        {"ClientId": b["ClientId"], "Configuration": {"collection_status": "collected", "UserPoolClient": b}} for b in bodies]})


def _client_check(cid, title, row, field, default, expected, good, bad, remediation, note):
    @install(cid, "cognito_user_pool", title, _with_clients({"ClientId": "c1", field: good}), _with_clients({"ClientId": "c1", field: good}, {"ClientId": "c2", field: bad}),
             rows=[P + row], severity="medium", control="IA-5", remediation=remediation, docs=[D_CLIENT], note=note,
             extra={"not_applicable": _with_clients(), "omitted": _with_clients({"ClientId": "c1"}), "omitted_expect": "FAIL"})
    def evaluate(item, index):
        clients = _clients(item)
        if not clients:
            return "NOT_APPLICABLE", {"reason": "user pool has no app clients"}
        failing = [get(c, "ClientId", str) for c in clients if _value(c, field, default, expected) != good]
        return result(bool(failing), failing_clients=failing, field=field)
    evaluate.__name__ = cid.replace(".", "_")


_client_check("aws.c2b.cognito.clients_prevent_user_existence_errors", "Every Cognito user pool app client prevents user existence errors",
              "cognito_user_pool_client_prevent_user_existence_errors", "PreventUserExistenceErrors", "", str, "ENABLED", "LEGACY",
              "Set PreventUserExistenceErrors to ENABLED on every app client.",
              "Prowler reports per app client: PreventUserExistenceErrors (default '') == ENABLED. Aggregated per pool: any failing client fails; a pool without clients is NOT_APPLICABLE.")
_client_check("aws.c2b.cognito.clients_token_revocation", "Every Cognito user pool app client has token revocation enabled",
              "cognito_user_pool_client_token_revocation_enabled", "EnableTokenRevocation", False, bool, True, False,
              "Set EnableTokenRevocation to true on every app client.",
              "Prowler reports per app client: EnableTokenRevocation (default False) must be true. Aggregated per pool.")


@install("aws.c2b.cognito.waf_web_acl_associated", "cognito_user_pool", "Cognito user pool is associated with a WAF web ACL",
    _up(WebAcl={"collection_status": "collected", "WebACL": {"Name": "acl", "ARN": "arn:aws:wafv2:us-east-1:111111111111:regional/webacl/acl/1"}}),
    _up(WebAcl={"collection_status": "collected"}), rows=[P + "cognito_user_pool_waf_acl_attached"], severity="medium", category="network", control="SC-7",
    remediation="Associate a regional AWS WAF web ACL with the user pool.", docs=[D_WAF_FOR, "https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-waf.html"],
    note="Prowler: pool ARN listed in any web ACL's COGNITO_USER_POOL resources. Equivalent per-pool read: wafv2 GetWebACLForResource(ResourceArn) returns WebACL, "
         "or no WebACL when none is associated.")
def cognito_waf(item, index):
    _pool(item)
    container = detail(item, "WebAcl")
    acl = None if container is None else _value(container, "WebACL", None, None)
    if acl is not None and not isinstance(acl, dict):
        raise Unavailable("malformed WebACL")
    return result(not acl, web_acl=(acl or {}).get("Name"))


# =========================================================================== Amazon Connect
D_CONNECT = "https://docs.aws.amazon.com/connect/latest/APIReference/API_DescribeInstanceAttribute.html"


def _connect(value):
    return {"Id": "i1", "Arn": "arn:aws:connect:us-east-1:111111111111:instance/i1",
            "ContactflowLogs": {"collection_status": "collected", "Attribute": {"AttributeType": "CONTACTFLOW_LOGS", "Value": value}}}


@install("aws.c2b.connect.contact_flow_logs", "connect_instance", "Amazon Connect instance has contact flow logs (CloudWatch) enabled",
    _connect("true"), _connect("false"), rows=[C + "connect_instance_logging_enabled", C + "foundational_security_connect_2"], severity="medium", control="AU-2",
    remediation="Enable contact flow logs on the instance (UpdateInstanceAttribute CONTACTFLOW_LOGS=true).",
    docs=[D_CONNECT, "https://docs.aws.amazon.com/securityhub/latest/userguide/connect-controls.html"],
    note="Steampipe: an aws_connect_instance_attribute row with attribute_type CONTACTFLOW_LOGS and value 'true' passes.")
def connect_logs(item, index):
    get(item, "Arn", str)
    container = detail(item, "ContactflowLogs")
    if container is None:
        raise Unavailable("instance no longer exists")
    attribute = get(container, "Attribute", dict)
    if get(attribute, "AttributeType", str) != "CONTACTFLOW_LOGS":
        raise Unavailable("unexpected attribute type")
    value = get(attribute, "Value", str)
    return result(value != "true", contactflow_logs=value)


# =========================================================================== Directory Service
D_DIR = "https://docs.aws.amazon.com/directoryservice/latest/devguide/API_DirectoryDescription.html"
D_TOPICS = "https://docs.aws.amazon.com/directoryservice/latest/devguide/API_DescribeEventTopics.html"
D_LOGSUB = "https://docs.aws.amazon.com/directoryservice/latest/devguide/API_ListLogSubscriptions.html"
D_SNAPLIM = "https://docs.aws.amazon.com/directoryservice/latest/devguide/API_SnapshotLimits.html"
D_DSCERT = "https://docs.aws.amazon.com/directoryservice/latest/devguide/API_CertificateInfo.html"
D_SHARED = "https://docs.aws.amazon.com/directoryservice/latest/devguide/API_DescribeSharedDirectories.html"
D_RADIUS = "https://docs.aws.amazon.com/directoryservice/latest/devguide/API_RadiusSettings.html"


def _lst(*rows):
    return {"collection_status": "collected" if rows else "empty", "items": list(rows)}


def _dir(**fields):
    base = {"DirectoryId": "d-1", "Type": "MicrosoftAD"}
    base.update(fields)
    return base


def _dir_type(item):
    get(item, "DirectoryId", str)
    return get(item, "Type", str)


@install("aws.c2b.directoryservice.sns_notifications", "directory_service_directory", "Directory Service directory has SNS event topic notifications",
    _dir(EventTopics=_lst({"TopicName": "t", "Status": "Registered"})), _dir(EventTopics=_lst()),
    rows=[P + "directoryservice_directory_monitor_notifications", C + "directory_service_directory_sns_notifications_enabled"], severity="medium", control="SI-4",
    remediation="Register an SNS topic for directory status notifications (RegisterEventTopic).", docs=[D_TOPICS],
    extra={"not_applicable": _dir(Type="SharedMicrosoftAD")},
    note="Both sources pass when DescribeEventTopics returns at least one topic. DescribeEventTopics is not supported for SharedMicrosoftAD directories "
         "(Prowler skips the call), so those are NOT_APPLICABLE here instead of failing on an empty default.")
def ds_topics(item, index):
    kind = _dir_type(item)
    if kind == "SharedMicrosoftAD":
        return "NOT_APPLICABLE", {"type": kind}
    topics = detail_list(item, "EventTopics")
    return result(not topics, event_topics=len(topics))


@install("aws.c2b.directoryservice.log_forwarding", "directory_service_directory", "Directory Service directory forwards security logs to CloudWatch Logs",
    _dir(LogSubscriptions=_lst({"DirectoryId": "d-1", "LogGroupName": "/aws/directoryservice/d-1"})), _dir(LogSubscriptions=_lst()),
    rows=[P + "directoryservice_directory_log_forwarding_enabled"], severity="medium", control="AU-2",
    remediation="Create a log subscription that forwards directory security logs to CloudWatch Logs (CreateLogSubscription).", docs=[D_LOGSUB],
    note="Prowler: ListLogSubscriptions for the directory returns at least one subscription.")
def ds_logs(item, index):
    _dir_type(item)
    subs = detail_list(item, "LogSubscriptions")
    return result(not subs, log_subscriptions=len(subs))


def _limits(limit, count, reached=False):
    return {"collection_status": "collected", "SnapshotLimits": {"ManualSnapshotsLimit": limit, "ManualSnapshotsCurrentCount": count, "ManualSnapshotsLimitReached": reached}}


@install("aws.c2b.directoryservice.manual_snapshot_quota", "directory_service_directory", "Directory Service directory has more than 2 manual snapshots of quota remaining",
    _dir(SnapshotLimits=_limits(5, 2)), _dir(SnapshotLimits=_limits(5, 3)),
    rows=[P + "directoryservice_directory_snapshots_limit", C + "directory_service_directory_snapshots_limit_2"], severity="low", control="CP-9",
    remediation="Delete obsolete manual snapshots so that more than two manual snapshots remain available.", docs=[D_SNAPLIM],
    extra={"reached": _dir(SnapshotLimits=_limits(5, 1, True)), "reached_expect": "FAIL",
           "not_applicable": _dir(Type="ADConnector", SnapshotLimits={"collection_status": "empty", "absent": True, "error": {"code": "UnsupportedOperationException"}})},
    note="Both sources: ManualSnapshotsLimitReached fails; otherwise (limit - current) <= 2 fails. A directory for which GetSnapshotLimits is unsupported "
         "(documented not-found/unsupported marker) is NOT_APPLICABLE (steampipe 'ok', Prowler no finding).")
def ds_snapshots(item, index):
    _dir_type(item)
    container = detail(item, "SnapshotLimits")
    if container is None:
        return "NOT_APPLICABLE", {"reason": "snapshot limits not supported for this directory"}
    limits = get(container, "SnapshotLimits", dict)
    reached = get(limits, "ManualSnapshotsLimitReached", bool)
    limit = get(limits, "ManualSnapshotsLimit", int)
    current = get(limits, "ManualSnapshotsCurrentCount", int)
    return result(reached or limit - current <= 2, limit=limit, current=current, limit_reached=reached, threshold_remaining=2)


def _dscert(expiry):
    return {"CertificateId": "c-1", "State": "Registered", "Type": "ClientLDAPS", "ExpiryDateTime": expiry}


def _ds_certificates(item):
    kind = _dir_type(item)
    if kind == "SimpleAD":
        return None, {"type": kind, "reason": "LDAPS certificates are not supported for Simple AD"}
    certs = detail_list(item, "Certificates")
    if not certs:
        return None, {"reason": "no LDAPS certificates registered"}
    return certs, None


@install("aws.c2b.directoryservice.ldap_certificate_over_90_days", "directory_service_directory", "Directory Service LDAPS certificates expire in more than 90 days (Prowler)",
    _dir(Certificates=_lst(_dscert("2026-04-02T00:00:00+00:00"))), _dir(Certificates=_lst(_dscert("2026-03-31T00:00:00+00:00"))),
    rows=[P + "directoryservice_ldap_certificate_expiration"], severity="medium", control="SC-17",
    remediation="Register a renewed LDAPS certificate before the current one expires.", docs=[D_DSCERT],
    extra={"index": CLOCK_INDEX, "not_applicable": _dir(Type="SimpleAD"), "none": _dir(Certificates=_lst()), "none_expect": "NOT_APPLICABLE"},
    note="Prowler: (ExpiryDateTime - now).days <= 90 fails (floor of the timedelta). Aggregated per directory: any expiring certificate fails.")
def ds_cert_prowler(item, index):
    certs, skip = _ds_certificates(item)
    if skip:
        return "NOT_APPLICABLE", skip
    now = clock(item, index)
    remaining = {get(c, "CertificateId", str): (parse_time(get(c, "ExpiryDateTime", str)) - now).days for c in certs}
    return result(any(d <= 90 for d in remaining.values()), remaining_days=remaining, threshold_days=90)


@install("aws.c2b.directoryservice.certificate_not_within_90_days", "directory_service_directory", "Directory Service certificates do not expire within 90 calendar days (steampipe)",
    _dir(Certificates=_lst(_dscert("2026-04-01T00:00:00+00:00"))), _dir(Certificates=_lst(_dscert("2026-03-31T23:00:00+00:00"))),
    rows=[C + "directory_service_certificate_expires_90_days"], severity="medium", control="SC-17",
    remediation="Register a renewed certificate before the current one is within 90 days of expiry.", docs=[D_DSCERT],
    extra={"index": CLOCK_INDEX, "not_applicable": _dir(Type="SimpleAD"), "none": _dir(Certificates=_lst()), "none_expect": "NOT_APPLICABLE"},
    note="Steampipe: date(expiry_date_time) - date(current_date) >= 90 is ok (calendar days). Different boundary from the Prowler rule, so kept separate.")
def ds_cert_steampipe(item, index):
    certs, skip = _ds_certificates(item)
    if skip:
        return "NOT_APPLICABLE", skip
    now = clock(item, index)
    remaining = {get(c, "CertificateId", str): days_between(parse_time(get(c, "ExpiryDateTime", str)), now) for c in certs}
    return result(any(d < 90 for d in remaining.values()), remaining_calendar_days=remaining, threshold_days=90)


@install("aws.c2b.directoryservice.radius_ms_chapv2", "directory_service_directory", "Directory Service RADIUS server uses MS-CHAPv2",
    _dir(RadiusSettings={"AuthenticationProtocol": "MS-CHAPv2"}, RadiusStatus="Completed"), _dir(RadiusSettings={"AuthenticationProtocol": "PAP"}, RadiusStatus="Completed"),
    rows=[P + "directoryservice_radius_server_security_protocol"], severity="medium", control="IA-2",
    remediation="Configure the RADIUS settings with AuthenticationProtocol MS-CHAPv2.", docs=[D_RADIUS, D_DIR],
    extra={"not_applicable": _dir()},
    note="Prowler: AuthenticationProtocol == MS-CHAPv2 passes. Prowler's RadiusSettings model is always truthy, so it also fails directories without RADIUS; "
         "those have no RADIUS server and are NOT_APPLICABLE here.")
def ds_radius_protocol(item, index):
    _dir_type(item)
    settings = optional(item, "RadiusSettings", None, dict)
    if not settings:
        return "NOT_APPLICABLE", {"reason": "no RADIUS server configured"}
    protocol = get(settings, "AuthenticationProtocol", str)
    return result(protocol != "MS-CHAPv2", authentication_protocol=protocol)


@install("aws.c2b.directoryservice.radius_mfa_enabled", "directory_service_directory", "Directory Service directory has RADIUS-based MFA enabled",
    _dir(RadiusSettings={"AuthenticationProtocol": "MS-CHAPv2"}, RadiusStatus="Completed"), _dir(),
    rows=[P + "directoryservice_supported_mfa_radius_enabled"], severity="medium", control="IA-2",
    remediation="Enable multi-factor authentication with a RADIUS server for the directory (EnableRadius).", docs=[D_RADIUS, D_DIR,
    "https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_mfa.html"],
    extra={"not_applicable": _dir(Type="SimpleAD"), "failed": _dir(RadiusSettings={"AuthenticationProtocol": "PAP"}, RadiusStatus="Failed"), "failed_expect": "FAIL"},
    note="Prowler: RadiusStatus == Completed passes; a directory without RadiusStatus fails. Simple AD and SharedMicrosoftAD directories cannot enable "
         "RADIUS MFA themselves and are NOT_APPLICABLE.")
def ds_radius_mfa(item, index):
    kind = _dir_type(item)
    if kind in ("SimpleAD", "SharedMicrosoftAD"):
        return "NOT_APPLICABLE", {"type": kind}
    status = optional(item, "RadiusStatus", None, str)
    return result(status != "Completed", radius_status=status)


@install("aws.c2b.directoryservice.shared_accounts_review", "directory_service_directory", "Directory Service directory is not shared with accounts outside a trusted list",
    _dir(SharedDirectories=_lst()), _dir(SharedDirectories=_lst()), rows=[X + "directory_service_directory_shared_with_trusted_accounts"],
    severity="medium", category="exposure", control="AC-3", remediation="Unshare the directory from any account that is not trusted (UnshareDirectory).",
    docs=[D_SHARED], extra={"simple_pass": _dir(Type="SimpleAD", SharedDirectories=_lst())},
    note="aws-perimeter compares SharedAccountId values with the operator-supplied trusted_accounts variable (placeholder default) and emits 'info' for others; "
         "unshared directories pass. Without a configured list, a shared directory is MANUAL with the accounts to review.")
def ds_shared(item, index):
    _dir_type(item)
    accounts = sorted({get(s, "SharedAccountId", str) for s in detail_list(item, "SharedDirectories")})
    if not accounts:
        return result(False, shared_with=[])
    return "MANUAL", {"shared_with": accounts, "question": "Are all of these accounts trusted for this directory?"}


manual_case("aws.c2b.directoryservice.shared_accounts_review", _dir(SharedDirectories=_lst({"SharedAccountId": "222222222222", "ShareStatus": "Shared"})))


# =========================================================================== Firewall Manager
D_FMS = "https://docs.aws.amazon.com/fms/2018-01-01/APIReference/API_ListComplianceStatus.html"


def _fms_policy(*statuses):
    return {"PolicyId": "p1", "PolicyName": "p", "PolicyArn": "arn:aws:fms:us-east-1:111111111111:policy/p1",
            "ComplianceStatus": _lst(*[{"PolicyId": "p1", "MemberAccount": "22222222222" + str(i), "EvaluationResults": [{"ComplianceStatus": s}] if s else []}
                                      for i, s in enumerate(statuses)])}


@install("aws.c2b.fms.policies_compliant", "fms_policy", "Observed Firewall Manager policy/account evaluations are compliant",
    ANCHOR, ANCHOR, rows=[P + "fms_policy_compliant"], severity="medium", category="network", control="SC-7", target="scope",
    dependencies=["fms_policy"], remediation="Review each observed non-compliant policy/account evaluation and correct the affected policy or resources.",
    docs=[D_FMS, "https://docs.aws.amazon.com/fms/2018-01-01/APIReference/API_PolicyComplianceStatus.html",
          "https://docs.aws.amazon.com/fms/2018-01-01/APIReference/API_EvaluationResult.html"],
    extra={"pass_index": inventory("fms_policy", [_fms_policy("COMPLIANT", "COMPLIANT")]), "fail_index": inventory("fms_policy", [_fms_policy("COMPLIANT", "NON_COMPLIANT")]),
           "not_applicable": ANCHOR, "not_applicable_index": inventory("fms_policy", []),
           "no_result": ANCHOR, "no_result_index": inventory("fms_policy", [_fms_policy(None)]), "no_result_expect": "UNKNOWN"},
    note="Pinned Prowler reads only the first EvaluationResults status and fails a missing result. AWS defines EvaluationResults as optional and each "
         "row has its own optional ComplianceStatus, so the native predicate examines every observed row: NON_COMPLIANT fails; missing, malformed, "
         "empty or unrecognized evaluations are UNKNOWN unless another row proves a violation. A complete empty regional policy inventory is "
         "NOT_APPLICABLE. PASS covers only returned policy/account evaluations; ListComplianceStatus does not establish organization-wide account coverage.")
def fms_compliant(item, index):
    scope = scope_of(item)
    policies = complete_items(index, "fms_policy")
    if not policies:
        return "NOT_APPLICABLE", {"scope": scope, "reason": "no Firewall Manager policies in this region"}
    failing = []
    incomplete = []
    observed = 0
    account_rows = 0
    for policy in policies:
        try:
            name = get(policy, "PolicyName", str)
            statuses = detail_list(policy, "ComplianceStatus")
        except Unavailable:
            incomplete.append({"policy": policy.get("PolicyId", "unknown"), "reason": "policy compliance status unavailable"})
            continue
        if not statuses:
            incomplete.append({"policy": name, "reason": "no member account evaluations returned"})
        for status in statuses:
            account_rows += 1
            try:
                account = get(status, "MemberAccount", str)
                if not account or not account.isdecimal():
                    raise Unavailable("missing or malformed member account")
            except Unavailable:
                account = "unknown"
                incomplete.append({"policy": name, "reason": "member account unavailable"})
            try:
                evaluations = get(status, "EvaluationResults", list)
            except Unavailable:
                evaluations = []
            if not evaluations:
                incomplete.append({"policy": name, "account": account, "reason": "evaluation results unavailable or empty"})
            for evaluation in evaluations:
                try:
                    value = get(evaluation, "ComplianceStatus", str)
                except Unavailable:
                    incomplete.append({"policy": name, "account": account, "reason": "evaluation status unavailable or malformed"})
                    continue
                if value == "NON_COMPLIANT":
                    failing.append({"policy": name, "account": account, "status": value})
                elif value == "COMPLIANT":
                    observed += 1
                else:
                    incomplete.append({"policy": name, "account": account, "reason": "unrecognized evaluation status"})
    evidence = {"scope": scope, "policy_count": len(policies), "member_account_rows": account_rows,
                "compliant_evaluations": observed, "non_compliant": failing,
                "coverage": "returned policy/account evaluations only; organization-wide account completeness is not established"}
    if failing:
        return "FAIL", {**evidence, "incomplete_evaluations": incomplete}
    if incomplete or not observed:
        return unknown("policy/account compliance evaluations incomplete or unavailable", **evidence,
                       incomplete_evaluations=incomplete)
    return "PASS", evidence


# =========================================================================== Amazon Bedrock
D_BR = "https://docs.aws.amazon.com/bedrock/latest/APIReference/"
D_GUARD = D_BR + "API_GetGuardrail.html"
D_AGENT = D_BR + "API_agent_AgentSummary.html"
D_LOGCFG = D_BR + "API_GetModelInvocationLoggingConfiguration.html"
GR_ARN = "arn:aws:bedrock:us-east-1:111111111111:guardrail/g1"


def _gr(**policies):
    body = {"guardrailId": "g1", "guardrailArn": GR_ARN, "name": "g", "version": "DRAFT", **policies}
    return {"id": "g1", "arn": GR_ARN, "name": "g", "Guardrail": {"collection_status": "collected", **body}}


def _guardrail(item):
    container = detail(item, "Guardrail")
    if container is None:
        raise Unavailable("guardrail no longer exists")
    get(container, "guardrailId", str)
    return container


_PA = lambda strength: {"contentPolicy": {"filters": [{"type": "PROMPT_ATTACK", "inputStrength": strength, "outputStrength": "NONE"}]}}


@install("aws.c2b.bedrock.guardrail_prompt_attack_high", "bedrock_guardrail", "Bedrock guardrail prompt attack filter strength is HIGH",
    _gr(**_PA("HIGH")), _gr(**_PA("MEDIUM")), rows=[P + "bedrock_guardrail_prompt_attack_filter_enabled"], severity="high", control="SI-10",
    remediation="Configure the guardrail content policy PROMPT_ATTACK filter with inputStrength HIGH.", docs=[D_GUARD, D_BR + "API_GuardrailContentFilter.html"],
    extra={"no_filter": _gr(), "no_filter_expect": "FAIL"},
    note="Prowler: the PROMPT_ATTACK content filter inputStrength (default NONE) must be HIGH; no filter fails.")
def br_prompt_attack(item, index):
    body = _guardrail(item)
    strength = None
    for f in list_of_objects(_value(body, "contentPolicy.filters", [], list)):
        if optional(f, "type", None, str) == "PROMPT_ATTACK":
            strength = optional(f, "inputStrength", "NONE", str)
    return result(strength != "HIGH", prompt_attack_input_strength=strength)


@install("aws.c2b.bedrock.guardrail_sensitive_information_filter", "bedrock_guardrail", "Bedrock guardrail blocks or masks sensitive information",
    _gr(sensitiveInformationPolicy={"piiEntities": [{"type": "EMAIL", "action": "ANONYMIZE"}]}), _gr(),
    rows=[P + "bedrock_guardrail_sensitive_information_filter_enabled"], severity="high", control="SC-28",
    remediation="Add a sensitive information policy (PII entities or regexes with BLOCK/ANONYMIZE) to the guardrail.", docs=[D_GUARD],
    note="Prowler: sensitiveInformationPolicy present in the GetGuardrail response passes.")
def br_sensitive(item, index):
    body = _guardrail(item)
    present = "sensitiveInformationPolicy" in body
    return result(not present, sensitive_information_policy=present)


def _cg(*filters):
    return {"contextualGroundingPolicy": {"filters": [dict(zip(("type", "threshold", "action", "enabled"), f)) for f in filters]}}


@install("aws.c2b.bedrock.guardrail_contextual_grounding", "bedrock_guardrail", "Bedrock guardrail blocks ungrounded and irrelevant responses",
    _gr(**_cg(("GROUNDING", 0.7, "BLOCK", True), ("RELEVANCE", 0.7, "BLOCK", True))), _gr(**_cg(("GROUNDING", 0.7, "BLOCK", True))),
    rows=[P + "bedrock_guardrail_contextual_grounding_filter_enabled"], severity="high", control="SI-10",
    remediation="Configure GROUNDING and RELEVANCE contextual grounding filters, enabled, with action BLOCK and a threshold above 0.",
    docs=[D_GUARD, D_BR + "API_GuardrailContextualGroundingFilter.html"],
    extra={"disabled": _gr(**_cg(("GROUNDING", 0.7, "BLOCK", False), ("RELEVANCE", 0.7, "BLOCK", True))), "disabled_expect": "FAIL",
           "zero": _gr(**_cg(("GROUNDING", 0, "BLOCK", True), ("RELEVANCE", 0.7, "BLOCK", True))), "zero_expect": "FAIL",
           "none_policy": _gr(), "none_policy_expect": "FAIL",
           "omitted": {"id": "g1", "Guardrail": {"collection_status": "collected", "guardrailId": "g1", "contextualGroundingPolicy": {"filters": [
               {"type": "GROUNDING", "threshold": 0.7}, {"type": "RELEVANCE", "threshold": 0.7, "action": "BLOCK", "enabled": True}]}}}, "omitted_expect": "UNKNOWN"},
    note="Prowler: both GROUNDING and RELEVANCE present; explicit enabled false, a non-BLOCK action or threshold <= 0 fails; omitted enabled/action "
         "(no documented default) is Prowler MANUAL and UNKNOWN here.")
def br_grounding(item, index):
    body = _guardrail(item)
    filters = {}
    for f in list_of_objects(_value(body, "contextualGroundingPolicy.filters", [], list)):
        kind = optional(f, "type", None, str)
        if kind:
            filters[kind] = f
    missing = sorted({"GROUNDING", "RELEVANCE"} - set(filters))
    if missing:
        return result(True, missing_filters=missing)
    reasons, unresolved = [], []
    for kind in ("GROUNDING", "RELEVANCE"):
        f = filters[kind]
        enabled = optional(f, "enabled", None, bool)
        action = optional(f, "action", None, str)
        threshold = optional(f, "threshold", 0, None)
        if not isinstance(threshold, (int, float)) or isinstance(threshold, bool):
            raise Unavailable("malformed grounding threshold")
        if enabled is False:
            reasons.append(kind + " disabled")
        elif action is not None and action != "BLOCK":
            reasons.append(kind + " action " + action)
        elif not threshold > 0:
            reasons.append(kind + " threshold 0")
        elif action is None or enabled is None:
            unresolved.append(kind)
    if reasons:
        return result(True, reasons=reasons)
    if unresolved:
        raise Unavailable("grounding filter omits enabled/action: " + ", ".join(unresolved))
    return result(False, filters=["GROUNDING", "RELEVANCE"])


@install("aws.c2b.bedrock.guardrails_configured", "bedrock_guardrail", "At least one Amazon Bedrock guardrail is configured in the region",
    ANCHOR, ANCHOR, rows=[P + "bedrock_guardrails_configured"], severity="medium", control="SI-10", target="scope", dependencies=["bedrock_guardrail"],
    remediation="Create a Bedrock guardrail (CreateGuardrail) and apply it to model invocations and agents.", docs=[D_BR + "API_ListGuardrails.html"],
    extra={"pass_index": inventory("bedrock_guardrail", [{"id": "g1", "arn": GR_ARN}]), "fail_index": inventory("bedrock_guardrail", [])},
    note="Prowler: per successfully listed region, at least one guardrail passes; none fails. A region where ListGuardrails was not collected is UNKNOWN.")
def br_guardrails_configured(item, index):
    scope = scope_of(item)
    rows = complete_items(index, "bedrock_guardrail")
    return result(not rows, scope=scope, guardrails=len(rows))


def _agent(guardrail=True):
    out = {"agentId": "a1", "agentName": "a", "agentStatus": "PREPARED"}
    if guardrail:
        out["guardrailConfiguration"] = {"guardrailIdentifier": "g1", "guardrailVersion": "1"}
    return out


@install("aws.c2b.bedrock.agent_guardrail", "bedrock_agent", "Amazon Bedrock agent uses a guardrail",
    _agent(), _agent(False), rows=[P + "bedrock_agent_guardrail_enabled"], severity="high", control="SI-10",
    remediation="Associate a guardrail with the agent (UpdateAgent guardrailConfiguration).", docs=[D_AGENT, D_BR + "API_agent_GuardrailConfiguration.html"],
    note="Prowler: ListAgents summary guardrailConfiguration.guardrailIdentifier set passes; agentId proves the summary was read, so an omitted guardrailConfiguration is a configured absence.")
def br_agent_guardrail(item, index):
    get(item, "agentId", str)
    config = optional(item, "guardrailConfiguration", {}, dict)
    gid = optional(config, "guardrailIdentifier", None, str) if config else None
    return result(not gid, guardrail_identifier=gid)


def _detail_key_check(cid, kind, title, row, container_key, sentinel, field, *, base, severity, remediation, docs, note):
    def mk(value):
        body = {sentinel: "x"}
        if value:
            body[field] = value
        return {**base, container_key: {"collection_status": "collected", **body}}

    @install(cid, kind, title, mk("arn:aws:kms:us-east-1:111111111111:key/k1"), mk(None), rows=[P + row], severity=severity, control="SC-28",
             remediation=remediation, docs=docs, note=note)
    def evaluate(item, index):
        container = detail(item, container_key)
        if container is None:
            raise Unavailable("resource no longer exists")
        get(container, sentinel, str)
        key = optional(container, field, None, str)
        return result(not key, kms_key_arn=key)
    evaluate.__name__ = cid.replace(".", "_")


_detail_key_check("aws.c2b.bedrock.custom_model_cmk", "bedrock_custom_model", "Bedrock custom model is encrypted with a customer managed KMS key",
                  "bedrock_custom_model_encrypted_with_cmk", "Model", "modelArn", "modelKmsKeyArn", base={"modelArn": "m", "modelName": "m"}, severity="critical",
                  remediation="Re-create the custom model (customization job) with a customer managed customModelKmsKeyId.", docs=[D_BR + "API_GetCustomModel.html"],
                  note="Prowler: GetCustomModel modelKmsKeyArn set passes (owned models only, ListCustomModels isOwned=true); a failed detail read is UNKNOWN.")
_detail_key_check("aws.c2b.bedrock.prompt_cmk", "bedrock_prompt", "Bedrock prompt is encrypted with a customer managed KMS key",
                  "bedrock_prompt_encrypted_with_cmk", "Prompt", "id", "customerEncryptionKeyArn", base={"id": "p1", "arn": "p"}, severity="medium",
                  remediation="Set customerEncryptionKeyArn (a customer managed KMS key) on the prompt.", docs=[D_BR + "API_agent_GetPrompt.html"],
                  note="Prowler: GetPrompt customerEncryptionKeyArn set passes.")


def _kb(*keys):
    return {"knowledgeBaseId": "kb1", "name": "kb", "DataSources": _lst(*[
        {"dataSourceId": "ds" + str(i), "Detail": {"collection_status": "collected", "dataSource": {"dataSourceId": "ds" + str(i),
         **({"serverSideEncryptionConfiguration": {"kmsKeyArn": k}} if k else {})}}} for i, k in enumerate(keys)])}


@install("aws.c2b.bedrock.knowledge_base_data_sources_cmk", "bedrock_knowledge_base", "Bedrock knowledge base data sources are encrypted with a customer managed KMS key",
    _kb("arn:aws:kms:us-east-1:111111111111:key/k1"), _kb("arn:aws:kms:us-east-1:111111111111:key/k1", None),
    rows=[P + "bedrock_knowledge_base_encrypted_with_cmk"], severity="high", control="SC-28",
    remediation="Set serverSideEncryptionConfiguration.kmsKeyArn (customer managed key) on every knowledge base data source.",
    docs=[D_BR + "API_agent_GetDataSource.html", D_BR + "API_agent_ServerSideEncryptionConfiguration.html"],
    extra={"not_applicable": _kb()},
    note="Prowler reports per data source: GetDataSource serverSideEncryptionConfiguration.kmsKeyArn set passes. Aggregated per knowledge base; "
         "a knowledge base without data sources is NOT_APPLICABLE; an unlisted data-source list is UNKNOWN.")
def br_kb(item, index):
    get(item, "knowledgeBaseId", str)
    sources = detail_list(item, "DataSources")
    if not sources:
        return "NOT_APPLICABLE", {"reason": "knowledge base has no data sources"}
    failing = []
    for source in sources:
        container = detail(source, "Detail")
        if container is None:
            continue
        body = get(container, "dataSource", dict)
        sid = get(body, "dataSourceId", str)
        if not _value(body, "serverSideEncryptionConfiguration.kmsKeyArn", None, None):
            failing.append(sid)
    return result(bool(failing), data_sources_without_cmk=failing)


def _logcfg(config=None):
    row = {"collection_status": "collected"}
    if config is not None:
        row["loggingConfig"] = config
    return inventory("bedrock_model_invocation_logging", [row])


_LOGCFG = {"cloudWatchConfig": {"logGroupName": "/bedrock/inv", "roleArn": "r"}, "s3Config": {"bucketName": "inv-bucket"}, "textDataDeliveryEnabled": True}


def _logging(index):
    rows = complete_items(index, "bedrock_model_invocation_logging")
    if len(rows) != 1:
        raise Unavailable("expected one model invocation logging configuration per region")
    row = rows[0]
    if row.get("collection_status") not in (None, "collected"):
        raise Unavailable("logging configuration not collected")
    config = optional(row, "loggingConfig", {}, dict)
    return config


@install("aws.c2b.bedrock.model_invocation_logging", "bedrock_model_invocation_logging", "Amazon Bedrock model invocation logging is enabled in the region",
    ANCHOR, ANCHOR, rows=[P + "bedrock_model_invocation_logging_enabled"], severity="medium", control="AU-2", target="scope",
    dependencies=["bedrock_model_invocation_logging"], remediation="Enable model invocation logging to CloudWatch Logs and/or S3 (PutModelInvocationLoggingConfiguration).",
    docs=[D_LOGCFG], extra={"pass_index": _logcfg(_LOGCFG), "fail_index": _logcfg()},
    note="Prowler: a non-empty loggingConfig in GetModelInvocationLoggingConfiguration passes.")
def br_logging(item, index):
    scope = scope_of(item)
    config = _logging(index)
    return result(not config, scope=scope, cloudwatch=bool(config.get("cloudWatchConfig")), s3=bool(config.get("s3Config")))


_ENC_BUCKET = {"Name": "inv-bucket", "Encryption": {"collection_status": "collected", "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}}}
_RAW_BUCKET = {"Name": "inv-bucket", "Encryption": {"collection_status": "empty", "absent": True, "error": {"code": "ServerSideEncryptionConfigurationNotFoundError"}}}
_KMS_LG = {"logGroupName": "/bedrock/inv", "arn": "arn:aws:logs:us-east-1:111111111111:log-group:/bedrock/inv:*", "kmsKeyId": "arn:aws:kms:us-east-1:111111111111:key/k1"}
_RAW_LG = {"logGroupName": "/bedrock/inv", "arn": "arn:aws:logs:us-east-1:111111111111:log-group:/bedrock/inv:*"}


@install("aws.c2b.bedrock.invocation_logs_encrypted", "bedrock_model_invocation_logging", "Bedrock model invocation logs are encrypted in S3 and KMS-encrypted in CloudWatch Logs",
    ANCHOR, ANCHOR, rows=[P + "bedrock_model_invocation_logs_encryption_enabled"], severity="high", control="SC-28", target="scope",
    dependencies=["bedrock_model_invocation_logging", "bucket", "log_group"],
    remediation="Enable default encryption on the destination bucket and associate a KMS key with the destination log group.",
    docs=[D_LOGCFG, "https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_LogGroup.html",
          "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketEncryption.html"],
    extra={"pass_index": indexes(_logcfg(_LOGCFG), inventory("bucket", [_ENC_BUCKET]), inventory("log_group", [_KMS_LG])),
           "fail_index": indexes(_logcfg(_LOGCFG), inventory("bucket", [_ENC_BUCKET]), inventory("log_group", [_RAW_LG])),
           "not_applicable": ANCHOR, "not_applicable_index": _logcfg(),
           "bucket": ANCHOR, "bucket_index": indexes(_logcfg(_LOGCFG), inventory("bucket", [_RAW_BUCKET]), inventory("log_group", [_KMS_LG])), "bucket_expect": "FAIL",
           "external": ANCHOR, "external_index": indexes(_logcfg(_LOGCFG), inventory("bucket", []), inventory("log_group", [])), "external_expect": "PASS"},
    note="Prowler (logging enabled only): the destination bucket, when present in the inventory, must have default encryption, and the destination "
         "log group, when present, must have kmsKeyId. Destinations outside the complete inventory are not failed, as upstream.")
def br_logs_encrypted(item, index):
    scope = scope_of(item)
    config = _logging(index)
    if not config:
        return "NOT_APPLICABLE", {"scope": scope, "reason": "model invocation logging disabled"}
    failures = []
    bucket = _value(config, "s3Config.bucketName", None, None)
    if bucket:
        for row in complete_items(index, "bucket"):
            if get(row, "Name", str) == bucket and detail(row, "Encryption") is None:
                failures.append("s3:" + bucket)
    group = _value(config, "cloudWatchConfig.logGroupName", None, None)
    if group:
        for row in complete_items(index, "log_group"):
            if get(row, "logGroupName", str) == group and not absent_or_kms(row):
                failures.append("logs:" + group)
    return result(bool(failures), scope=scope, unencrypted=failures)


def absent_or_kms(row):
    return optional(row, "kmsKeyId", None, str)


@install("aws.c2b.bedrock.prompt_management_exists", "bedrock_prompt", "Amazon Bedrock Prompt Management prompts exist in the region",
    ANCHOR, ANCHOR, rows=[P + "bedrock_prompt_management_exists"], severity="low", control="CM-2", target="scope", dependencies=["bedrock_prompt"],
    remediation="Manage production prompts with Bedrock Prompt Management (CreatePrompt) for versioning and review.", docs=[D_BR + "API_agent_ListPrompts.html"],
    extra={"pass_index": inventory("bedrock_prompt", [{"id": "p1", "arn": "p"}]), "fail_index": inventory("bedrock_prompt", [])},
    note="Prowler: per region where ListPrompts succeeded, at least one prompt passes; none fails.")
def br_prompts_exist(item, index):
    scope = scope_of(item)
    rows = complete_items(index, "bedrock_prompt")
    return result(not rows, scope=scope, prompts=len(rows))


_BR_ENDPOINTS = ("bedrock", "bedrock-runtime", "bedrock-agent", "bedrock-agent-runtime", "bedrock-mantle")


def _endpoint(svc, vpc="vpc-1", state="available"):
    return {"VpcEndpointId": "vpce-" + svc, "VpcId": vpc, "State": state, "ServiceName": "com.amazonaws.us-east-1." + svc}


def _br_active(index):
    """Prowler: logging enabled, any guardrail or any agent in the region."""
    unknown_parts = []
    try:
        if _logging(index):
            return True
    except Unavailable:
        unknown_parts.append("bedrock_model_invocation_logging")
    for kind in ("bedrock_guardrail", "bedrock_agent"):
        try:
            if complete_items(index, kind):
                return True
        except Unavailable:
            unknown_parts.append(kind)
    if unknown_parts:
        raise Unavailable("Bedrock activity unknown: " + ", ".join(unknown_parts))
    return False


_VPC = {"VpcId": "vpc-1", "State": "available"}
_ACTIVE = indexes(_logcfg(_LOGCFG), inventory("bedrock_guardrail", []), inventory("bedrock_agent", []), inventory("network_interface", [{"NetworkInterfaceId": "eni-1", "VpcId": "vpc-1"}]))


@install("aws.c2b.bedrock.vpc_endpoints", "vpc", "In-use VPC in a Bedrock-active region has interface endpoints for all Bedrock APIs",
    _VPC, _VPC, rows=[P + "bedrock_vpc_endpoints_configured"], severity="medium", category="network", control="SC-7",
    dependencies=["vpc", "vpc_endpoint", "network_interface", "bedrock_model_invocation_logging", "bedrock_guardrail", "bedrock_agent"],
    remediation="Create interface VPC endpoints for bedrock, bedrock-runtime, bedrock-agent, bedrock-agent-runtime and bedrock-mantle in the VPC.",
    docs=["https://docs.aws.amazon.com/bedrock/latest/userguide/vpc-interface-endpoints.html"],
    extra={"pass_index": indexes(_ACTIVE, inventory("vpc_endpoint", [_endpoint(s) for s in _BR_ENDPOINTS])),
           "fail_index": indexes(_ACTIVE, inventory("vpc_endpoint", [_endpoint(s) for s in _BR_ENDPOINTS[:4]])),
           "not_applicable": _VPC, "not_applicable_index": indexes(_logcfg(), inventory("bedrock_guardrail", []), inventory("bedrock_agent", []),
                                                                    inventory("network_interface", []), inventory("vpc_endpoint", []))},
    note="Prowler: only VPCs with network interfaces (in_use) in regions with Bedrock activity (invocation logging enabled, a guardrail or an agent); "
         "each of the five pinned Bedrock endpoint services must have an available endpoint in the VPC.")
def br_vpc_endpoints(item, index):
    vpc_id = get(item, "VpcId", str)
    if not any(get(e, "VpcId", str) == vpc_id for e in complete_items(index, "network_interface") if "VpcId" in e):
        return "NOT_APPLICABLE", {"reason": "VPC has no network interfaces"}
    if not _br_active(index):
        return "NOT_APPLICABLE", {"reason": "no Bedrock activity in the region"}
    found = set()
    for endpoint in complete_items(index, "vpc_endpoint"):
        if get(endpoint, "VpcId", str) == vpc_id and get(endpoint, "State", str).lower() == "available":
            service = get(endpoint, "ServiceName", str)
            found.update(s for s in _BR_ENDPOINTS if service.endswith("." + s))
    missing = [s for s in _BR_ENDPOINTS if s not in found]
    return result(bool(missing), missing_endpoint_services=missing)


BEDROCK_FULL = "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"
_HUMAN_TRUST = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % ACCOUNT}, "Action": "sts:AssumeRole"}]}
_SVC_TRUST = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"}, "Action": "sts:AssumeRole"}]}


def _role(trust=_HUMAN_TRUST, *arns):
    return {"RoleName": "app", "Arn": "arn:aws:iam::%s:role/app" % ACCOUNT, "Path": "/", "AssumeRolePolicyDocument": trust,
            "RolePolicyList": [], "AttachedManagedPolicies": [{"PolicyArn": a, "PolicyName": a.rsplit("/", 1)[1]} for a in arns]}


@install("aws.c2b.bedrock.role_no_full_access_policy", "iam_role", "Non-service IAM role does not have AmazonBedrockFullAccess attached",
    _role(_HUMAN_TRUST, "arn:aws:iam::aws:policy/ReadOnlyAccess"), _role(_HUMAN_TRUST, BEDROCK_FULL), rows=[P + "bedrock_full_access_policy_attached"],
    severity="high", category="least_privilege", control="AC-6", remediation="Detach AmazonBedrockFullAccess and grant scoped Bedrock permissions.",
    docs=["https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonBedrockFullAccess.html",
          "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html"],
    extra={"not_applicable": _role(_SVC_TRUST, BEDROCK_FULL)},
    note="Prowler: exact ARN arn:aws:iam::aws:policy/AmazonBedrockFullAccess among attached policies fails; service roles (Prowler is_service_role) are skipped.")
def br_full_access(item, index):
    if is_service_role(item):
        return "NOT_APPLICABLE", {"reason": "service role"}
    hit = BEDROCK_FULL in attached_arns(item, "iam_role")
    return result(hit, bedrock_full_access=hit)


def _ssc(expiry):
    out = {"ServiceSpecificCredentialId": "ACCA1", "UserName": "u", "ServiceName": "bedrock.amazonaws.com", "Status": "Active",
           "CreateDate": "2025-06-01T00:00:00+00:00"}
    if expiry:
        out["ExpirationDate"] = expiry
    return out


@install("aws.c2b.bedrock.api_key_long_term_expired", "iam_service_specific_credential", "Amazon Bedrock long-term API key has expired",
    _ssc("2025-12-01T00:00:00+00:00"), _ssc("2026-02-01T00:00:00+00:00"), rows=[P + "bedrock_api_key_no_long_term_credentials"], severity="high",
    category="least_privilege", control="IA-5", remediation="Delete long-term Bedrock API keys and use short-term (session-scoped) Bedrock API keys.",
    docs=["https://docs.aws.amazon.com/IAM/latest/APIReference/API_ServiceSpecificCredentialMetadata.html",
          "https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html"],
    extra={"index": CLOCK_INDEX, "not_applicable": _ssc(None), "other": {**_ssc("2026-02-01T00:00:00+00:00"), "ServiceName": "codecommit.amazonaws.com"},
           "other_expect": "NOT_APPLICABLE"},
    note="Prowler: Bedrock (bedrock.amazonaws.com) service-specific credentials with an ExpirationDate; already expired passes, any other fails "
         "(more than 10000 days remaining is reported as never-expiring, critical). Keys without ExpirationDate are skipped, as upstream.")
def br_api_key(item, index):
    service = get(item, "ServiceName", str)
    if service != "bedrock.amazonaws.com":
        return "NOT_APPLICABLE", {"service": service}
    get(item, "ServiceSpecificCredentialId", str)
    expiry = optional(item, "ExpirationDate", None, str)
    if not expiry:
        return "NOT_APPLICABLE", {"reason": "no expiration date (Prowler skips)"}
    now = clock(item, index)
    end = parse_time(expiry)
    if end <= now:
        return result(False, expired=True)
    return result(True, expired=False, days_remaining=(end - now).days, never_expires=(end - now) > timedelta(days=10000))


# =========================================================================== merged / manual / rejected
MERGED = {
    P + "cognito_identity_pool_guest_access_disabled": (["aws.b.cognito.no_guest_identities"],
        "Identity pool AllowUnauthenticatedIdentities false; Prowler reads the same DescribeIdentityPool member."),
}

MANUAL = {
    P + "bedrock_agent_role_least_privilege": {
        "question": "Does every Amazon Bedrock agent execution role avoid AWS-managed *FullAccess policies, administrative or privilege-escalation permissions, and have a permissions boundary?",
        "title": "Amazon Bedrock agent execution role follows least privilege",
        "guidance": "Prowler joins GetAgent agentResourceRoleArn with the IAM role inventory and applies its own administrative-access and privilege-escalation "
                    "combination catalogue to every attached and inline policy. That catalogue is Prowler-specific and not a documented AWS rule; review each "
                    "agent role's policies and permissions boundary against your least-privilege baseline.",
        "docs": [D_BR + "API_agent_Agent.html", "https://docs.aws.amazon.com/bedrock/latest/userguide/agents-permissions.html"],
    },
    P + "bedrock_agent_role_not_shared_across_agents": {
        "question": "Does every Amazon Bedrock agent (draft and every version routed by an active alias) use an execution role that no other agent in the account uses?",
        "title": "Amazon Bedrock agent has a dedicated execution role",
        "guidance": "The source builds an account-wide role index across all regions, agent drafts and alias-routed versions (ListAgentAliases, GetAgentVersion). "
                    "The per-region snapshot cannot prove dedication account-wide; list agentResourceRoleArn for every agent and deployed version and confirm no role repeats.",
        "docs": [D_BR + "API_agent_GetAgentVersion.html", D_BR + "API_agent_ListAgentAliases.html"],
    },
    P + "bedrock_api_key_no_administrative_privileges": {
        "question": "Do the IAM users that own Amazon Bedrock API keys lack administrative privileges, privilege-escalation paths and full Bedrock service access?",
        "title": "Amazon Bedrock API key owner has no administrative or privilege-escalation permissions",
        "guidance": "Prowler evaluates each Bedrock service-specific credential's user policies with its own admin/privilege-escalation/full-service catalogue. "
                    "Review the attached and inline policies of every user holding a Bedrock API key.",
        "docs": ["https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListServiceSpecificCredentials.html", "https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html"],
    },
}

_SECRET_SCAN = ("Upstream runs a secret-content scanner (detect-secrets) over the decoded payload. PEASO is a read-only configuration CSPM that does not collect or scan "
                "secret material; collecting full environment variables, build specs or pipeline definitions to grep for credentials is intrusive and unsuitable for the snapshot.")
REJECTED = {
    P + "amplify_app_no_secrets_in_environment": {"classification": "intrusive_unsuitable", "reason": _SECRET_SCAN, "replacement": [],
        "docs": ["https://docs.aws.amazon.com/amplify/latest/APIReference/API_App.html"]},
    P + "datapipeline_pipeline_no_secrets_in_definition": {"classification": "intrusive_unsuitable", "reason": _SECRET_SCAN, "replacement": [],
        "docs": ["https://docs.aws.amazon.com/datapipeline/latest/APIReference/API_GetPipelineDefinition.html"]},
}

# New collector facts (read-only APIs) needed for predicates of this group to leave UNKNOWN.
COLLECTOR_FACTS = [
    {"kind": "acmpca_certificate_authority", "api": "acm-pca ListCertificateAuthorities", "fields": "Arn, Type, Status, CertificateAuthorityConfiguration.KeyAlgorithm",
     "checks": ["aws.c2b.acmpca.root_ca_disabled", "aws.c2b.acmpca.pqc_key_algorithm"]},
    {"kind": "cognito_user_pool (detail WebAcl)", "api": "wafv2 GetWebACLForResource(ResourceArn=UserPool.Arn)", "fields": "WebACL.{Name, ARN} or omitted",
     "checks": ["aws.c2b.cognito.waf_web_acl_associated"]},
    {"kind": "connect_instance", "api": "connect ListInstances + DescribeInstanceAttribute(AttributeType=CONTACTFLOW_LOGS) as ContactflowLogs",
     "fields": "Id, Arn, ContactflowLogs.Attribute.{AttributeType, Value}", "checks": ["aws.c2b.connect.contact_flow_logs"]},
    {"kind": "directory_service_directory", "api": "ds DescribeDirectories + DescribeEventTopics (EventTopics) + ListLogSubscriptions (LogSubscriptions) + GetSnapshotLimits (SnapshotLimits) + ListCertificates (Certificates) + DescribeSharedDirectories(OwnerDirectoryId) (SharedDirectories)",
     "fields": "DirectoryId, Type, RadiusSettings.AuthenticationProtocol, RadiusStatus; EventTopics[].TopicName; LogSubscriptions[].LogGroupName; SnapshotLimits.{ManualSnapshotsLimit, ManualSnapshotsCurrentCount, ManualSnapshotsLimitReached}; Certificates[].{CertificateId, ExpiryDateTime}; SharedDirectories[].SharedAccountId (child lists as {collection_status, items}; never RADIUS shared secrets)",
     "checks": ["aws.c2b.directoryservice.*"]},
    {"kind": "fms_policy", "api": "fms ListPolicies + ListComplianceStatus(PolicyId) as ComplianceStatus",
     "fields": "PolicyId, PolicyName, PolicyArn; ComplianceStatus.items[].{MemberAccount, EvaluationResults[].ComplianceStatus}", "checks": ["aws.c2b.fms.policies_compliant"]},
    {"kind": "bedrock_guardrail", "api": "bedrock ListGuardrails + GetGuardrail(guardrailIdentifier) as Guardrail",
     "fields": "id, arn; Guardrail.{guardrailId, contentPolicy.filters[].{type, inputStrength}, sensitiveInformationPolicy (presence only), contextualGroundingPolicy.filters[].{type, threshold, action, enabled}}",
     "checks": ["aws.c2b.bedrock.guardrail_*", "aws.c2b.bedrock.guardrails_configured", "aws.c2b.bedrock.vpc_endpoints"]},
    {"kind": "bedrock_agent", "api": "bedrock-agent ListAgents", "fields": "agentId, agentName, guardrailConfiguration.guardrailIdentifier",
     "checks": ["aws.c2b.bedrock.agent_guardrail", "aws.c2b.bedrock.vpc_endpoints"]},
    {"kind": "bedrock_custom_model", "api": "bedrock ListCustomModels(isOwned=true) + GetCustomModel as Model", "fields": "modelArn, Model.{modelArn, modelKmsKeyArn}",
     "checks": ["aws.c2b.bedrock.custom_model_cmk"]},
    {"kind": "bedrock_prompt", "api": "bedrock-agent ListPrompts + GetPrompt as Prompt", "fields": "id, arn, Prompt.{id, customerEncryptionKeyArn} (never prompt text)",
     "checks": ["aws.c2b.bedrock.prompt_cmk", "aws.c2b.bedrock.prompt_management_exists"]},
    {"kind": "bedrock_knowledge_base", "api": "bedrock-agent ListKnowledgeBases + ListDataSources (DataSources) + GetDataSource as DataSources[].Detail",
     "fields": "knowledgeBaseId; DataSources.items[].Detail.dataSource.{dataSourceId, serverSideEncryptionConfiguration.kmsKeyArn} (no data source credentials)",
     "checks": ["aws.c2b.bedrock.knowledge_base_data_sources_cmk"]},
    {"kind": "bedrock_model_invocation_logging", "api": "bedrock GetModelInvocationLoggingConfiguration (one row per region)",
     "fields": "loggingConfig.{cloudWatchConfig.logGroupName, s3Config.bucketName} or omitted", "checks": ["aws.c2b.bedrock.model_invocation_logging", "aws.c2b.bedrock.invocation_logs_encrypted", "aws.c2b.bedrock.vpc_endpoints"]},
    {"kind": "iam_service_specific_credential", "api": "iam ListUsers + ListServiceSpecificCredentials(UserName, ServiceName=bedrock.amazonaws.com)",
     "fields": "ServiceSpecificCredentialId, UserName, ServiceName, Status, CreateDate, ExpirationDate (never the credential secret)", "checks": ["aws.c2b.bedrock.api_key_long_term_expired"]},
]
