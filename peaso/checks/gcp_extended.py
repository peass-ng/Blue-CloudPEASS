"""Reviewed GCP metadata predicates, independent of live clients and wall time.

Pinned source associations and scope differences live in reviewed_gcp.json.
Provider defaults are never substituted for absent or unreadable fields.
"""
from datetime import datetime
from decimal import Decimal, InvalidOperation
import re

from . import register, result, unknown
from .facts import Unavailable, field_check, get, list_of_objects, omitted
from .fixtures import CASES

PREFIX = "gcp.reviewed."
IDS = []


def rule(suffix, kind, title, *, severity="medium", control="CM-6", category="hardening"):
    cid = PREFIX + suffix
    IDS.append(cid)
    return register(cid, "gcp", category, kind, title, severity, control,
                    "Review this explicit configuration with the resource owner and apply the intended security policy.")


def scalar(suffix, kind, path, good, bad, title):
    cid = PREFIX + suffix
    IDS.append(cid)
    field_check(cid, "gcp", kind, path, good, bad, title, expected=type(good))


scalar("compute.deletion_protection", "instance", "deletionProtection", True, False,
       "Compute VM enables deletion protection")
scalar("compute.automatic_restart", "instance", "scheduling.automaticRestart", True, False,
       "Compute VM enables automatic restart")
scalar("compute.maintenance_migrate", "instance", "scheduling.onHostMaintenance", "MIGRATE", "TERMINATE",
       "Compute VM selects live migration during host maintenance")
scalar("compute.confidential_computing", "instance", "confidentialInstanceConfig.enableConfidentialCompute", True, False,
       "Compute VM explicitly enables confidential computing")
scalar("loadbalancer.backend_logging", "backend_service", "logConfig.enable", True, False,
       "Backend service explicitly enables request logging")


# Flow Logs apply to subnets carrying VM traffic. Compute documents that
# logConfig is omitted from get/list when not explicitly set and then defaults
# to disabled (an org policy requiring flow logs sets it at creation), and that
# REGIONAL_MANAGED_PROXY and other proxy/PSC purposes do not support it.
FLOW_LOG_PURPOSES = ("PRIVATE", "PRIVATE_RFC_1918")
NON_FLOW_LOG_PURPOSES = ("REGIONAL_MANAGED_PROXY", "GLOBAL_MANAGED_PROXY", "INTERNAL_HTTPS_LOAD_BALANCER",
    "PRIVATE_SERVICE_CONNECT", "PRIVATE_NAT", "PEER_MIGRATION")
DEPENDENCIES = {PREFIX + "network.flow_logs": ["subnetwork", "vpc_flow_logs_config"],
                PREFIX + "project.os_login_2fa": ["project", "org_policy_effective"]}


def _relative(link):
    """Validate native Flow Logs target identities without discarding authority."""
    from urllib.parse import urlsplit
    if not isinstance(link, str):
        raise Unavailable("Flow Logs target identity unavailable")
    parsed = urlsplit(link)
    if parsed.query or parsed.fragment:
        raise Unavailable("Flow Logs target query or fragment unsupported")
    if parsed.scheme or parsed.netloc:
        if parsed.scheme != "https" or parsed.netloc not in ("www.googleapis.com", "compute.googleapis.com"):
            raise Unavailable("foreign Flow Logs target authority")
        if not parsed.path.startswith("/compute/v1/projects/"):
            raise Unavailable("unsupported Flow Logs target API path")
        link = parsed.path
    value = link.removeprefix("/").removeprefix("compute/v1/")
    if not re.fullmatch(r"projects/[A-Za-z0-9_-]+/(?:global/networks|regions/[a-z][a-z0-9-]*/"
                        r"(?:subnetworks|vpnTunnels|interconnectAttachments))/[a-z](?:[-a-z0-9]*[a-z0-9])?", value):
        raise Unavailable("malformed Flow Logs target resource")
    return value


def network_management_flow_logs(item, index):
    """Network Management VpcFlowLogsConfig coverage of this subnet, or None."""
    from .facts import optional
    envelopes = index.get("collections", {}).get("vpc_flow_logs_config", []) if isinstance(index, dict) else []
    if not envelopes:
        return None, {"network_management_configs": "not_collected"}
    envelopes = list_of_objects(envelopes)
    bad = [{"status": row.get("status"), "error": row.get("error", {}).get("reason") or row.get("error", {}).get("code")}
           for row in envelopes if row.get("status") not in ("collected", "empty")]
    context = index.get("context", {})
    if context and get(context, "provider", str) != "gcp":
        raise Unavailable("GCP Flow Logs context unavailable")
    scope = context.get("scope")
    if scope is None and len(envelopes) == 1:
        scope = envelopes[0].get("scope")
    if (not isinstance(scope, str) or not re.fullmatch(r"projects/[A-Za-z0-9_-]+", scope)
            or any(row.get("scope") != scope for row in envelopes)):
        raise Unavailable("Flow Logs alternative project scope unavailable or inconsistent")
    subnet = _relative(get(item, "selfLink", str))
    network = _relative(get(item, "network", str))
    if not subnet.startswith(scope + "/") or not network.startswith(scope + "/"):
        raise Unavailable("subnet/network outside the Flow Logs evaluation project")
    matched, identities = [], {}
    for resource in list_of_objects(index.get("vpc_flow_logs_config", [])):
        config = get(resource, "data", dict)
        name = get(config, "name", str)
        native = {key: value for key, value in config.items() if not key.startswith("_")}
        if name in identities and identities[name] != native:
            raise Unavailable("conflicting Flow Logs config observations")
        identities[name] = native
        level = get(config, "configLevel", str)
        if level not in ("project", "organization"):
            raise Unavailable("Flow Logs config level unavailable")
        parent = re.escape(scope) if level == "project" else r"organizations/[1-9][0-9]*"
        if not re.fullmatch(parent + r"/locations/global/vpcFlowLogsConfigs/[A-Za-z0-9_-]+", name):
            raise Unavailable("Flow Logs config identity outside its declared scope")
        targets = {}
        for field in ("subnet", "network", "vpnTunnel", "interconnectAttachment"):
            target = optional(config, field, None, str)
            if target is not None:
                targets[field] = _relative(target)
        if len(targets) > 1:
            raise Unavailable("conflicting Flow Logs target selectors")
        state = optional(config, "state", "ENABLED", str)
        filtered = bool(optional(config, "filterExpr", "", str))
        if state not in ("ENABLED", "STATE_UNSPECIFIED", "DISABLED"):
            raise Unavailable("unrecognized Flow Logs config state")
        covers = targets.get("subnet") == subnet or targets.get("network") == network or (level == "organization" and not targets)
        if covers and state != "DISABLED":
            matched.append({"name": name, "level": level, "filtered": filtered})
    if bad:
        return matched, {"network_management_configs": "unverified", "network_management_status": bad}
    return matched, {"network_management_configs": "collected"}


@rule("network.flow_logs", "subnetwork", "Subnet explicitly enables VPC Flow Logs", control="AU-2")
def flow_logs(item, index):
    from .facts import optional
    purpose = omitted(item, "purpose", "PRIVATE", str)
    context = {"network": item.get("network"), "region": item.get("region"), "purpose": purpose}
    if purpose in NON_FLOW_LOG_PURPOSES:
        return "NOT_APPLICABLE", {**context, "reason": "Subnet purpose does not carry VM traffic or support Flow Logs"}
    if purpose not in FLOW_LOG_PURPOSES:
        return unknown("unrecognized subnet purpose", **context)
    legacy = optional(item, "enableFlowLogs", None, bool)
    if "logConfig" in item and "enable" in get(item, "logConfig", dict):
        enabled = get(item, "logConfig.enable", bool)
        if legacy is not None and legacy != enabled:
            return unknown("conflicting explicit legacy and structured Flow Logs settings", **context)
        source = "logConfig.enable"
    elif legacy is not None:
        enabled, source = legacy, "enableFlowLogs"
    else:
        # Absent only proves "unset => disabled" on a complete representation.
        enabled = omitted(item, "logConfig.enable", False, bool)
        source = "omitted (API default: disabled)"
    if enabled:
        return result(False, **context, flow_logs_enabled=True, source=source)
    matched, coverage = network_management_flow_logs(item, index)
    if matched:
        if all(row["filtered"] for row in matched):
            if coverage["network_management_configs"] != "collected":
                return unknown("unfiltered Flow Logs alternative coverage unresolved", **context, **coverage)
            return "MANUAL", {**context, **coverage, "vpc_flow_logs_configs": matched,
                "reason": "Only filtered Network Management Flow Logs configs cover this subnet"}
        return result(False, **context, **coverage, flow_logs_enabled=True, source="networkmanagement.vpcFlowLogsConfigs",
                      vpc_flow_logs_configs=matched)
    if coverage["network_management_configs"] != "collected":
        return unknown("alternative Flow Logs configuration inventory incomplete or unavailable", **context, **coverage)
    return result(True, **context, **coverage, flow_logs_enabled=False, source=source,
                  semantics="Subnet-level setting; Network Management configs are counted only when collected")


@rule("compute.ip_forwarding", "instance", "Compute VM restricts IP forwarding", control="SC-7")
def ip_forwarding(item, index):
    enabled = get(item, "canIpForward", bool)
    name = get(item, "name", str)
    if enabled and name.startswith("gke-"):
        return "MANUAL", {"canIpForward": enabled, "reason": "GKE naming hint requires ownership and forwarding review"}
    return result(enabled, canIpForward=enabled)


@rule("compute.single_interface", "instance", "Compute VM has one network interface", control="SC-7")
def single_interface(item, index):
    interfaces = list_of_objects(get(item, "networkInterfaces", list))
    name = get(item, "name", str)
    if not interfaces:
        return unknown("empty interface list is not a valid normal Compute VM configuration")
    if len(interfaces) > 1 and name.startswith("gke-"):
        return "MANUAL", {"interface_count": len(interfaces), "reason": "GKE naming hint may describe intentional multi-network configuration"}
    return result(len(interfaces) != 1, interface_count=len(interfaces))


def default_accounts(item):
    name = get(item, "name", str)
    accounts = list_of_objects(get(item, "serviceAccounts", list))
    defaults = []
    for account in accounts:
        email = get(account, "email", str)
        if re.fullmatch(r"[0-9]+-compute@developer\.gserviceaccount\.com", email):
            defaults.append(account)
    return name, defaults


@rule("compute.no_default_service_account", "instance", "Compute VM avoids the default service account", control="AC-6")
def no_default_account(item, index):
    name, defaults = default_accounts(item)
    if defaults and name.startswith("gke-"):
        return "MANUAL", {"reason": "Review GKE node identity and declared default service account", "accounts": [a["email"] for a in defaults]}
    return result(bool(defaults), accounts=[a["email"] for a in defaults], semantics="Declared attachment, not effective IAM permissions")


@rule("compute.no_default_full_api", "instance", "Compute VM avoids default identity with full OAuth API scope", control="AC-6")
def no_default_full_api(item, index):
    name, defaults = default_accounts(item)
    broad = []
    for account in defaults:
        scopes = get(account, "scopes", list)
        if any(not isinstance(scope, str) for scope in scopes):
            raise Unavailable("malformed service account OAuth scopes")
        if "https://www.googleapis.com/auth/cloud-platform" in scopes:
            broad.append(account["email"])
    if broad and name.startswith("gke-"):
        return "MANUAL", {"reason": "GKE naming hint requires node identity review", "accounts": broad}
    return result(bool(broad), accounts=broad, semantics="OAuth scope declaration; IAM still limits permissions")


@rule("compute.disk_auto_delete", "instance", "VM attached persistent disks avoid automatic deletion", control="CP-9")
def disk_auto_delete(item, index):
    disks = list_of_objects(get(item, "disks", list))
    affected = []
    for disk in disks:
        if disk.get("type") == "SCRATCH":
            continue
        if disk.get("type") not in (None, "PERSISTENT"):
            return unknown("unrecognized attached disk type")
        if get(disk, "autoDelete", bool):
            affected.append(disk.get("deviceName"))
    return result(bool(affected), auto_delete_devices=affected, semantics="Data-retention configuration, independent of snapshot coverage")


def metadata_flag(item, path, key, *, numeric=False):
    values = []
    for row in list_of_objects(get(item, path, list)):
        if get(row, "key", str) == key:
            value = get(row, "value", str).lower()
            if value not in (("true", "false", "1", "0") if numeric else ("true", "false")):
                raise Unavailable("malformed explicit metadata boolean")
            values.append(value in ("true", "1"))
    if len(values) != 1:
        raise Unavailable("metadata setting missing or duplicated; inherited/default setting unknown")
    return values[0]


@rule("compute.block_project_ssh_keys", "instance", "VM explicitly blocks project-wide SSH keys", control="AC-3")
def block_project_keys(item, index):
    flag = metadata_flag(item, "metadata.items", "block-project-ssh-keys")
    return result(not flag, block_project_ssh_keys=flag)


@rule("compute.no_serial_console", "instance", "VM explicitly disables serial-console access", control="AC-3")
def serial_console(item, index):
    flag = metadata_flag(item, "metadata.items", "serial-port-enable", numeric=True)
    return result(flag, serial_port_enable=flag)


@rule("project.os_login_2fa", "project", "Project explicitly enables OS Login with two-factor authentication", control="IA-2")
def project_os_login_2fa(item, index):
    # "For OS Login 2FA to be enforced, metadata for both OS Login (enable-oslogin)
    # and OS Login 2FA (enable-oslogin-2fa) must be set to TRUE" (Set up OS Login).
    # compute.requireOsLogin does not set enable-oslogin-2fa, so an unset project
    # key on a successful projects.get read is "not enforced".
    from . import ComputeDisabled, gcp_project_metadata_items, gcp_oslogin_unset
    try:
        rows = gcp_project_metadata_items(item)
    except ComputeDisabled:
        return "NOT_APPLICABLE", {"reason": "Compute Engine API is disabled in the project; no VM uses project metadata"}
    values = {"enable-oslogin": [], "enable-oslogin-2fa": []}
    for row in rows:
        key = get(row, "key", str)
        if key in values:
            value = get(row, "value", str).lower()
            if value not in ("true", "false"):
                raise Unavailable("malformed explicit metadata boolean")
            values[key].append(value == "true")
    if any(len(flags) > 1 for flags in values.values()):
        raise Unavailable("duplicated OS Login project metadata")
    login = values["enable-oslogin"][0] if values["enable-oslogin"] else None
    two_factor = values["enable-oslogin-2fa"][0] if values["enable-oslogin-2fa"] else None
    if two_factor is True and login is None:
        try:
            login, policy = gcp_oslogin_unset(index)
        except Unavailable as exc:
            return unknown("OS Login enablement unresolved while 2FA flag is true", detail=str(exc), enable_oslogin_2fa=True)
    return result(not (login and two_factor), enable_oslogin=login, enable_oslogin_2fa=two_factor,
        semantics="Both OS Login and 2FA declarations are required. Instance overrides, guest enforcement and principal eligibility need review")


@rule("network.no_default_vpc", "network", "VPC network avoids the default network", control="SC-7")
def no_default_vpc(item, index):
    name = get(item, "name", str)
    if not name:
        raise Unavailable("empty network name")
    return result(name == "default", network_name=name, semantics="Per-network predicate; complete project absence requires complete inventory")


@rule("storage.soft_delete", "bucket", "Bucket configures a positive soft-delete retention period", control="CP-9")
def soft_delete(item, index):
    value = get(item, "softDeletePolicy.retentionDurationSeconds", (str, int))
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
        raise Unavailable("invalid soft-delete retention duration")
    return result(int(value) == 0, retention_seconds=int(value))


# Cloud Storage buckets read with projection=full include every property; an
# unset logging/versioning/lifecycle configuration is omitted from the resource.
@rule("storage.versioning", "bucket", "Bucket enables object versioning", control="CP-9")
def bucket_versioning(item, index):
    enabled = omitted(item, "versioning.enabled", False, bool)
    return result(not enabled, field="versioning.enabled", configured=enabled,
                  source="versioning.enabled" if isinstance(item.get("versioning"), dict) and "enabled" in item["versioning"] else "omitted (unset)")


@rule("storage.access_logging", "bucket", "Bucket configures usage and storage log destination", control="AU-2")
def bucket_logging(item, index):
    logging = omitted(item, "logging", None, dict)
    if logging is None:
        return result(True, log_bucket=None, source="omitted (logging not configured)")
    target = get(logging, "logBucket", str)
    return result(not bool(target.strip()), log_bucket=target, semantics="Destination configured; delivery and destination permissions are separate evidence")


@rule("storage.lifecycle", "bucket", "Bucket declares a supported lifecycle rule and condition", control="CM-6")
def lifecycle(item, index):
    configuration = omitted(item, "lifecycle", None, dict)
    if configuration is None:
        return result(True, valid_rule_count=0, source="omitted (no lifecycle configuration)")
    rows = list_of_objects(omitted(item, "lifecycle.rule", [], list))
    valid = 0
    for row in rows:
        action = get(row, "action.type", str)
        condition = get(row, "condition", dict)
        if action not in ("Delete", "SetStorageClass", "AbortIncompleteMultipartUpload"):
            return unknown("unrecognized lifecycle action", action=action)
        if action == "SetStorageClass" and not get(row, "action.storageClass", str):
            return unknown("empty target storage class")
        valid += bool(condition)
    return result(valid == 0, valid_rule_count=valid, semantics="Configuration existence, not data-retention adequacy")


def primary_sql(item):
    kind = get(item, "instanceType", str)
    if kind not in ("CLOUD_SQL_INSTANCE", "READ_REPLICA_INSTANCE", "ON_PREMISES_INSTANCE"):
        raise Unavailable("unrecognized SQL instance type")
    return kind == "CLOUD_SQL_INSTANCE"


@rule("sql.high_availability", "sql_instance", "Primary SQL instance configures regional high availability", control="CP-10")
def sql_ha(item, index):
    if not primary_sql(item):
        return "NOT_APPLICABLE", {"reason": "Read replica or external SQL instance is outside primary-instance predicate"}
    availability = get(item, "settings.availabilityType", str)
    if availability not in ("REGIONAL", "ZONAL"):
        return unknown("unrecognized SQL availability type")
    return result(availability != "REGIONAL", availability_type=availability)


@rule("sql.cmek", "sql_instance", "Primary SQL instance declares customer-managed encryption", control="SC-12")
def sql_cmek(item, index):
    if not primary_sql(item):
        return "NOT_APPLICABLE", {"reason": "Not a primary Cloud SQL instance"}
    key = get(item, "diskEncryptionConfiguration.kmsKeyName", str)
    return result(not bool(key.strip()), kms_key_name=key)


def sql_flag(suffix, engine, flag, good, bad, title, *, values=None):
    @rule(suffix, "sql_instance", title, control="AU-2" if "log" in flag or "audit" in flag else "CM-6")
    def evaluate(item, index):
        version = get(item, "databaseVersion", str)
        if not version.startswith(("MYSQL_", "POSTGRES_", "SQLSERVER_")):
            return unknown("unrecognized SQL database engine")
        if not version.startswith(engine + "_"):
            return "NOT_APPLICABLE", {"database_version": version, "reason": "Different database engine"}
        rows = list_of_objects(get(item, "settings.databaseFlags", list))
        flags = {}
        for row in rows:
            name, value = get(row, "name", str), get(row, "value", str)
            if name in flags:
                return unknown("duplicate SQL flag")
            flags[name] = value
        if flag not in flags:
            return unknown("explicit SQL flag absent; version-specific default is not inferred", flag=flag)
        value = flags[flag]
        if value not in (values or (good, bad)):
            return unknown("unrecognized SQL flag value", flag=flag, configured=value)
        return result(value != good, flag=flag, configured=value, database_version=version)
    CASES[PREFIX + suffix] = {"pass": {"databaseVersion": engine + "_8", "settings": {"databaseFlags": [{"name": flag, "value": good}]}},
        "fail": {"databaseVersion": engine + "_8", "settings": {"databaseFlags": [{"name": flag, "value": bad}]}}}


sql_flag("sql.mysql_local_infile", "MYSQL", "local_infile", "off", "on", "MySQL explicitly disables local file loading")
sql_flag("sql.mysql_skip_show_database", "MYSQL", "skip_show_database", "on", "off", "MySQL explicitly restricts database listing")
sql_flag("sql.postgres_pgaudit", "POSTGRES", "cloudsql.enable_pgaudit", "on", "off", "PostgreSQL explicitly enables pgAudit")
sql_flag("sql.postgres_log_connections", "POSTGRES", "log_connections", "on", "off", "PostgreSQL logs connections")
sql_flag("sql.postgres_log_disconnections", "POSTGRES", "log_disconnections", "on", "off", "PostgreSQL logs disconnections")
sql_flag("sql.postgres_log_statement", "POSTGRES", "log_statement", "ddl", "none", "PostgreSQL explicitly logs DDL statements",
         values=("none", "ddl", "mod", "all"))
sql_flag("sql.postgres_log_error_verbosity", "POSTGRES", "log_error_verbosity", "default", "terse", "PostgreSQL selects default error logging verbosity",
         values=("terse", "default", "verbose"))


INACTIVE_PRIMARY = ("DESTROYED", "DESTROY_SCHEDULED", "DISABLED")


def rotation_applicability(item):
    """NOT_APPLICABLE reason, or None when automatic rotation must be assessed.

    Cloud KMS: only ENCRYPT_DECRYPT keys support automatic rotation; for other
    purposes rotationPeriod must be omitted. Manually managed EXTERNAL keys do
    not support automatic rotation. A key whose primary version is destroyed,
    scheduled for destruction or disabled can no longer encrypt (aligned with
    gcp.ports.kms_key_rotation)."""
    purpose = get(item, "purpose", str)
    if purpose != "ENCRYPT_DECRYPT":
        if purpose in ("ASYMMETRIC_SIGN", "ASYMMETRIC_DECRYPT", "MAC", "RAW_ENCRYPT_DECRYPT", "KEY_ENCAPSULATION"):
            return "Automatic rotation is supported only for symmetric ENCRYPT_DECRYPT keys"
        raise Unavailable("unrecognized KMS key purpose")
    if "primary" in item:
        primary = get(item, "primary", dict)
        if primary.get("state") in INACTIVE_PRIMARY:
            return "Primary key version is " + primary["state"] + "; the key cannot encrypt new data"
        if primary.get("protectionLevel") == "EXTERNAL":
            return "Manually managed external (EKM) keys do not support automatic rotation"
    elif omitted(item, "primary", None, dict) is None:
        return "Key has no primary version; it cannot encrypt new data"
    return None


def rotation_seconds(item):
    if rotation_applicability(item):
        return None
    # rotationPeriod is omitted when automatic rotation is not configured.
    duration = omitted(item, "rotationPeriod", "0s", str)
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,9})?s", duration):
        raise Unavailable("invalid protobuf rotation duration")
    try:
        return Decimal(duration[:-1])
    except InvalidOperation:
        raise Unavailable("invalid rotation duration") from None


@rule("kms.rotation_enabled", "kms_key", "Symmetric KMS key enables automatic rotation", control="SC-12")
def kms_rotation(item, index):
    seconds = rotation_seconds(item)
    if seconds is None:
        return "NOT_APPLICABLE", {"reason": rotation_applicability(item)}
    return result(seconds <= 0, rotation_seconds=str(seconds),
                  source="rotationPeriod" if "rotationPeriod" in item else "omitted (automatic rotation not configured)")


@rule("kms.rotation_90_days", "kms_key", "Symmetric KMS key schedules rotation within ninety days", control="SC-12")
def kms_rotation_90(item, index):
    seconds = rotation_seconds(item)
    if seconds is None:
        return "NOT_APPLICABLE", {"reason": rotation_applicability(item)}
    if seconds <= 0:
        return result(True, rotation_seconds="0", source="omitted (automatic rotation not configured)"
                      if "rotationPeriod" not in item else "rotationPeriod")
    observed = datetime.fromisoformat(get(item, "_provenance.collected_at", str).replace("Z", "+00:00"))
    next_time = datetime.fromisoformat(get(item, "nextRotationTime", str).replace("Z", "+00:00"))
    if observed.tzinfo is None or next_time.tzinfo is None:
        return unknown("rotation timestamps need explicit time zones")
    delta = Decimal(str((next_time - observed).total_seconds()))
    return result(not (0 < seconds <= 7776000 and 0 <= delta <= 7776000), rotation_seconds=str(seconds),
                  next_rotation_seconds=str(delta), assessed_at=observed.isoformat())


@rule("kms.no_public_iam", "kms_key", "KMS key policy avoids public members", control="AC-3", category="exposure")
def kms_public(item, index):
    policy = get(item, "iamPolicy", dict)
    public = []
    for binding in list_of_objects(get(policy, "bindings", list)):
        members = get(binding, "members", list)
        if any(not isinstance(member, str) for member in members):
            raise Unavailable("malformed KMS IAM members")
        for member in members:
            if member in ("allUsers", "allAuthenticatedUsers"):
                public.append({"member": member, "role": binding.get("role"), "condition": binding.get("condition")})
    return result(bool(public), public_bindings=public, semantics="Declared public member, including conditional bindings; no effective-access claim")


ANONYMOUS_DATASET = re.compile(r"_[0-9a-f]{40}")


def dataset_id(item):
    reference = item.get("datasetReference")
    return reference.get("datasetId") if isinstance(reference, dict) else None


@rule("bigquery.cmek", "bigquery_dataset", "BigQuery dataset declares default customer-managed encryption", control="SC-12")
def bigquery_cmek(item, index):
    if isinstance(dataset_id(item), str) and ANONYMOUS_DATASET.fullmatch(dataset_id(item)):
        return "NOT_APPLICABLE", {"dataset_id": dataset_id(item),
            "reason": "Hidden anonymous dataset holding cached query results, managed by BigQuery"}
    # datasets.get (datasetView=FULL) omits defaultEncryptionConfiguration when
    # the dataset uses Google-managed encryption.
    configuration = omitted(item, "defaultEncryptionConfiguration", {}, dict)
    if not configuration:
        return result(True, default_encryption_configuration={})
    key = get(configuration, "kmsKeyName", str)
    if not key:
        return unknown("empty KMS key name in encryption configuration")
    return result(False, kms_key_name=key, semantics="Dataset default for new tables, not proof that existing tables use CMEK")


@rule("bigquery.no_public_acl", "bigquery_dataset", "BigQuery dataset avoids declared public access principals", control="AC-3", category="exposure")
def bigquery_public(item, index):
    # A full datasets.get representation omits an empty ACL (hidden datasets).
    rows = list_of_objects(omitted(item, "access", [], list))
    public = []
    for row in rows:
        for field in ("specialGroup", "iamMember"):
            if field in row:
                principal = get(row, field, str)
                if principal in ("allUsers", "allAuthenticatedUsers"):
                    public.append({"principal": principal, "role": row.get("role"), "condition": row.get("condition")})
    return result(bool(public), public_access_entries=public, semantics="Declared dataset ACL; conditions, inherited IAM and authorized views need separate review")


# Independent semantic fixtures for custom predicates. No evaluator uses CASES.
CASES.update({
    PREFIX + "network.flow_logs": {"pass": {"logConfig": {"enable": True}, "purpose": "PRIVATE"},
        "fail": {"logConfig": {"enable": False}, "purpose": "PRIVATE"}},
    PREFIX + "storage.versioning": {"pass": {"versioning": {"enabled": True}}, "fail": {"versioning": {"enabled": False}},
        "malformed": {"versioning": {"enabled": {"unexpected": True}}}},
    PREFIX + "bigquery.cmek": {"pass": {"defaultEncryptionConfiguration": {"kmsKeyName": "projects/p/locations/r/keyRings/a/cryptoKeys/k"}},
        "fail": {"defaultEncryptionConfiguration": {}}},
    PREFIX + "bigquery.no_public_acl": {"pass": {"access": []}, "fail": {"access": [{"specialGroup": "allAuthenticatedUsers", "role": "READER"}]}},
    PREFIX + "compute.ip_forwarding": {"pass": {"name": "vm", "canIpForward": False}, "fail": {"name": "vm", "canIpForward": True}},
    PREFIX + "compute.single_interface": {"pass": {"name": "vm", "networkInterfaces": [{"name": "nic0"}]},
        "fail": {"name": "vm", "networkInterfaces": [{"name": "nic0"}, {"name": "nic1"}]}},
    PREFIX + "compute.no_default_service_account": {"pass": {"name": "vm", "serviceAccounts": []},
        "fail": {"name": "vm", "serviceAccounts": [{"email": "123-compute@developer.gserviceaccount.com"}]}},
    PREFIX + "compute.no_default_full_api": {"pass": {"name": "vm", "serviceAccounts": []},
        "fail": {"name": "vm", "serviceAccounts": [{"email": "123-compute@developer.gserviceaccount.com", "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}]}},
    PREFIX + "compute.disk_auto_delete": {"pass": {"disks": [{"autoDelete": False}]}, "fail": {"disks": [{"autoDelete": True}]}},
    PREFIX + "compute.block_project_ssh_keys": {"pass": {"metadata": {"items": [{"key": "block-project-ssh-keys", "value": "true"}]}},
        "fail": {"metadata": {"items": [{"key": "block-project-ssh-keys", "value": "false"}]}}},
    PREFIX + "compute.no_serial_console": {"pass": {"metadata": {"items": [{"key": "serial-port-enable", "value": "false"}]}},
        "fail": {"metadata": {"items": [{"key": "serial-port-enable", "value": "true"}]}}},
    PREFIX + "project.os_login_2fa": {"pass": {"commonInstanceMetadata": {"fingerprint": "f", "items": [{"key": "enable-oslogin", "value": "true"}, {"key": "enable-oslogin-2fa", "value": "true"}]}},
        "fail": {"commonInstanceMetadata": {"fingerprint": "f", "items": [{"key": "enable-oslogin-2fa", "value": "false"}]}},
        "unknown": {"commonInstanceMetadata": {"fingerprint": "f", "items": [{"key": "enable-oslogin-2fa", "value": "true"}, {"key": "enable-oslogin-2fa", "value": "false"}]}}},
    PREFIX + "network.no_default_vpc": {"pass": {"name": "production"}, "fail": {"name": "default"}},
    PREFIX + "storage.soft_delete": {"pass": {"softDeletePolicy": {"retentionDurationSeconds": "604800"}}, "fail": {"softDeletePolicy": {"retentionDurationSeconds": "0"}}},
    PREFIX + "storage.access_logging": {"pass": {"logging": {"logBucket": "logs"}}, "fail": {"logging": {"logBucket": ""}}},
    PREFIX + "storage.lifecycle": {"pass": {"lifecycle": {"rule": [{"action": {"type": "Delete"}, "condition": {"age": 365}}]}},
        "fail": {"lifecycle": {"rule": []}}},
    PREFIX + "sql.high_availability": {"pass": {"instanceType": "CLOUD_SQL_INSTANCE", "settings": {"availabilityType": "REGIONAL"}},
        "fail": {"instanceType": "CLOUD_SQL_INSTANCE", "settings": {"availabilityType": "ZONAL"}}},
    PREFIX + "sql.cmek": {"pass": {"instanceType": "CLOUD_SQL_INSTANCE", "diskEncryptionConfiguration": {"kmsKeyName": "projects/p/locations/r/keyRings/a/cryptoKeys/k"}},
        "fail": {"instanceType": "CLOUD_SQL_INSTANCE", "diskEncryptionConfiguration": {"kmsKeyName": ""}}},
    PREFIX + "kms.rotation_enabled": {"pass": {"purpose": "ENCRYPT_DECRYPT", "rotationPeriod": "7776000s", "primary": {"state": "ENABLED"}},
        "fail": {"purpose": "ENCRYPT_DECRYPT", "rotationPeriod": "0s", "primary": {"state": "ENABLED"}}},
    PREFIX + "kms.rotation_90_days": {"pass": {"purpose": "ENCRYPT_DECRYPT", "rotationPeriod": "7776000s", "primary": {"state": "ENABLED"}, "nextRotationTime": "2026-10-11T00:00:00Z", "_provenance": {"collected_at": "2026-10-10T00:00:00Z"}},
        "fail": {"purpose": "ENCRYPT_DECRYPT", "rotationPeriod": "7776001s", "primary": {"state": "ENABLED"}, "nextRotationTime": "2026-10-11T00:00:00Z", "_provenance": {"collected_at": "2026-10-10T00:00:00Z"}}},
    PREFIX + "kms.no_public_iam": {"pass": {"iamPolicy": {"bindings": []}},
        "fail": {"iamPolicy": {"bindings": [{"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter", "members": ["allUsers"]}]}}},
})

for _cid in IDS:
    CASES[_cid].setdefault("missing", {})
    CASES[_cid].setdefault("malformed", None)
