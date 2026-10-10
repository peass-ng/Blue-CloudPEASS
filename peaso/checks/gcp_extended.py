"""Reviewed GCP metadata predicates, independent of live clients and wall time.

Pinned source associations and scope differences live in reviewed_gcp.json.
Provider defaults are never substituted for absent or unreadable fields.
"""
from datetime import datetime
from decimal import Decimal, InvalidOperation
import re

from . import register, result, unknown
from .facts import Unavailable, field_check, get, list_of_objects
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
scalar("storage.versioning", "bucket", "versioning.enabled", True, False,
       "Bucket enables object versioning")
scalar("network.flow_logs", "subnetwork", "logConfig.enable", True, False,
       "Subnet explicitly enables VPC Flow Logs")
scalar("loadbalancer.backend_logging", "backend_service", "logConfig.enable", True, False,
       "Backend service explicitly enables request logging")


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
    enabled = metadata_flag(item, "commonInstanceMetadata.items", "enable-oslogin-2fa")
    return result(not enabled, enable_oslogin_2fa=enabled, semantics="Project declaration; individual instance overrides and principal eligibility need review")


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


@rule("storage.access_logging", "bucket", "Bucket configures usage and storage log destination", control="AU-2")
def bucket_logging(item, index):
    target = get(item, "logging.logBucket", str)
    return result(not bool(target.strip()), log_bucket=target, semantics="Destination configured; delivery and destination permissions are separate evidence")


@rule("storage.lifecycle", "bucket", "Bucket declares a supported lifecycle rule and condition", control="CM-6")
def lifecycle(item, index):
    rows = list_of_objects(get(item, "lifecycle.rule", list))
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


def rotation_seconds(item):
    purpose = get(item, "purpose", str)
    if purpose != "ENCRYPT_DECRYPT":
        if purpose in ("ASYMMETRIC_SIGN", "ASYMMETRIC_DECRYPT", "MAC", "RAW_ENCRYPT_DECRYPT"):
            return None
        raise Unavailable("unrecognized KMS key purpose")
    duration = get(item, "rotationPeriod", str)
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
        return "NOT_APPLICABLE", {"reason": "Automatic rotation is assessed only for symmetric encryption keys"}
    return result(seconds <= 0, rotation_seconds=str(seconds))


@rule("kms.rotation_90_days", "kms_key", "Symmetric KMS key schedules rotation within ninety days", control="SC-12")
def kms_rotation_90(item, index):
    seconds = rotation_seconds(item)
    if seconds is None:
        return "NOT_APPLICABLE", {"reason": "Not a symmetric encryption key"}
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


@rule("bigquery.cmek", "bigquery_dataset", "BigQuery dataset declares default customer-managed encryption", control="SC-12")
def bigquery_cmek(item, index):
    configuration = get(item, "defaultEncryptionConfiguration", dict)
    if not configuration:
        return result(True, default_encryption_configuration={})
    key = get(configuration, "kmsKeyName", str)
    if not key:
        return unknown("empty KMS key name in encryption configuration")
    return result(False, kms_key_name=key, semantics="Dataset default for new tables, not proof that existing tables use CMEK")


@rule("bigquery.no_public_acl", "bigquery_dataset", "BigQuery dataset avoids declared public access principals", control="AC-3", category="exposure")
def bigquery_public(item, index):
    rows = list_of_objects(get(item, "access", list))
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
    PREFIX + "project.os_login_2fa": {"pass": {"commonInstanceMetadata": {"items": [{"key": "enable-oslogin-2fa", "value": "true"}]}},
        "fail": {"commonInstanceMetadata": {"items": [{"key": "enable-oslogin-2fa", "value": "false"}]}}},
    PREFIX + "network.no_default_vpc": {"pass": {"name": "production"}, "fail": {"name": "default"}},
    PREFIX + "storage.soft_delete": {"pass": {"softDeletePolicy": {"retentionDurationSeconds": "604800"}}, "fail": {"softDeletePolicy": {"retentionDurationSeconds": "0"}}},
    PREFIX + "storage.access_logging": {"pass": {"logging": {"logBucket": "logs"}}, "fail": {"logging": {"logBucket": ""}}},
    PREFIX + "storage.lifecycle": {"pass": {"lifecycle": {"rule": [{"action": {"type": "Delete"}, "condition": {"age": 365}}]}},
        "fail": {"lifecycle": {"rule": []}}},
    PREFIX + "sql.high_availability": {"pass": {"instanceType": "CLOUD_SQL_INSTANCE", "settings": {"availabilityType": "REGIONAL"}},
        "fail": {"instanceType": "CLOUD_SQL_INSTANCE", "settings": {"availabilityType": "ZONAL"}}},
    PREFIX + "sql.cmek": {"pass": {"instanceType": "CLOUD_SQL_INSTANCE", "diskEncryptionConfiguration": {"kmsKeyName": "projects/p/locations/r/keyRings/a/cryptoKeys/k"}},
        "fail": {"instanceType": "CLOUD_SQL_INSTANCE", "diskEncryptionConfiguration": {"kmsKeyName": ""}}},
    PREFIX + "kms.rotation_enabled": {"pass": {"purpose": "ENCRYPT_DECRYPT", "rotationPeriod": "7776000s"},
        "fail": {"purpose": "ENCRYPT_DECRYPT", "rotationPeriod": "0s"}},
    PREFIX + "kms.rotation_90_days": {"pass": {"purpose": "ENCRYPT_DECRYPT", "rotationPeriod": "7776000s", "nextRotationTime": "2026-10-11T00:00:00Z", "_provenance": {"collected_at": "2026-10-10T00:00:00Z"}},
        "fail": {"purpose": "ENCRYPT_DECRYPT", "rotationPeriod": "7776001s", "nextRotationTime": "2026-10-11T00:00:00Z", "_provenance": {"collected_at": "2026-10-10T00:00:00Z"}}},
    PREFIX + "kms.no_public_iam": {"pass": {"iamPolicy": {"bindings": []}},
        "fail": {"iamPolicy": {"bindings": [{"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter", "members": ["allUsers"]}]}}},
})

for _cid in IDS:
    CASES[_cid].setdefault("missing", {})
    CASES[_cid].setdefault("malformed", None)
