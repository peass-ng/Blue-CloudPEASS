"""claude_aws_b storage/data-pipeline services: FSx, API Gateway v2, Glacier, Glue,
Kinesis, Firehose, MediaStore, Storage Gateway and WorkSpaces."""
from __future__ import annotations

from . import result, unknown
from .facts import Unavailable, get, list_of_objects, complete_items, optional
from .claude_aws_b_common import (install, absent_or, empty, policy_document, wildcard_allow_statements,
    turbot_public_statements, is_policy_public, account, protected_resources, kms_manager, strings,
    subnet_vpc, subnet_route_table, igw_default_route, CONTEXT, SCOPE, clock)
from peaso.aws_service_lifecycle import retirement_state, RETIRED_SERVICES

FSX_DOC = "https://docs.aws.amazon.com/fsx/latest/APIReference/API_FileSystem.html"
GLUE_SEC = "https://docs.aws.amazon.com/glue/latest/webapi/API_SecurityConfiguration.html"
KINESIS_DOC = "https://docs.aws.amazon.com/kinesis/latest/APIReference/API_StreamDescriptionSummary.html"


# --------------------------------------------------------------------------- FSx
def _fsx_type(item, wanted):
    kind = get(item, "FileSystemType", str)
    if kind not in ("WINDOWS", "LUSTRE", "ONTAP", "OPENZFS"):
        raise Unavailable("unrecognized FSx file system type")
    return kind if kind in wanted else None


_FSX_CONFIG = {"WINDOWS": "WindowsConfiguration", "LUSTRE": "LustreConfiguration", "OPENZFS": "OpenZFSConfiguration", "ONTAP": "OntapConfiguration"}


@install("aws.cb.fsx.copy_tags_to_backups", "fsx_file_system", "FSx file system copies tags to backups",
    {"FileSystemType": "LUSTRE", "LustreConfiguration": {"CopyTagsToBackups": True}},
    {"FileSystemType": "WINDOWS", "WindowsConfiguration": {"CopyTagsToBackups": False}},
    rows=["prowler.aws.fsx_file_system_copy_tags_to_backups_enabled"], severity="low",
    remediation="Enable CopyTagsToBackups on the FSx file system (UpdateFileSystem) so backups inherit ownership and classification tags.",
    docs=[FSX_DOC], extra={"not_applicable": {"FileSystemType": "ONTAP"}},
    note="Prowler reads CopyTagsToBackups for LUSTRE, WINDOWS and OPENZFS; ONTAP has no such member and is not applicable.")
def fsx_copy_backups(item, index):
    kind = _fsx_type(item, ("WINDOWS", "LUSTRE", "OPENZFS"))
    if kind is None:
        return "NOT_APPLICABLE", {"file_system_type": get(item, "FileSystemType", str)}
    value = get(item, _FSX_CONFIG[kind] + ".CopyTagsToBackups", bool)
    return result(not value, file_system_type=kind, copy_tags_to_backups=value)


@install("aws.cb.fsx.copy_tags_to_volumes", "fsx_file_system", "FSx for OpenZFS file system copies tags to volumes",
    {"FileSystemType": "OPENZFS", "OpenZFSConfiguration": {"CopyTagsToVolumes": True}},
    {"FileSystemType": "OPENZFS", "OpenZFSConfiguration": {"CopyTagsToVolumes": False}},
    rows=["prowler.aws.fsx_file_system_copy_tags_to_volumes_enabled"], severity="low",
    remediation="Enable CopyTagsToVolumes on the FSx for OpenZFS file system.",
    docs=["https://docs.aws.amazon.com/fsx/latest/APIReference/API_OpenZFSFileSystemConfiguration.html"], extra={"not_applicable": {"FileSystemType": "LUSTRE"}})
def fsx_copy_volumes(item, index):
    if _fsx_type(item, ("OPENZFS",)) is None:
        return "NOT_APPLICABLE", {"file_system_type": get(item, "FileSystemType", str)}
    value = get(item, "OpenZFSConfiguration.CopyTagsToVolumes", bool)
    return result(not value, copy_tags_to_volumes=value)


@install("aws.cb.fsx.openzfs_copy_tags_backups_and_volumes", "fsx_file_system", "FSx for OpenZFS copies tags to both backups and volumes",
    {"FileSystemType": "OPENZFS", "OpenZFSConfiguration": {"CopyTagsToBackups": True, "CopyTagsToVolumes": True}},
    {"FileSystemType": "OPENZFS", "OpenZFSConfiguration": {"CopyTagsToBackups": True, "CopyTagsToVolumes": False}},
    rows=["aws-compliance.control.fsx_file_system_copy_tags_to_backup_and_volume_enabled"], severity="low",
    remediation="Enable both CopyTagsToBackups and CopyTagsToVolumes on the FSx for OpenZFS file system.",
    docs=["https://docs.aws.amazon.com/fsx/latest/APIReference/API_OpenZFSFileSystemConfiguration.html"], extra={"not_applicable": {"FileSystemType": "LUSTRE"}})
def fsx_openzfs_both(item, index):
    if _fsx_type(item, ("OPENZFS",)) is None:
        return "NOT_APPLICABLE", {"file_system_type": get(item, "FileSystemType", str)}
    backups = get(item, "OpenZFSConfiguration.CopyTagsToBackups", bool)
    volumes = get(item, "OpenZFSConfiguration.CopyTagsToVolumes", bool)
    return result(not (backups and volumes), copy_tags_to_backups=backups, copy_tags_to_volumes=volumes)


@install("aws.cb.fsx.lustre_copy_tags_to_backups", "fsx_file_system", "FSx for Lustre copies tags to backups",
    {"FileSystemType": "LUSTRE", "LustreConfiguration": {"CopyTagsToBackups": True}},
    {"FileSystemType": "LUSTRE", "LustreConfiguration": {"CopyTagsToBackups": False}},
    rows=["aws-compliance.control.fsx_lustre_file_system_copy_tags_to_backup_enabled"], severity="low",
    remediation="Enable CopyTagsToBackups on the FSx for Lustre file system.",
    docs=["https://docs.aws.amazon.com/fsx/latest/APIReference/API_LustreFileSystemConfiguration.html"], extra={"not_applicable": {"FileSystemType": "WINDOWS"}})
def fsx_lustre_tags(item, index):
    if _fsx_type(item, ("LUSTRE",)) is None:
        return "NOT_APPLICABLE", {"file_system_type": get(item, "FileSystemType", str)}
    value = get(item, "LustreConfiguration.CopyTagsToBackups", bool)
    return result(not value, copy_tags_to_backups=value)


for _cid, _type, _allowed, _row in [
    ("aws.cb.fsx.ontap_multi_az", "ONTAP", ("MULTI_AZ_1", "MULTI_AZ_2"), "aws-compliance.control.fsx_netapp_ontap_file_system_multi_az_deployment_enabled"),
    ("aws.cb.fsx.openzfs_multi_az", "OPENZFS", ("MULTI_AZ_1",), "aws-compliance.control.fsx_openzfs_file_system_multi_az_deployment_enabled"),
    ("aws.cb.fsx.windows_multi_az_deployment", "WINDOWS", ("MULTI_AZ_1",), "aws-compliance.control.fsx_windows_file_system_multi_az_deployment_enabled"),
]:
    def _multi(cid, fstype, allowed, row):
        config = _FSX_CONFIG[fstype]
        other = "LUSTRE"
        @install(cid, "fsx_file_system", "FSx " + fstype + " file system uses a Multi-AZ deployment type",
            {"FileSystemType": fstype, config: {"DeploymentType": allowed[0]}},
            {"FileSystemType": fstype, config: {"DeploymentType": "SINGLE_AZ_1"}},
            rows=[row], severity="medium", remediation="Create the FSx " + fstype + " file system with a Multi-AZ deployment type (" + ", ".join(allowed) + ") and migrate data; the deployment type cannot be changed in place.",
            docs=[FSX_DOC], extra={"not_applicable": {"FileSystemType": other}})
        def evaluate(item, index):
            if _fsx_type(item, (fstype,)) is None:
                return "NOT_APPLICABLE", {"file_system_type": get(item, "FileSystemType", str)}
            mode = get(item, config + ".DeploymentType", str)
            return result(mode not in allowed, deployment_type=mode, accepted=list(allowed))
    _multi(_cid, _type, _allowed, _row)


@install("aws.cb.fsx.windows_multiple_subnets", "fsx_file_system", "FSx for Windows file system spans more than one subnet",
    {"FileSystemType": "WINDOWS", "SubnetIds": ["subnet-a", "subnet-b"]},
    {"FileSystemType": "WINDOWS", "SubnetIds": ["subnet-a"]},
    rows=["prowler.aws.fsx_windows_file_system_multi_az_enabled"], severity="low",
    remediation="Deploy FSx for Windows File Server as MULTI_AZ_1 with a preferred and a standby subnet.",
    docs=[FSX_DOC], extra={"not_applicable": {"FileSystemType": "LUSTRE"}},
    note="Prowler evaluates len(SubnetIds) > 1, which is distinct from the DeploymentType enum predicate.")
def fsx_windows_subnets(item, index):
    if _fsx_type(item, ("WINDOWS",)) is None:
        return "NOT_APPLICABLE", {"file_system_type": get(item, "FileSystemType", str)}
    subnets = strings(get(item, "SubnetIds", list), "SubnetIds")
    return result(len(subnets) <= 1, subnet_count=len(subnets))


def _backup_index(arn, rtype):
    return {"collections": {"backup_protected_resource": [{"status": "collected"}]}, "backup_protected_resource": [{"data": {"ResourceArn": arn, "ResourceType": rtype}}]}


_FSX_ARN = "arn:aws:fsx:us-east-1:111111111111:file-system/fs-1"


@install("aws.cb.fsx.protected_by_backup_plan", "fsx_file_system", "FSx file system is a protected resource in AWS Backup",
    {"ResourceARN": _FSX_ARN}, {"ResourceARN": _FSX_ARN}, rows=["aws-compliance.control.fsx_file_system_protected_by_backup_plan"],
    severity="medium", remediation="Assign the FSx file system to an AWS Backup plan resource selection so recovery points are created.",
    docs=["https://docs.aws.amazon.com/aws-backup/latest/devguide/API_ProtectedResource.html"], dependencies=["fsx_file_system", "backup_protected_resource"],
    extra={"pass_index": _backup_index(_FSX_ARN, "FSx"), "fail_index": {"collections": {"backup_protected_resource": [{"status": "empty"}]}, "backup_protected_resource": []}})
def fsx_backup(item, index):
    arn = get(item, "ResourceARN", str)
    rows = protected_resources(index)
    hit = any(get(r, "ResourceArn", str) == arn and get(r, "ResourceType", str) == "FSx" for r in rows)
    return result(not hit, resource_arn=arn, protected=hit)


# --------------------------------------------------------------------------- API Gateway v2
@install("aws.cb.apigatewayv2.stage_access_logging", "http_api_stage", "API Gateway v2 stage has access logging configured",
    {"StageName": "prod", "AccessLogSettings": {"DestinationArn": "arn:aws:logs:us-east-1:111111111111:log-group:api", "Format": "$context.requestId"}},
    {"StageName": "prod"}, rows=["aws-compliance.control.gatewayv2_stage_access_logging_enabled"], severity="medium",
    remediation="Configure AccessLogSettings (destination log group and format) on every API Gateway v2 stage.",
    docs=["https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-stages-stagename.html"],
    note="GetStages omits AccessLogSettings when access logging is not configured; StageName proves the stage object was read.")
def v2_access_logs(item, index):
    settings = absent_or(item, "StageName", "AccessLogSettings")
    return result(empty(settings), stage=get(item, "StageName", str), access_log_settings=settings is not None)


# --------------------------------------------------------------------------- Glacier
_VAULT = "arn:aws:glacier:us-east-1:111111111111:vaults/v"
_PUBLIC = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "glacier:*", "Resource": "*"}]}
_PRIVATE = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111111111111:root"}, "Action": "glacier:*", "Resource": "*"}]}
_ABSENT = {"collection_status": "empty", "absent": True}


def vault_policy(item):
    container = get(item, "Policy", dict)
    if container.get("collection_status") == "empty" and container.get("absent") is True:
        return None
    return policy_document(get(container, "policy.Policy"))


def _vault(policy):
    import json
    return {"VaultARN": _VAULT, "Policy": _ABSENT if policy is None else {"policy": {"Policy": json.dumps(policy)}}}


@install("aws.cb.glacier.vault_policy_no_public_principal", "glacier_vault", "Glacier vault policy has no Allow statement for the wildcard principal",
    _vault(_PRIVATE), _vault(_PUBLIC), rows=["aws-compliance.control.glacier_vault_restrict_public_access"], severity="high", category="exposure",
    remediation="Remove Allow statements with Principal \"*\" (or AWS \"*\") from the Glacier vault access policy.",
    docs=["https://docs.aws.amazon.com/amazonglacier/latest/dev/api-GetVaultAccessPolicy.html"], extra={"absent": _vault(None)},
    note="aws-compliance ignores conditions; a vault without an access policy is ok.")
def glacier_compliance(item, index):
    statements = vault_policy(item)
    if statements is None:
        return result(False, policy=None)
    hits = wildcard_allow_statements(statements)
    return result(bool(hits), public_statements=len(hits))


@install("aws.cb.glacier.vault_policy_prohibit_public_access", "glacier_vault", "Glacier vault policy does not grant unconditioned public access",
    _vault(_PRIVATE), _vault(_PUBLIC), rows=["aws-perimeter.control.glacier_vault_policy_prohibit_public_access"], severity="high", category="exposure",
    remediation="Restrict the Glacier vault policy with account, organization or source ARN conditions, or remove wildcard principals.",
    docs=["https://docs.aws.amazon.com/amazonglacier/latest/dev/access-control-resource-based.html"], extra={"not_applicable": _vault(None)},
    note="aws-perimeter resource_policy_public_sql; a vault with no policy is info (NOT_APPLICABLE).")
def glacier_perimeter(item, index):
    statements = vault_policy(item)
    if statements is None:
        return "NOT_APPLICABLE", {"policy": None}
    hits = turbot_public_statements(statements)
    return result(bool(hits), public_statements=len(hits))


def prowler_star_principal(statement):
    principal = statement.get("Principal")
    if principal is None:
        return False
    if isinstance(principal, (str, list, dict)) and "*" in principal:
        return True
    if isinstance(principal, dict):
        for key in ("AWS", "CanonicalUser"):
            value = principal.get(key)
            if isinstance(value, (str, list)) and "*" in value:
                return True
    return False


@install("aws.cb.glacier.vault_policy_star_principal", "glacier_vault", "Glacier vault has no policy or no Allow statement for everyone",
    _vault(_PRIVATE), _vault(_PUBLIC), rows=["prowler.aws.glacier_vaults_policy_public_access"], severity="critical", category="exposure",
    remediation="Remove Allow statements whose Principal, Principal.AWS or Principal.CanonicalUser contains \"*\" from the vault access policy.",
    docs=["https://docs.aws.amazon.com/amazonglacier/latest/dev/api-GetVaultAccessPolicy.html"], extra={"absent": _vault(None)},
    note="Prowler substring semantics on Principal, AWS and CanonicalUser; conditions are not considered.")
def glacier_prowler(item, index):
    statements = vault_policy(item)
    if statements is None:
        return result(False, policy=None)
    hits = [s for s in statements if s.get("Effect") == "Allow" and prowler_star_principal(s)]
    return result(bool(hits), public_statements=len(hits))


# --------------------------------------------------------------------------- Glue
@install("aws.cb.glue.connection_jdbc_enforce_ssl", "glue_connection", "Glue JDBC connection enforces SSL",
    {"Name": "c", "ConnectionType": "JDBC", "ConnectionProperties": {"JDBC_ENFORCE_SSL": "true"}},
    {"Name": "c", "ConnectionType": "JDBC", "ConnectionProperties": {"JDBC_ENFORCE_SSL": "false"}},
    rows=["aws-compliance.control.glue_connection_ssl_enabled", "prowler.aws.glue_database_connections_ssl_enabled"], severity="high",
    remediation="Set the JDBC_ENFORCE_SSL connection property to true on the Glue connection.",
    docs=["https://docs.aws.amazon.com/glue/latest/dg/connection-properties.html"], extra={"not_applicable": {"Name": "n", "ConnectionType": "NETWORK", "ConnectionProperties": {}}},
    note="Both sources require JDBC_ENFORCE_SSL == 'true'. Non-JDBC connection types have no JDBC SSL property and are not applicable.")
def glue_ssl(item, index):
    ctype = get(item, "ConnectionType", str)
    if ctype != "JDBC":
        return "NOT_APPLICABLE", {"connection_type": ctype}
    value = absent_or(item, "Name", "ConnectionProperties.JDBC_ENFORCE_SSL")
    return result(value != "true", jdbc_enforce_ssl=value)


_CATALOG = {"EncryptionSettings": {"DataCatalogEncryptionSettings": {"EncryptionAtRest": {"CatalogEncryptionMode": "SSE-KMS"}, "ConnectionPasswordEncryption": {"ReturnConnectionPasswordEncrypted": True}}}}
_CATALOG_OFF = {"EncryptionSettings": {"DataCatalogEncryptionSettings": {"EncryptionAtRest": {"CatalogEncryptionMode": "DISABLED"}, "ConnectionPasswordEncryption": {"ReturnConnectionPasswordEncrypted": False}}}}
_GLUE_SET = "https://docs.aws.amazon.com/glue/latest/webapi/API_DataCatalogEncryptionSettings.html"


@install("aws.cb.glue.catalog_metadata_encryption", "glue_data_catalog", "Glue Data Catalog metadata encryption is not disabled",
    _CATALOG, _CATALOG_OFF, rows=["aws-compliance.control.glue_data_catalog_encryption_settings_metadata_encryption_enabled"], severity="medium",
    remediation="Enable Data Catalog encryption at rest (CatalogEncryptionMode SSE-KMS or SSE-KMS-WITH-SERVICE-ROLE) with PutDataCatalogEncryptionSettings.",
    docs=[_GLUE_SET])
def glue_meta(item, index):
    mode = get(item, "EncryptionSettings.DataCatalogEncryptionSettings.EncryptionAtRest.CatalogEncryptionMode", str)
    return result(mode == "DISABLED", catalog_encryption_mode=mode)


@install("aws.cb.glue.catalog_password_encryption", "glue_data_catalog", "Glue Data Catalog returns connection passwords encrypted",
    _CATALOG, _CATALOG_OFF, rows=["aws-compliance.control.glue_data_catalog_encryption_settings_password_encryption_enabled"], severity="high",
    remediation="Enable ConnectionPasswordEncryption (ReturnConnectionPasswordEncrypted) with a KMS key in the Data Catalog settings.",
    docs=[_GLUE_SET])
def glue_password(item, index):
    value = get(item, "EncryptionSettings.DataCatalogEncryptionSettings.ConnectionPasswordEncryption.ReturnConnectionPasswordEncrypted", bool)
    return result(not value, return_connection_password_encrypted=value)


def _tables_index(count):
    return {"collections": {"glue_table": [{"status": "collected" if count else "empty"}]}, "glue_table": [{"data": {"Name": "t%d" % i}} for i in range(count)]}


def _has_tables(index):
    return bool(complete_items(index, "glue_table"))


@install("aws.cb.glue.catalog_password_encryption_with_tables", "glue_data_catalog", "Glue Data Catalog with tables encrypts connection passwords",
    _CATALOG, _CATALOG_OFF, rows=["prowler.aws.glue_data_catalogs_connection_passwords_encryption_enabled"], severity="high",
    remediation="Enable ConnectionPasswordEncryption with a KMS key in the Glue Data Catalog settings.",
    docs=[_GLUE_SET, "https://docs.aws.amazon.com/glue/latest/webapi/API_SearchTables.html"], dependencies=["glue_data_catalog", "glue_table"],
    extra={"index": _tables_index(1), "not_applicable_index": _tables_index(0)},
    note="Prowler only reports regions that contain Glue tables (scan_unused_services off).")
def glue_password_tables(item, index):
    value = get(item, "EncryptionSettings.DataCatalogEncryptionSettings.ConnectionPasswordEncryption.ReturnConnectionPasswordEncrypted", bool)
    if not _has_tables(index):
        return "NOT_APPLICABLE", {"reason": "no Glue tables in region"}
    return result(not value, return_connection_password_encrypted=value)


@install("aws.cb.glue.catalog_metadata_sse_kms_with_tables", "glue_data_catalog", "Glue Data Catalog with tables uses SSE-KMS metadata encryption",
    _CATALOG, _CATALOG_OFF, rows=["prowler.aws.glue_data_catalogs_metadata_encryption_enabled"], severity="medium",
    remediation="Set CatalogEncryptionMode to SSE-KMS for the Glue Data Catalog.",
    docs=[_GLUE_SET], dependencies=["glue_data_catalog", "glue_table"], extra={"index": _tables_index(1)},
    note="Prowler requires mode exactly SSE-KMS and only reports regions with tables; distinct from the != DISABLED predicate.")
def glue_meta_tables(item, index):
    mode = get(item, "EncryptionSettings.DataCatalogEncryptionSettings.EncryptionAtRest.CatalogEncryptionMode", str)
    if not _has_tables(index):
        return "NOT_APPLICABLE", {"reason": "no Glue tables in region"}
    return result(mode != "SSE-KMS", catalog_encryption_mode=mode)


def _glue_policy(policy):
    import json
    return {"ResourcePolicy": _ABSENT if policy is None else {"PolicyInJson": json.dumps(policy)}}


@install("aws.cb.glue.catalog_policy_not_public", "glue_data_catalog", "Glue Data Catalog resource policy does not allow public access",
    _glue_policy(_PRIVATE), _glue_policy(_PUBLIC), rows=["prowler.aws.glue_data_catalogs_not_publicly_accessible"], severity="high", category="exposure",
    remediation="Remove wildcard principals from the Glue Data Catalog resource policy or restrict them with account/organization conditions.",
    docs=["https://docs.aws.amazon.com/glue/latest/webapi/API_GetResourcePolicy.html"], extra={"index": {"context": {"Account": "111111111111"}}, "not_applicable": _glue_policy(None)},
    note="Prowler is_policy_public(policy, audited_account); catalogs without a policy are skipped (NOT_APPLICABLE).")
def glue_catalog_policy(item, index):
    container = get(item, "ResourcePolicy", dict)
    if container.get("collection_status") == "empty" and container.get("absent") is True:
        return "NOT_APPLICABLE", {"policy": None}
    statements = policy_document(get(container, "PolicyInJson", str))
    public = is_policy_public(statements, account(index))
    return result(public, public=public)


_SECCONF = {"Name": "sec", "EncryptionConfiguration": {"S3Encryption": [{"S3EncryptionMode": "SSE-KMS"}], "CloudWatchEncryption": {"CloudWatchEncryptionMode": "SSE-KMS"}, "JobBookmarksEncryption": {"JobBookmarksEncryptionMode": "CSE-KMS"}}}
_SECCONF_OFF = {"Name": "sec", "EncryptionConfiguration": {"S3Encryption": [{"S3EncryptionMode": "DISABLED"}], "CloudWatchEncryption": {"CloudWatchEncryptionMode": "DISABLED"}, "JobBookmarksEncryption": {"JobBookmarksEncryptionMode": "DISABLED"}}}


def _sec_index(conf):
    return {"collections": {"glue_security_configuration": [{"status": "collected"}]}, "glue_security_configuration": [{"data": conf}]}


def _security_configuration(item, index, sentinel):
    name = absent_or(item, sentinel, "SecurityConfiguration")
    configs = complete_items(index, "glue_security_configuration")
    if name is None:
        return None, None
    matches = [c for c in configs if get(c, "Name", str) == name]
    if len(matches) > 1:
        raise Unavailable("ambiguous Glue security configuration")
    return name, (matches[0] if matches else None)


_MODES = {"cloudwatch": ("CloudWatchEncryption", "CloudWatchEncryptionMode"), "bookmarks": ("JobBookmarksEncryption", "JobBookmarksEncryptionMode")}
_SENTINEL = {"glue_dev_endpoint": "EndpointName", "glue_job": "Role"}

for _kind, _label in (("glue_dev_endpoint", "dev_endpoint"), ("glue_job", "job")):
    for _mode, (_block, _field) in _MODES.items():
        def _glue_mode(kind, label, mode, block, field):
            sentinel = _SENTINEL[kind]
            if kind == "glue_dev_endpoint":
                rows = {"cloudwatch": ["aws-compliance.control.glue_dev_endpoint_cloudwatch_logs_encryption_enabled", "prowler.aws.glue_development_endpoints_cloudwatch_logs_encryption_enabled"],
                        "bookmarks": ["aws-compliance.control.glue_dev_endpoint_job_bookmarks_encryption_enabled", "prowler.aws.glue_development_endpoints_job_bookmark_encryption_enabled"]}[mode]
            else:
                rows = {"cloudwatch": ["aws-compliance.control.glue_job_cloudwatch_logs_encryption_enabled", "prowler.aws.glue_etl_jobs_cloudwatch_logs_encryption_enabled"],
                        "bookmarks": ["aws-compliance.control.glue_job_bookmarks_encryption_enabled", "prowler.aws.glue_etl_jobs_job_bookmark_encryption_enabled"]}[mode]
            base = {sentinel: "x", "SecurityConfiguration": "sec"}
            @install("aws.cb.glue." + label + "_" + mode + "_encryption", kind, "Glue " + label.replace("_", " ") + " security configuration encrypts " + ("CloudWatch logs" if mode == "cloudwatch" else "job bookmarks"),
                base, {sentinel: "x"}, rows=rows, severity="medium",
                remediation="Attach a Glue security configuration whose " + field + " is not DISABLED to the " + label.replace("_", " ") + ".",
                docs=[GLUE_SEC], dependencies=[kind, "glue_security_configuration"],
                extra={"index": _sec_index(_SECCONF), "fail_index": _sec_index(_SECCONF)},
                note="Both sources fail when no security configuration is attached or the referenced one does not exist, and pass when the mode is not DISABLED.")
            def evaluate(item, index):
                name, conf = _security_configuration(item, index, sentinel)
                if conf is None:
                    return result(True, security_configuration=name, reason="no attached or resolvable security configuration")
                value = get(conf, "EncryptionConfiguration." + block + "." + field, str)
                return result(value == "DISABLED", security_configuration=name, mode=value)
        _glue_mode(_kind, _label, _mode, _block, _field)

    def _glue_s3(kind, label):
        sentinel = _SENTINEL[kind]
        row = "aws-compliance.control.glue_dev_endpoint_s3_encryption_enabled" if kind == "glue_dev_endpoint" else "aws-compliance.control.glue_job_s3_encryption_enabled"
        @install("aws.cb.glue." + label + "_s3_encryption_all_modes", kind, "Every S3 encryption entry of the attached Glue security configuration is enabled",
            {sentinel: "x", "SecurityConfiguration": "sec"}, {sentinel: "x", "SecurityConfiguration": "sec"}, rows=[row], severity="medium",
            remediation="Set every S3Encryption entry of the attached Glue security configuration to SSE-KMS or SSE-S3.",
            docs=[GLUE_SEC], dependencies=[kind, "glue_security_configuration"],
            extra={"index": _sec_index(_SECCONF), "fail_index": _sec_index(_SECCONF_OFF), "not_applicable": {sentinel: "x"}},
            note="The SQL lateral-joins jsonb_array_elements(s3_encryption): resources without a resolvable configuration emit no row (NOT_APPLICABLE here); each S3Encryption element must not be DISABLED.")
        def evaluate(item, index):
            name, conf = _security_configuration(item, index, sentinel)
            if conf is None:
                return "NOT_APPLICABLE", {"security_configuration": name, "reason": "source query emits no row without a joined configuration"}
            entries = list_of_objects(get(conf, "EncryptionConfiguration.S3Encryption", list))
            if not entries:
                return "NOT_APPLICABLE", {"security_configuration": name, "reason": "no S3Encryption entries"}
            modes = [get(e, "S3EncryptionMode", str) for e in entries]
            return result(any(m == "DISABLED" for m in modes), security_configuration=name, modes=modes)

        @install("aws.cb.glue." + label + "_s3_encryption_first_mode", kind, "Glue " + label.replace("_", " ") + " has S3 encryption enabled",
            {sentinel: "x", "SecurityConfiguration": "sec"}, {sentinel: "x"}, rows=["prowler.aws.glue_development_endpoints_s3_encryption_enabled"] if kind == "glue_dev_endpoint" else ["prowler.aws.glue_etl_jobs_amazon_s3_encryption_enabled"],
            severity="medium" if kind == "glue_dev_endpoint" else "high",
            remediation="Attach a Glue security configuration with S3 encryption (SSE-KMS or SSE-S3) to the " + label.replace("_", " ") + ".",
            docs=[GLUE_SEC], dependencies=[kind, "glue_security_configuration"],
            extra={"index": _sec_index(_SECCONF)} if kind == "glue_dev_endpoint" else {"index": _sec_index(_SECCONF), "fail": {sentinel: "x", "DefaultArgumentFlags": {}}},
            note="Prowler reads S3Encryption[0].S3EncryptionMode; without a configuration, dev endpoints fail and jobs pass only with --encryption-type sse-s3 (needs the allowlisted DefaultArgumentFlags fact).")
        def evaluate_first(item, index):
            name, conf = _security_configuration(item, index, sentinel)
            if conf is None:
                if kind == "glue_dev_endpoint":
                    return result(True, security_configuration=name)
                flags = get(item, "DefaultArgumentFlags", dict)
                encryption = flags.get("--encryption-type")
                return result(encryption != "sse-s3", security_configuration=name, encryption_type_argument=encryption)
            entries = list_of_objects(get(conf, "EncryptionConfiguration.S3Encryption", list))
            if not entries:
                raise Unavailable("security configuration without S3Encryption entries")
            mode = get(entries[0], "S3EncryptionMode", str)
            return result(mode == "DISABLED", security_configuration=name, mode=mode)
    _glue_s3(_kind, _label)


@install("aws.cb.glue.job_continuous_cloudwatch_logging", "glue_job", "Glue ETL job enables continuous CloudWatch logging",
    {"Role": "r", "DefaultArgumentFlags": {"--enable-continuous-cloudwatch-log": "true"}}, {"Role": "r", "DefaultArgumentFlags": {}},
    rows=["prowler.aws.glue_etl_jobs_logging_enabled"], severity="medium",
    remediation="Set the --enable-continuous-cloudwatch-log job argument to true.",
    docs=["https://docs.aws.amazon.com/glue/latest/dg/aws-glue-programming-etl-glue-arguments.html"],
    note="Requires an allowlisted DefaultArgumentFlags fact (non-secret boolean/enum job flags); the collector strips DefaultArguments.")
def glue_job_logging(item, index):
    get(item, "Role", str)
    flags = get(item, "DefaultArgumentFlags", dict)
    value = flags.get("--enable-continuous-cloudwatch-log", "false")
    return result(value != "true", continuous_cloudwatch_log=value)


@install("aws.cb.glue.spark_job_version_3", "glue_job", "Glue Spark job (Spark UI enabled) runs Glue version 3.0 or later",
    {"Role": "r", "GlueVersion": "4.0", "DefaultArgumentFlags": {"--enable-spark-ui": "true"}},
    {"Role": "r", "GlueVersion": "2.0", "DefaultArgumentFlags": {"--enable-spark-ui": "true"}},
    rows=["aws-compliance.control.glue_spark_job_runs_on_version_3_or_higher"], severity="medium",
    remediation="Upgrade the Glue job to Glue version 3.0 or later.",
    docs=["https://docs.aws.amazon.com/glue/latest/dg/release-notes.html"], extra={"not_applicable": {"Role": "r", "GlueVersion": "2.0", "DefaultArgumentFlags": {}}},
    note="Pinned variable glue_spark_job_supported_version default 3.0; jobs without --enable-spark-ui true are skipped by the source.")
def glue_spark(item, index):
    get(item, "Role", str)
    flags = get(item, "DefaultArgumentFlags", dict)
    if flags.get("--enable-spark-ui") != "true":
        return "NOT_APPLICABLE", {"reason": "source skips jobs without --enable-spark-ui true"}
    version = get(item, "GlueVersion", str)
    try:
        number = float(version)
    except ValueError as exc:
        raise Unavailable("unparseable GlueVersion") from exc
    return result(number < 3.0, glue_version=version, minimum=3.0)


@install("aws.cb.glue.ml_transform_user_data_encryption", "glue_ml_transform", "Glue ML transform user data encryption is not disabled",
    {"TransformId": "t", "TransformEncryption": {"MlUserDataEncryption": {"MlUserDataEncryptionMode": "SSE-KMS"}}}, {"TransformId": "t"},
    rows=["prowler.aws.glue_ml_transform_encrypted_at_rest"], severity="medium",
    remediation="Configure TransformEncryption.MlUserDataEncryption with SSE-KMS on the ML transform.",
    docs=["https://docs.aws.amazon.com/glue/latest/webapi/API_TransformEncryption.html"],
    note="Prowler defaults an omitted MlUserDataEncryptionMode to DISABLED.")
def glue_ml(item, index):
    mode = absent_or(item, "TransformId", "TransformEncryption.MlUserDataEncryption.MlUserDataEncryptionMode", "DISABLED")
    return result(mode == "DISABLED", mode=mode)


@install("aws.cb.glue.ml_transform_encryption_configured", "glue_ml_transform", "Glue ML transform has a TransformEncryption configuration",
    {"TransformId": "t", "TransformEncryption": {"MlUserDataEncryption": {"MlUserDataEncryptionMode": "SSE-KMS"}}}, {"TransformId": "t"},
    rows=["aws-compliance.control.glue_ml_transform_encryption_at_rest_enabled"], severity="medium",
    remediation="Configure TransformEncryption on the Glue ML transform.",
    docs=["https://docs.aws.amazon.com/glue/latest/webapi/API_TransformEncryption.html"],
    note="Source only tests transform_encryption IS NOT NULL; distinct from the mode predicate.")
def glue_ml_presence(item, index):
    value = absent_or(item, "TransformId", "TransformEncryption")
    return result(value is None, transform_encryption=value is not None)


# --------------------------------------------------------------------------- Kinesis / Firehose
def _stream(**kw):
    return {"StreamARN": "arn:aws:kinesis:us-east-1:111111111111:stream/s", **kw}


@install("aws.cb.firehose.server_side_encryption", "firehose_delivery_stream", "Firehose delivery stream server-side encryption is enabled",
    {"DeliveryStreamARN": "a", "DeliveryStreamEncryptionConfiguration": {"Status": "ENABLED"}}, {"DeliveryStreamARN": "a", "DeliveryStreamEncryptionConfiguration": {"Status": "DISABLED"}},
    rows=["aws-compliance.control.kinesis_firehose_delivery_stream_server_side_encryption_enabled"], severity="medium",
    remediation="Enable server-side encryption on the Firehose delivery stream (StartDeliveryStreamEncryption).",
    docs=["https://docs.aws.amazon.com/firehose/latest/APIReference/API_DeliveryStreamEncryptionConfiguration.html"])
def firehose_sse(item, index):
    status = absent_or(item, "DeliveryStreamARN", "DeliveryStreamEncryptionConfiguration.Status")
    return result(status != "ENABLED", status=status)


@install("aws.cb.kinesis.retention_at_least_168h", "kinesis_stream", "Kinesis stream retains data for at least 168 hours",
    _stream(RetentionPeriodHours=168), _stream(RetentionPeriodHours=24), rows=["prowler.aws.kinesis_stream_data_retention_period"], severity="medium",
    remediation="Increase the stream retention period (IncreaseStreamRetentionPeriod) to at least 168 hours.",
    docs=[KINESIS_DOC], note="Prowler min_kinesis_stream_retention_hours default 168 with >=.")
def kinesis_min(item, index):
    hours = get(item, "RetentionPeriodHours", int)
    return result(hours < 168, retention_hours=hours)


@install("aws.cb.kinesis.retention_exactly_168h", "kinesis_stream", "Kinesis stream retention period equals 168 hours",
    _stream(RetentionPeriodHours=168), _stream(RetentionPeriodHours=8760), rows=["aws-compliance.control.kinesis_stream_retention_period_168_hours"], severity="low",
    remediation="Set the stream retention period to 168 hours as required by the source policy.",
    docs=[KINESIS_DOC], note="Source uses equality (= 168); longer retention alarms. Kept separate from the >= threshold.")
def kinesis_eq(item, index):
    hours = get(item, "RetentionPeriodHours", int)
    return result(hours != 168, retention_hours=hours)


@install("aws.cb.kinesis.kms_encryption", "kinesis_stream", "Kinesis stream uses KMS server-side encryption",
    _stream(EncryptionType="KMS"), _stream(EncryptionType="NONE"),
    rows=["prowler.aws.kinesis_stream_encrypted_at_rest", "aws-compliance.control.kinesis_stream_server_side_encryption_enabled"], severity="high",
    remediation="Enable server-side encryption with KMS on the stream (StartStreamEncryption).", docs=[KINESIS_DOC])
def kinesis_kms(item, index):
    value = absent_or(item, "StreamARN", "EncryptionType", "NONE")
    return result(value != "KMS", encryption_type=value)


@install("aws.cb.kinesis.customer_kms_key", "kinesis_stream", "Kinesis stream is encrypted with a key other than alias/aws/kinesis",
    _stream(EncryptionType="KMS", KeyId="arn:aws:kms:us-east-1:111111111111:key/k"), _stream(EncryptionType="KMS", KeyId="alias/aws/kinesis"),
    rows=["aws-compliance.control.kinesis_stream_encrypted_with_kms_cmk"], severity="medium",
    remediation="Re-encrypt the stream with a customer managed KMS key.", docs=[KINESIS_DOC],
    note="Literal source predicate: EncryptionType KMS and KeyId <> 'alias/aws/kinesis'.")
def kinesis_cmk(item, index):
    value = absent_or(item, "StreamARN", "EncryptionType", "NONE")
    if value != "KMS":
        return result(True, encryption_type=value)
    key = get(item, "KeyId", str)
    return result(key == "alias/aws/kinesis", key_id=key)


# --------------------------------------------------------------------------- MediaStore
def _container(policy):
    import json
    return {"ARN": "arn:aws:mediastore:us-east-1:111111111111:container/c", "Policy": _ABSENT if policy is None else {"Policy": json.dumps(policy)}}


@install("aws.cb.mediastore.container_policy_not_public", "media_store_container", "MediaStore container policy does not grant unconditioned public access",
    _container(_PRIVATE), _container(_PUBLIC), rows=["aws-perimeter.control.media_store_container_policy_prohibit_public_access"], severity="high", category="exposure",
    remediation="Historical snapshots: review any public policy at the observation date. MediaStore is fully shut down; no current policy mutation applies.",
    docs=["https://docs.aws.amazon.com/mediastore/latest/apireference/API_GetContainerPolicy.html",
        RETIRED_SERVICES["mediastore"]["primary_url"], RETIRED_SERVICES["mediastore"]["access_url"]],
    extra={"not_applicable": _container(None), "pass_index": {"context": {**CONTEXT, "created_at": "2025-11-11T00:00:00+00:00"}},
        "fail_index": {"context": {**CONTEXT, "created_at": "2025-11-11T00:00:00+00:00"}},
        "not_applicable_index": {"context": {**CONTEXT, "created_at": "2025-11-11T00:00:00+00:00"}}},
    note="Historical-only MediaStore predicate over policies observed before 2025-11-12; AWS General Reference lists full shutdown on that date and CloudFormation says resources inaccessible after 2025-11-13. The transition interval and missing/malformed clocks are UNKNOWN; current snapshots are NOT_APPLICABLE. No policy is historical NOT_APPLICABLE.")
def mediastore(item, index):
    state = retirement_state("media_store_container", clock(item, index))
    if state == "retired":
        return "NOT_APPLICABLE", {"reason": "MediaStore is in full shutdown; historical policy evaluation does not apply to this observation date.",
            "end_of_support": RETIRED_SERVICES["mediastore"]["end_of_support"].isoformat(),
            "source": RETIRED_SERVICES["mediastore"]["primary_url"]}
    if state != "historical":
        return unknown("MediaStore lifecycle applicability is uncertain at the observation date", lifecycle_state=state)
    container = get(item, "Policy", dict)
    if container.get("collection_status") == "empty" and container.get("absent") is True:
        return "NOT_APPLICABLE", {"policy": None}
    hits = turbot_public_statements(policy_document(get(container, "Policy")))
    return result(bool(hits), public_statements=len(hits))


# --------------------------------------------------------------------------- Storage Gateway
@install("aws.cb.storagegateway.fileshare_kms", "storagegateway_file_share", "Storage Gateway file share uses KMS encryption",
    {"FileShareARN": "a", "KMSEncrypted": True}, {"FileShareARN": "a", "KMSEncrypted": False},
    rows=["prowler.aws.storagegateway_fileshare_encryption_enabled"], severity="medium",
    remediation="Enable KMS encryption with a customer managed key on the NFS/SMB file share.",
    docs=["https://docs.aws.amazon.com/storagegateway/latest/APIReference/API_NFSFileShareInfo.html"])
def sgw_kms(item, index):
    get(item, "FileShareARN", str)
    value = get(item, "KMSEncrypted", bool)
    return result(not value, kms_encrypted=value)


@install("aws.cb.storagegateway.gateway_not_on_ec2", "storagegateway_gateway", "Storage Gateway is not hosted on EC2",
    {"GatewayARN": "a", "HostEnvironment": "VMWARE"}, {"GatewayARN": "a", "HostEnvironment": "EC2"},
    rows=["prowler.aws.storagegateway_gateway_fault_tolerant"], severity="medium",
    remediation="Host the gateway on an on-premises hypervisor or hardware appliance to avoid single-instance EC2 dependency.",
    docs=["https://docs.aws.amazon.com/storagegateway/latest/APIReference/API_DescribeGatewayInformation.html"])
def sgw_env(item, index):
    get(item, "GatewayARN", str)
    env = get(item, "HostEnvironment", str)
    return result(env == "EC2", host_environment=env)


# --------------------------------------------------------------------------- WorkSpaces
_WS = "https://docs.aws.amazon.com/workspaces/latest/api/API_Workspace.html"


def _ws_flags(item):
    root = absent_or(item, "WorkspaceId", "RootVolumeEncryptionEnabled", False, bool)
    user = absent_or(item, "WorkspaceId", "UserVolumeEncryptionEnabled", False, bool)
    return root, user


@install("aws.cb.workspaces.root_and_user_volume_encryption", "workspaces_workspace", "WorkSpace root and user volumes are encrypted",
    {"WorkspaceId": "ws", "RootVolumeEncryptionEnabled": True, "UserVolumeEncryptionEnabled": True}, {"WorkspaceId": "ws", "RootVolumeEncryptionEnabled": True},
    rows=["prowler.aws.workspaces_volume_encryption_enabled", "aws-compliance.control.workspaces_workspace_volume_encryption_enabled"], severity="high",
    remediation="Recreate the WorkSpace with root and user volume encryption enabled using a KMS key.", docs=[_WS])
def ws_both(item, index):
    root, user = _ws_flags(item)
    return result(not (root and user), root=root, user=user)


for _cid, _field, _row in (("aws.cb.workspaces.root_volume_encryption", "RootVolumeEncryptionEnabled", "aws-compliance.control.workspaces_workspace_root_volume_encryption_enabled"),
                          ("aws.cb.workspaces.user_volume_encryption", "UserVolumeEncryptionEnabled", "aws-compliance.control.workspaces_workspace_user_volume_encryption_enabled")):
    def _ws_one(cid, field, row):
        @install(cid, "workspaces_workspace", "WorkSpace " + ("root" if "Root" in field else "user") + " volume is encrypted",
            {"WorkspaceId": "ws", field: True}, {"WorkspaceId": "ws", field: False}, rows=[row], severity="high",
            remediation="Recreate the WorkSpace with " + field + " set to true.", docs=[_WS])
        def evaluate(item, index):
            value = absent_or(item, "WorkspaceId", field, False, bool)
            return result(not value, **{field: value})
    _ws_one(_cid, _field, _row)


def _vpc_index(public_subnets, private_with_nat, private_plain, ws_public=False):
    subnets, tables = [], []
    def add(sid, routes):
        subnets.append({"data": {"SubnetId": sid, "VpcId": "vpc-1"}})
        tables.append({"data": {"VpcId": "vpc-1", "Associations": [{"SubnetId": sid}], "Routes": routes}})
    for i in range(public_subnets):
        add("subnet-pub%d" % i, [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}])
    for i in range(private_with_nat):
        add("subnet-nat%d" % i, [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"}])
    for i in range(private_plain):
        add("subnet-priv%d" % i, [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}])
    return {"collections": {"subnet": [{"status": "collected"}], "route_table": [{"status": "collected"}]}, "subnet": subnets, "route_table": tables}


@install("aws.cb.workspaces.private_subnet_with_nat_vpc", "workspaces_workspace", "WorkSpace is in a private subnet of a VPC with a public subnet, two private subnets and NAT",
    {"WorkspaceId": "ws", "SubnetId": "subnet-nat0"}, {"WorkspaceId": "ws", "SubnetId": "subnet-pub0"},
    rows=["prowler.aws.workspaces_vpc_2private_1public_subnets_nat"], severity="high", category="network",
    remediation="Place WorkSpaces in private subnets of a VPC with at least two private subnets, one public subnet and a NAT gateway for egress.",
    docs=[_WS, "https://docs.aws.amazon.com/workspaces/latest/adminguide/amazon-workspaces-vpc.html"], dependencies=["workspaces_workspace", "subnet", "route_table"],
    extra={"index": _vpc_index(1, 1, 1)},
    note="Prowler: public = 0.0.0.0/0 to igw-; NAT = a private subnet whose route table has a NatGatewayId route. Main-table fallback is scoped to the subnet's VPC.")
def ws_vpc(item, index):
    subnet_id = get(item, "SubnetId", str)
    subnet = subnet_vpc(index, subnet_id)
    vpc_id = get(subnet, "VpcId", str)
    public, private, nat, own_public = 0, 0, False, None
    for row in complete_items(index, "subnet"):
        if get(row, "VpcId", str) != vpc_id:
            continue
        sid = get(row, "SubnetId", str)
        table, _ = subnet_route_table(index, sid, vpc_id)
        is_public = igw_default_route(table)
        if sid == subnet_id:
            own_public = is_public
        if is_public:
            public += 1
        else:
            private += 1
            if any("NatGatewayId" in r for r in list_of_objects(get(table, "Routes", list))):
                nat = True
    failed = public < 1 or private < 2 or not nat or own_public
    return result(failed, vpc=vpc_id, public_subnets=public, private_subnets=private, nat_gateway=nat, workspace_subnet_public=own_public)
