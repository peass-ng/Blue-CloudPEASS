"""claude2_aws_b data service group: Athena, AWS Backup, DataSync, DAX, DLM, DMS, DocumentDB, DRS, DynamoDB, ElastiCache.

Native ports plus merged, manual and rejected rows. Facts that the collector does not gather
yet are listed in COLLECTOR_FACTS; until then their predicates return UNKNOWN.
"""
from __future__ import annotations

import json
import re
from datetime import timedelta
from fnmatch import fnmatchcase

from . import alias_check, result, unknown
from .facts import Unavailable, get, list_of_objects, complete_items, optional
from .fixtures import nest
from .claude2_aws_b_common import (install, flag, detail, detail_list, absent_or, strings, text, clock, parse_time, account,
    policy_document, is_policy_public, resource_policy_public, selection_resources, protected_resources,
    subnet_is_public_prowler, subnet_is_public_turbot, security_groups, scope_of, inventory, indexes,
    ABSENT, CONTEXT, SCOPE, ACCOUNT, P, C, X)

D_ATHENA = "https://docs.aws.amazon.com/athena/latest/APIReference/API_WorkGroupConfiguration.html"
D_ATHENA_ENC = "https://docs.aws.amazon.com/athena/latest/APIReference/API_EncryptionConfiguration.html"
D_ATHENA_SH = "https://docs.aws.amazon.com/securityhub/latest/userguide/athena-controls.html"
D_BACKUP_VAULT = "https://docs.aws.amazon.com/aws-backup/latest/devguide/API_DescribeBackupVault.html"
D_BACKUP_VAULT_POLICY = "https://docs.aws.amazon.com/aws-backup/latest/devguide/API_GetBackupVaultAccessPolicy.html"
D_BACKUP_RP = "https://docs.aws.amazon.com/aws-backup/latest/devguide/API_RecoveryPointByBackupVault.html"
D_BACKUP_RULE = "https://docs.aws.amazon.com/aws-backup/latest/devguide/API_BackupRule.html"
D_BACKUP_SEL = "https://docs.aws.amazon.com/aws-backup/latest/devguide/API_BackupSelection.html"
D_BACKUP_PR = "https://docs.aws.amazon.com/aws-backup/latest/devguide/API_ProtectedResource.html"
D_BACKUP_REPORT = "https://docs.aws.amazon.com/aws-backup/latest/devguide/API_ListReportPlans.html"
D_BACKUP_SH = "https://docs.aws.amazon.com/securityhub/latest/userguide/backup-controls.html"
D_DATASYNC = "https://docs.aws.amazon.com/datasync/latest/userguide/API_DescribeTask.html"
D_DAX = "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_dax_Cluster.html"
D_DLM = "https://docs.aws.amazon.com/dlm/latest/APIReference/API_LifecyclePolicySummary.html"
D_DMS_EP = "https://docs.aws.amazon.com/dms/latest/APIReference/API_Endpoint.html"
D_DMS_SH = "https://docs.aws.amazon.com/securityhub/latest/userguide/dms-controls.html"
D_DMS_MONGO = "https://docs.aws.amazon.com/dms/latest/APIReference/API_MongoDbSettings.html"
D_DMS_REDIS = "https://docs.aws.amazon.com/dms/latest/APIReference/API_RedisSettings.html"
D_DMS_NEPTUNE = "https://docs.aws.amazon.com/dms/latest/APIReference/API_NeptuneSettings.html"
D_DMS_TASK = "https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Tasks.CustomizingTasks.TaskSettings.Logging.html"
D_DMS_CERT = "https://docs.aws.amazon.com/dms/latest/APIReference/API_Certificate.html"
D_DMS_RI = "https://docs.aws.amazon.com/dms/latest/APIReference/API_ReplicationInstance.html"
D_DOCDB = "https://docs.aws.amazon.com/documentdb/latest/developerguide/API_DBCluster.html"
D_DOCDB_INST = "https://docs.aws.amazon.com/documentdb/latest/developerguide/API_DBInstance.html"
D_DOCDB_SH = "https://docs.aws.amazon.com/securityhub/latest/userguide/documentdb-controls.html"
D_DOCDB_TLS = "https://docs.aws.amazon.com/documentdb/latest/developerguide/security.encryption.ssl.html"
D_CSNAP_ATTR = "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBClusterSnapshotAttributes.html"
D_DRS = "https://docs.aws.amazon.com/drs/latest/APIReference/API_DescribeSourceServers.html"
D_DDB = "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TableDescription.html"
D_DDB_SSE = "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_SSEDescription.html"
D_DDB_POLICY = "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_GetResourcePolicy.html"
D_DDB_TAGS = "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ListTagsOfResource.html"
D_AAS = "https://docs.aws.amazon.com/autoscaling/application/APIReference/API_ScalableTarget.html"
D_DDB_SH = "https://docs.aws.amazon.com/securityhub/latest/userguide/dynamodb-controls.html"
D_EC_CLUSTER = "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CacheCluster.html"
D_EC_RG = "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_ReplicationGroup.html"
D_EC_SUBNET = "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CacheSubnetGroup.html"
D_EC_SH = "https://docs.aws.amazon.com/securityhub/latest/userguide/elasticache-controls.html"
D_EC_AUTH = "https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/auth.html"
D_EFS = "https://docs.aws.amazon.com/efs/latest/ug/API_FileSystemDescription.html"

ARN_PREFIX = "arn:aws:{}:us-east-1:" + ACCOUNT + ":"
VAULT_ARN = ARN_PREFIX.format("backup") + "backup-vault:v1"
RP_ARN = ARN_PREFIX.format("backup") + "recovery-point:rp1"
TABLE_ARN = ARN_PREFIX.format("dynamodb") + "table/t1"
EFS_ARN = ARN_PREFIX.format("elasticfilesystem") + "file-system/fs-1"
TASK_ARN = ARN_PREFIX.format("datasync") + "task/task-1"
DAX_ARN = ARN_PREFIX.format("dax") + "cache/d1"
EP_ARN = ARN_PREFIX.format("dms") + "endpoint:E1"
RT_ARN = ARN_PREFIX.format("dms") + "task:T1"
CERT_ARN = ARN_PREFIX.format("dms") + "cert:C1"
RI_ARN = ARN_PREFIX.format("dms") + "rep:R1"
DOC_ARN = ARN_PREFIX.format("rds") + "cluster:doc1"
DOC_INST_ARN = ARN_PREFIX.format("rds") + "db:doc1-1"
EC_ARN = ARN_PREFIX.format("elasticache") + "cluster:c1-001"
RG_ARN = ARN_PREFIX.format("elasticache") + "replicationgroup:rg1"
KMS_ARN = ARN_PREFIX.format("kms") + "key/k1"

# Read-only facts the collector does not gather yet (predicates stay UNKNOWN until they are collected).
COLLECTOR_FACTS = [
    {"kind": "athena_workgroup", "api": "athena:ListWorkGroups + athena:GetWorkGroup",
     "fields": ["Name", "State", "WorkGroup.WorkGroup.{Name, State, Configuration.{ResultConfiguration.EncryptionConfiguration.EncryptionOption, "
                "EnforceWorkGroupConfiguration, PublishCloudWatchMetricsEnabled, ManagedQueryResultsConfiguration.Enabled}}"],
     "checks": ["aws.c2b.athena.results_encrypted", "aws.c2b.athena.results_encrypted_prowler", "aws.c2b.athena.enforce_configuration",
                "aws.c2b.athena.enforce_configuration_prowler", "aws.c2b.athena.cloudwatch_metrics", "aws.c2b.athena.cloudwatch_metrics_prowler"]},
    {"kind": "backup_vault", "api": "backup:GetBackupVaultAccessPolicy",
     "fields": ["Policy.Policy", "ResourceNotFoundException stored as the ABSENT marker (today it becomes an error status)"],
     "checks": ["aws.c2b.backup.vault_policy_denies_recovery_point_deletion", "aws.c2b.backup.vault_policy_not_public"]},
    {"kind": "backup_recovery_point", "api": "backup:ListRecoveryPointsByBackupVault (every vault)",
     "fields": ["RecoveryPointArn", "BackupVaultName", "IsEncrypted", "Lifecycle.DeleteAfterDays"],
     "checks": ["aws.c2b.backup.recovery_point_encrypted", "aws.c2b.backup.recovery_point_retention_35"]},
    {"kind": "datasync_task", "api": "datasync:ListTasks + datasync:DescribeTask",
     "fields": ["TaskArn", "Task.{TaskArn, CloudWatchLogGroupArn, Options.LogLevel}"],
     "checks": ["aws.c2b.datasync.task_log_group", "aws.c2b.datasync.task_logging_level"]},
    {"kind": "dax_cluster", "api": "dax:DescribeClusters",
     "fields": ["ClusterArn", "SSEDescription.Status", "ClusterEndpointEncryptionType", "Nodes[].AvailabilityZone"],
     "checks": ["aws.c2b.dax.encryption_at_rest", "aws.c2b.dax.encryption_in_transit", "aws.c2b.dax.multi_az"]},
    {"kind": "dlm_lifecycle_policy", "api": "dlm:GetLifecyclePolicies", "fields": ["PolicyId", "State", "PolicyType"],
     "checks": ["aws.c2b.dlm.policy_exists_with_snapshots", "aws.c2b.dlm.ebs_snapshot_policy_with_snapshots"]},
    {"kind": "dms_endpoint", "api": "dms:DescribeEndpoints",
     "fields": ["EndpointArn", "EngineName", "SslMode", "MongoDbSettings.AuthType", "NeptuneSettings.IamAuthEnabled",
                "RedisSettings.{ServerName, SslSecurityProtocol}"],
     "checks": ["aws.c2b.dms.endpoint_ssl", "aws.c2b.dms.mongodb_auth", "aws.c2b.dms.neptune_iam_auth", "aws.c2b.dms.redis_tls"]},
    {"kind": "dms_replication_task", "api": "dms:DescribeReplicationTasks",
     "fields": ["ReplicationTaskArn", "ReplicationTaskSettings (JSON: Logging.EnableLogging, Logging.LogComponents[].{Id, Severity})"],
     "checks": ["aws.c2b.dms.task_source_logging", "aws.c2b.dms.task_target_logging"]},
    {"kind": "dms_certificate", "api": "dms:DescribeCertificates", "fields": ["CertificateArn", "ValidToDate"],
     "checks": ["aws.c2b.dms.certificate_not_expired"]},
    {"kind": "docdb_cluster", "api": "rds:DescribeDBClusterParameters (cluster parameter group of each docdb cluster)",
     "fields": ["ClusterParameterGroupValues.tls"], "checks": ["aws.c2b.docdb.cluster_tls_required"]},
    {"kind": "rds_cluster_snapshot", "api": "rds:DescribeDBClusterSnapshotAttributes",
     "fields": ["Attributes.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes[].{AttributeName, AttributeValues}"],
     "checks": ["aws.c2b.docdb.snapshot_restore_not_all_exact", "aws.c2b.docdb.snapshot_not_public_prowler"]},
    {"kind": "drs_source_server", "api": "drs:DescribeSourceServers", "fields": ["sourceServerID", "dataReplicationInfo.dataReplicationState", "UninitializedAccountException stored as an empty inventory"],
     "checks": ["aws.c2b.drs.region_has_job"]},
    {"kind": "appautoscaling_target", "api": "application-autoscaling:DescribeScalableTargets (ServiceNamespace=dynamodb)",
     "fields": ["ServiceNamespace", "ResourceId", "ScalableDimension"], "checks": ["aws.c2b.dynamodb.capacity_autoscaling"]},
    {"kind": "dynamodb_table", "api": "dynamodb:GetResourcePolicy + dynamodb:ListTagsOfResource",
     "fields": ["ResourcePolicy.Policy (PolicyNotFoundException stored as the ABSENT marker)", "Tags.items[].{Key, Value}"],
     "checks": ["aws.c2b.dynamodb.policy_not_cross_account", "aws.c2b.dynamodb.table_in_backup_selection_or_tag"]},
    {"kind": "elasticache_subnet_group", "api": "elasticache:DescribeCacheSubnetGroups",
     "fields": ["CacheSubnetGroupName", "Subnets[].SubnetIdentifier"],
     "checks": ["aws.c2b.elasticache.cluster_public_subnet_prowler", "aws.c2b.elasticache.cluster_public_subnet"]},
]


# =========================================================================== Athena
def _wg_item(configuration, state="ENABLED"):
    return {"Name": "wg1", "State": state, "WorkGroup": {"collection_status": "collected",
            "WorkGroup": {"Name": "wg1", "State": state, "Configuration": configuration}}}


def _workgroup(item):
    get(item, "Name", str)
    body = detail(item, "WorkGroup")
    if body is None:
        raise Unavailable("workgroup detail not found")
    return get(body, "WorkGroup", dict)


def _wg_conf(workgroup, path, default, expected):
    return absent_or(workgroup, "Name", "Configuration." + path, default, expected)


def _wg_enabled(workgroup):
    state = get(workgroup, "State", str)
    return None if state == "ENABLED" else {"state": state, "reason": "Prowler evaluates enabled workgroups only"}


_ENC = ("SSE_S3", "SSE_KMS", "CSE_KMS")


def _wg_encryption(workgroup):
    return _wg_conf(workgroup, "ResultConfiguration.EncryptionConfiguration.EncryptionOption", None, str)


@install("aws.c2b.athena.results_encrypted", "athena_workgroup", "Athena workgroup query results are encrypted at rest",
    _wg_item({"ResultConfiguration": {"EncryptionConfiguration": {"EncryptionOption": "SSE_KMS"}}}), _wg_item({"ResultConfiguration": {}}),
    rows=[C + "athena_workgroup_encryption_at_rest_enabled", C + "foundational_security_athena_1"], severity="medium", control="SC-28",
    remediation="Enable query result encryption (SSE_S3, SSE_KMS or CSE_KMS) or managed query results on the Athena workgroup.",
    docs=[D_ATHENA, D_ATHENA_ENC, D_ATHENA_SH],
    extra={"mqr": _wg_item({"ManagedQueryResultsConfiguration": {"Enabled": True}}), "mqr_expect": "PASS",
           "disabled_wg": _wg_item({}, state="DISABLED"), "disabled_wg_expect": "FAIL"},
    note="Steampipe: managed query results enabled, or EncryptionOption in SSE_S3/SSE_KMS/CSE_KMS; every workgroup, any state.")
def athena_results_encrypted(item, index):
    workgroup = _workgroup(item)
    mqr = _wg_conf(workgroup, "ManagedQueryResultsConfiguration.Enabled", False, bool)
    option = _wg_encryption(workgroup)
    return result(not mqr and option not in _ENC, managed_query_results=mqr, encryption_option=option)


@install("aws.c2b.athena.results_encrypted_prowler", "athena_workgroup", "Enabled Athena workgroup encrypts query results",
    _wg_item({"ResultConfiguration": {"EncryptionConfiguration": {"EncryptionOption": "SSE_S3"}}}),
    _wg_item({"ManagedQueryResultsConfiguration": {"Enabled": True}}),
    rows=[P + "athena_workgroup_encryption"], severity="medium", control="SC-28",
    remediation="Configure ResultConfiguration.EncryptionConfiguration (SSE_S3, SSE_KMS or CSE_KMS) on the Athena workgroup.",
    docs=[D_ATHENA_ENC], extra={"not_applicable": _wg_item({}, state="DISABLED")},
    note="Prowler: EncryptionConfiguration of the result configuration only (managed query results are not considered); "
         "DISABLED workgroups are NOT_APPLICABLE. Prowler's extra filter on workgroups with recent queries is not replicated.")
def athena_results_encrypted_prowler(item, index):
    workgroup = _workgroup(item)
    skip = _wg_enabled(workgroup)
    if skip:
        return "NOT_APPLICABLE", skip
    option = _wg_encryption(workgroup)
    return result(option not in _ENC, encryption_option=option)


def _athena_bool(cid, path, title, rows, remediation, prowler, docs, note):
    @install(cid, "athena_workgroup", title, _wg_item(nest(path, True)), _wg_item(nest(path, False)), rows=rows, severity="medium",
        control="AU-2" if "Metrics" in path else "CM-6", remediation=remediation, docs=docs,
        extra={"not_applicable": _wg_item({}, state="DISABLED")} if prowler else {"unset": _wg_item({}), "unset_expect": "FAIL"}, note=note)
    def evaluate(item, index):
        workgroup = _workgroup(item)
        if prowler:
            skip = _wg_enabled(workgroup)
            if skip:
                return "NOT_APPLICABLE", skip
        value = _wg_conf(workgroup, path, False, bool)
        return result(not value, field=path, configured=value)
    evaluate.__name__ = cid.replace(".", "_")


_athena_bool("aws.c2b.athena.enforce_configuration", "EnforceWorkGroupConfiguration", "Athena workgroup enforces its configuration",
    [C + "athena_workgroup_enforce_configuration_enabled"], "Enable EnforceWorkGroupConfiguration so workgroup settings override client-side settings.",
    False, [D_ATHENA], "Steampipe: every workgroup; an omitted EnforceWorkGroupConfiguration is treated as false.")
_athena_bool("aws.c2b.athena.enforce_configuration_prowler", "EnforceWorkGroupConfiguration", "Enabled Athena workgroup enforces its configuration",
    [P + "athena_workgroup_enforce_configuration"], "Enable EnforceWorkGroupConfiguration so workgroup settings override client-side settings.",
    True, [D_ATHENA], "Prowler: enabled workgroups only (DISABLED is NOT_APPLICABLE); the recent-queries filter is not replicated.")
_athena_bool("aws.c2b.athena.cloudwatch_metrics", "PublishCloudWatchMetricsEnabled", "Athena workgroup publishes CloudWatch metrics",
    [C + "athena_workgroup_logging_enabled", C + "foundational_security_athena_4"], "Enable PublishCloudWatchMetricsEnabled on the Athena workgroup.",
    False, [D_ATHENA, D_ATHENA_SH], "Steampipe: every workgroup; an omitted PublishCloudWatchMetricsEnabled is treated as false.")
_athena_bool("aws.c2b.athena.cloudwatch_metrics_prowler", "PublishCloudWatchMetricsEnabled", "Enabled Athena workgroup publishes CloudWatch metrics",
    [P + "athena_workgroup_logging_enabled"], "Enable PublishCloudWatchMetricsEnabled on the Athena workgroup.",
    True, [D_ATHENA], "Prowler: enabled workgroups only (DISABLED is NOT_APPLICABLE); the recent-queries filter is not replicated.")


# =========================================================================== AWS Backup
ANCHOR = {"scope": SCOPE}
_PLAN = {"BackupPlanId": "p1", "BackupPlanArn": ARN_PREFIX.format("backup") + "backup-plan:p1"}
_VAULT = {"BackupVaultArn": VAULT_ARN, "BackupVaultName": "v1"}


@install("aws.c2b.backup.plans_exist_when_vaults", "backup_plan", "Region with backup vaults has at least one backup plan",
    ANCHOR, ANCHOR, rows=[P + "backup_plans_exist"], severity="low", control="CP-9", target="scope", dependencies=["backup_plan", "backup_vault"],
    remediation="Create an AWS Backup plan that assigns the resources to protect.", docs=["https://docs.aws.amazon.com/aws-backup/latest/devguide/creating-a-backup-plan.html"],
    extra={"pass_index": indexes(inventory("backup_plan", [_PLAN]), inventory("backup_vault", [_VAULT])),
           "fail_index": indexes(inventory("backup_plan", []), inventory("backup_vault", [_VAULT])),
           "not_applicable": ANCHOR, "not_applicable_index": indexes(inventory("backup_plan", []), inventory("backup_vault", []))},
    note="Prowler: PASS when backup plans exist, FAIL when none exist but vaults do, nothing otherwise. Prowler aggregates the account; "
         "here each audited region is evaluated over its own plan and vault inventories.")
def backup_plans_exist(item, index):
    scope = scope_of(item)
    plans = complete_items(index, "backup_plan")
    if plans:
        return result(False, scope=scope, plans=len(plans))
    vaults = complete_items(index, "backup_vault")
    if not vaults:
        return "NOT_APPLICABLE", {"scope": scope, "reason": "no backup plans or vaults"}
    return result(True, scope=scope, plans=0, vaults=len(vaults))


@install("aws.c2b.backup.report_plans_when_plans", "backup_report_plan", "Region with backup plans has a backup report plan",
    ANCHOR, ANCHOR, rows=[P + "backup_reportplans_exist"], severity="low", control="AU-6", target="scope",
    dependencies=["backup_plan", "backup_report_plan"],
    remediation="Create an AWS Backup report plan (for example BACKUP_JOB_REPORT) for the region.", docs=[D_BACKUP_REPORT],
    extra={"pass_index": indexes(inventory("backup_plan", [_PLAN]), inventory("backup_report_plan", [{"ReportPlanName": "r1"}])),
           "fail_index": indexes(inventory("backup_plan", [_PLAN]), inventory("backup_report_plan", [])),
           "not_applicable": ANCHOR, "not_applicable_index": indexes(inventory("backup_plan", []), inventory("backup_report_plan", []))},
    note="Prowler: only evaluated when backup plans exist; PASS iff at least one report plan exists.")
def backup_report_plans(item, index):
    scope = scope_of(item)
    if not complete_items(index, "backup_plan"):
        return "NOT_APPLICABLE", {"scope": scope, "reason": "no backup plans"}
    reports = complete_items(index, "backup_report_plan")
    return result(not reports, scope=scope, report_plans=len(reports))


@install("aws.c2b.backup.vault_encrypted", "backup_vault", "Backup vault reports a configured encryption key",
    dict(_VAULT, EncryptionKeyArn=KMS_ARN), dict(_VAULT),
    rows=[P + "backup_vaults_encrypted"], severity="medium", control="SC-28",
    remediation="Review the vault's key metadata and the resource type of each recovery point before changing backup encryption; vault keys do not independently encrypt every supported resource type.",
    docs=[D_BACKUP_VAULT, "https://docs.aws.amazon.com/aws-backup/latest/devguide/encryption.html"],
    extra={"fail_expect": "UNKNOWN"},
    note="Pinned Prowler FAILS a missing ListBackupVaults EncryptionKeyArn. AWS says an omitted key at vault creation defaults to a KMS key, and vault-independent encryption depends on the protected resource type; an absent list field does not prove unencrypted backups. Use matching DescribeBackupVault key metadata when available; missing, denied, conflicting or malformed metadata is UNKNOWN. A present vault key establishes only vault key configuration, not every recovery point's encryption state.")
def backup_vault_encrypted(item, index):
    vault_arn = get(item, "BackupVaultArn", str)
    if not vault_arn:
        raise Unavailable("backup vault ARN unavailable")
    config = item.get("Configuration")
    detail_status = "not_collected"
    if config is not None:
        if not isinstance(config, dict):
            raise Unavailable("malformed DescribeBackupVault response")
        detail_status = config.get("collection_status", "collected")
        if detail_status != "collected":
            return "UNKNOWN", {"reason": "DescribeBackupVault key metadata unavailable", "vault_arn": vault_arn,
                "detail_collection_status": detail_status}
        if config.get("BackupVaultArn") != vault_arn:
            return "UNKNOWN", {"reason": "DescribeBackupVault identity missing or mismatched", "vault_arn": vault_arn,
                "detail_collection_status": detail_status}

    def observed_key(source, value):
        if value is None:
            return None
        if not isinstance(value, str) or not re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+", value):
            raise Unavailable("malformed " + source + " EncryptionKeyArn")
        return value

    listed = observed_key("ListBackupVaults", item.get("EncryptionKeyArn"))
    described = observed_key("DescribeBackupVault", config.get("EncryptionKeyArn")) if config is not None else None
    if config is not None and listed and described and listed != described:
        return "UNKNOWN", {"reason": "vault key ARN differs between list and describe responses", "vault_arn": vault_arn,
            "detail_collection_status": detail_status}
    if config is not None and not described:
        return "UNKNOWN", {"reason": "DescribeBackupVault did not report an encryption key ARN", "vault_arn": vault_arn,
            "list_key_observed": bool(listed), "detail_collection_status": detail_status}
    key = described or listed
    if not key:
        return "UNKNOWN", {"reason": "vault encryption key ARN not observed; AWS may use its default KMS key",
            "vault_arn": vault_arn, "detail_collection_status": detail_status}
    return result(False, vault_arn=vault_arn, encryption_key_arn=key,
        source_api="backup:DescribeBackupVault" if described else "backup:ListBackupVaults",
        criterion="vault key metadata observed; recovery point encryption is assessed separately")


_RP = {"RecoveryPointArn": RP_ARN, "BackupVaultName": "v1"}

flag("aws.c2b.backup.recovery_point_encrypted", "backup_recovery_point", "Backup recovery point is encrypted", "IsEncrypted",
    rows=[P + "backup_recovery_point_encrypted", C + "backup_recovery_point_encryption_enabled", C + "foundational_security_backup_1"],
    severity="medium", control="SC-28", sentinel="RecoveryPointArn", base=_RP, docs=[D_BACKUP_RP, D_BACKUP_SH],
    remediation="Store recovery points in a vault with a KMS key; copy unencrypted recovery points into an encrypted vault.")


@install("aws.c2b.backup.recovery_point_retention_35", "backup_recovery_point", "Backup recovery point is retained at least 35 days",
    dict(_RP, Lifecycle={"DeleteAfterDays": 35}), dict(_RP, Lifecycle={"DeleteAfterDays": 7}),
    rows=[C + "backup_recovery_point_min_retention_35_days"], severity="medium", control="CP-9",
    remediation="Set the recovery point lifecycle DeleteAfterDays to 35 or more, or leave it unset (never expires).", docs=[D_BACKUP_RP],
    extra={"never": dict(_RP), "never_expect": "PASS"},
    note="Steampipe: an omitted Lifecycle.DeleteAfterDays means the recovery point never expires and passes.")
def recovery_point_retention(item, index):
    days = absent_or(item, "RecoveryPointArn", "Lifecycle.DeleteAfterDays", None, int)
    return result(days is not None and days < 35, delete_after_days=days)


def _plan(rules):
    return dict(_PLAN, Plan={"collection_status": "collected", "BackupPlan": {"BackupPlanName": "p1", "Rules": rules}})


@install("aws.c2b.backup.plan_rules_retention_35", "backup_plan", "Backup plan rules retain recovery points at least 35 days",
    _plan([{"RuleName": "r1", "Lifecycle": {"DeleteAfterDays": 35}}, {"RuleName": "r2"}]), _plan([{"RuleName": "r1", "Lifecycle": {"DeleteAfterDays": 30}}]),
    rows=[C + "backup_plan_min_retention_35_days"], severity="medium", control="CP-9",
    remediation="Set DeleteAfterDays of every backup rule lifecycle to 35 or more, or remove the expiration.", docs=[D_BACKUP_RULE],
    extra={"not_applicable": _plan([]), "cold_only": _plan([{"RuleName": "r1", "Lifecycle": {"MoveToColdStorageAfterDays": 30}}]), "cold_only_expect": "PASS"},
    note="Steampipe: a rule without Lifecycle never expires (ok), DeleteAfterDays >= 35 ok, otherwise alarm. Deviation: a Lifecycle without "
         "DeleteAfterDays (only cold-storage transition) also never expires and passes here, while upstream alarms on the NULL cast. "
         "A plan without rules is NOT_APPLICABLE (upstream emits no row).")
def plan_rules_retention(item, index):
    get(item, "BackupPlanId", str)
    body = detail(item, "Plan")
    if body is None:
        raise Unavailable("backup plan detail not found")
    rules = list_of_objects(get(body, "BackupPlan.Rules", list))
    if not rules:
        return "NOT_APPLICABLE", {"reason": "backup plan has no rules"}
    short = []
    for rule in rules:
        lifecycle = optional(rule, "Lifecycle", None, dict)
        days = None if lifecycle is None else optional(lifecycle, "DeleteAfterDays", None, int)
        if days is not None and days < 35:
            short.append({"rule": rule.get("RuleName"), "delete_after_days": days})
    return result(bool(short), short_retention_rules=short)


_LOCK_ACTIONS = ("backup:DeleteRecoveryPoint", "backup:UpdateRecoveryPointLifecycle", "backup:PutBackupVaultAccessPolicy")


def _vault_policy(item):
    get(item, "BackupVaultArn", str)
    body = detail(item, "Policy")
    if body is None:
        return None
    return policy_document(get(body, "Policy"))


def _actions(statement):
    actions = statement.get("Action", [])
    actions = [actions] if isinstance(actions, str) else actions
    return strings(actions, "Statement.Action")


def _covers(patterns, action):
    return any(fnmatchcase(action.lower(), p.lower()) for p in patterns)


def _vault_policy_doc(statements):
    return {"collection_status": "collected", "Policy": json.dumps({"Version": "2012-10-17", "Statement": statements})}


_DENY = {"Effect": "Deny", "Principal": "*", "Action": list(_LOCK_ACTIONS), "Resource": "*"}


@install("aws.c2b.backup.vault_policy_denies_recovery_point_deletion", "backup_vault", "Backup vault policy denies manual recovery point deletion",
    dict(_VAULT, Policy=_vault_policy_doc([_DENY])), dict(_VAULT, Policy=_vault_policy_doc([dict(_DENY, Action=["backup:DeleteRecoveryPoint"])])),
    rows=[C + "backup_recovery_point_manual_deletion_disabled"], severity="medium", control="CP-9",
    remediation="Add a vault access policy Deny statement on backup:DeleteRecoveryPoint, backup:UpdateRecoveryPointLifecycle and "
                "backup:PutBackupVaultAccessPolicy for Resource \"*\" (or use AWS Backup Vault Lock).",
    docs=[D_BACKUP_VAULT_POLICY, "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-vault-access-policy.html"],
    extra={"no_policy": dict(_VAULT, Policy=ABSENT), "no_policy_expect": "FAIL",
           "wildcard": dict(_VAULT, Policy=_vault_policy_doc([dict(_DENY, Action="backup:*", Resource=["*"])])), "wildcard_expect": "PASS"},
    note="Steampipe: a Deny statement whose Action array contains the three actions and Resource = \"*\". Relaxed to avoid false positives: "
         "wildcard actions (backup:*, *, backup:Delete*...) that cover each action, a string Action and Resource [\"*\"] also count. "
         "A vault without an access policy fails.")
def vault_policy_denies_deletion(item, index):
    statements = _vault_policy(item)
    if statements is None:
        return result(True, policy=None)
    for statement in statements:
        if statement.get("Effect") != "Deny":
            continue
        resource = statement.get("Resource")
        if resource not in ("*", ["*"]):
            continue
        patterns = _actions(statement)
        if all(_covers(patterns, action) for action in _LOCK_ACTIONS):
            return result(False, statement=statement.get("Sid"))
    return result(True, required_actions=list(_LOCK_ACTIONS))


_PUBLIC = {"Effect": "Allow", "Principal": "*", "Action": "backup:CopyIntoBackupVault", "Resource": "*"}


@install("aws.c2b.backup.vault_policy_not_public", "backup_vault", "Backup vault access policy does not allow public access",
    dict(_VAULT, Policy=_vault_policy_doc([dict(_PUBLIC, Principal={"AWS": "arn:aws:iam::" + ACCOUNT + ":root"})])),
    dict(_VAULT, Policy=_vault_policy_doc([_PUBLIC])),
    rows=[X + "backup_vault_policy_prohibit_public_access"], severity="high", category="exposure", control="AC-3",
    remediation="Remove Allow statements with a wildcard principal from the backup vault access policy, or restrict them with conditions.",
    docs=[D_BACKUP_VAULT_POLICY], extra={"no_policy": dict(_VAULT, Policy=ABSENT)},
    note="aws-perimeter resource_policy_public: Allow statement with a wildcard principal and no restricting condition. No policy passes.")
def vault_policy_not_public(item, index):
    statements = _vault_policy(item)
    if statements is None:
        return result(False, policy=None)
    return result(public := resource_policy_public(statements), public_policy=public)


def _protected_index(arn, rtype):
    return inventory("backup_protected_resource", [{"ResourceArn": arn, "ResourceType": rtype}])


def _table(**extra):
    return {"Table": {"Table": {"TableName": "t1", "TableArn": TABLE_ARN, **extra}}}


def _table_body(item):
    body = get(item, "Table.Table", dict)
    get(body, "TableArn", str)
    return body


@install("aws.c2b.dynamodb.table_protected_resource", "dynamodb_table", "DynamoDB table is an AWS Backup protected resource",
    _table(), _table(), rows=[C + "dynamodb_table_protected_by_backup_plan"], severity="medium", control="CP-9",
    dependencies=["dynamodb_table", "backup_protected_resource"],
    remediation="Protect the DynamoDB table with an AWS Backup plan so recovery points exist.", docs=[D_BACKUP_PR],
    extra={"pass_index": _protected_index(TABLE_ARN, "DynamoDB"), "fail_index": _protected_index(TABLE_ARN, "EFS")},
    note="Steampipe: the table ARN is a backup protected resource of type DynamoDB.")
def table_protected(item, index):
    arn = get(_table_body(item), "TableArn", str)
    hit = any(get(r, "ResourceArn", str) == arn and get(r, "ResourceType", str) == "DynamoDB" for r in protected_resources(index))
    return result(not hit, resource_arn=arn, protected_resource=hit)


@install("aws.c2b.efs.file_system_protected_resource", "efs_file_system", "EFS file system is an AWS Backup protected resource",
    {"FileSystemArn": EFS_ARN}, {"FileSystemArn": EFS_ARN},
    rows=[C + "efs_file_system_protected_by_backup_plan", C + "foundational_security_efs_2"], severity="medium", control="CP-9",
    dependencies=["efs_file_system", "backup_protected_resource"],
    remediation="Protect the EFS file system with an AWS Backup plan (or enable EFS automatic backups).",
    docs=[D_BACKUP_PR, D_EFS, "https://docs.aws.amazon.com/securityhub/latest/userguide/efs-controls.html"],
    extra={"pass_index": _protected_index(EFS_ARN, "EFS"), "fail_index": _protected_index("arn:other", "EFS")},
    note="Steampipe: the file system ARN is a backup protected resource of type EFS.")
def efs_protected(item, index):
    arn = get(item, "FileSystemArn", str)
    hit = any(get(r, "ResourceArn", str) == arn and get(r, "ResourceType", str) == "EFS" for r in protected_resources(index))
    return result(not hit, resource_arn=arn, protected_resource=hit)


def _plan_index(resources, tag_keys=()):
    body = {"Resources": resources}
    if tag_keys:
        body["ListOfTags"] = [{"ConditionType": "STRINGEQUALS", "ConditionKey": k, "ConditionValue": "v"} for k in tag_keys]
    return inventory("backup_plan", [dict(_PLAN, Selections={"collection_status": "collected",
                     "items": [{"SelectionId": "s1", "Selection": {"BackupSelection": body}}]})])


def _selections(index):
    out = []
    for plan in complete_items(index, "backup_plan"):
        selections = get(plan, "Selections", dict)
        if selections.get("collection_status") not in ("collected", "empty"):
            raise Unavailable("backup selections unavailable")
        for selection in list_of_objects(selections.get("items", [])):
            out.append(get(selection, "Selection.BackupSelection", dict))
    return out


def _table_wildcards(arn):
    partition = arn.split(":")[1] if arn.count(":") > 2 else "aws"
    return {arn, "arn:%s:dynamodb:*:*:table/*" % partition, "*"}


@install("aws.c2b.dynamodb.table_in_backup_selection_prowler", "dynamodb_table", "DynamoDB table is selected by an AWS Backup plan",
    _table(), _table(), rows=[P + "dynamodb_table_protected_by_backup_plan"], severity="medium", control="CP-9",
    dependencies=["dynamodb_table", "backup_plan"],
    remediation="Add the table ARN (or a dynamodb table wildcard) to an AWS Backup plan resource selection.", docs=[D_BACKUP_SEL],
    extra={"pass_index": _plan_index(["arn:aws:dynamodb:*:*:table/*"]), "fail_index": _plan_index([ARN_PREFIX.format("dynamodb") + "table/other"])},
    note="Prowler protected_resources are backup selection Resources; the ARN, arn:<partition>:dynamodb:*:*:table/* and * count.")
def table_selected(item, index):
    arn = get(_table_body(item), "TableArn", str)
    resources = selection_resources(index)
    return result(not (matches := _table_wildcards(arn) & set(resources)), resource_arn=arn, backup_selection_match=bool(matches))


def _table_tags(item):
    tags = detail_list(item, "Tags")
    return {get(t, "Key", str) for t in tags}


@install("aws.c2b.dynamodb.table_in_backup_selection_or_tag", "dynamodb_table", "DynamoDB table is in a backup selection by ARN or tag key",
    dict(_table(), Tags={"collection_status": "collected", "items": [{"Key": "backup", "Value": "daily"}]}),
    dict(_table(), Tags={"collection_status": "empty", "items": []}),
    rows=[C + "dynamodb_table_in_backup_plan"], severity="medium", control="CP-9", dependencies=["dynamodb_table", "backup_plan"],
    remediation="Assign the table to an AWS Backup plan selection by ARN or by a tag condition.", docs=[D_BACKUP_SEL, D_DDB_TAGS],
    extra={"pass_index": _plan_index([], ["backup"]), "fail_index": _plan_index([], ["other"]),
           "by_arn": dict(_table(), Tags={"collection_status": "empty", "items": []}), "by_arn_index": _plan_index([TABLE_ARN]), "by_arn_expect": "PASS"},
    note="Steampipe: selection Resources contain the table ARN, or a ListOfTags ConditionKey equals one of the table tag keys (values are "
         "not compared, as upstream). Relaxed to avoid false positives: selection Resources * and arn:<partition>:dynamodb:*:*:table/* also count.")
def table_selected_or_tag(item, index):
    arn = get(_table_body(item), "TableArn", str)
    keys = _table_tags(item)
    wildcards = _table_wildcards(arn)
    for selection in _selections(index):
        resources = strings(optional(selection, "Resources", [], list), "BackupSelection.Resources")
        if wildcards & set(resources):
            return result(False, matched="resource", resource_arn=arn)
        conditions = list_of_objects(optional(selection, "ListOfTags", [], list))
        if keys & {c.get("ConditionKey") for c in conditions}:
            return result(False, matched="tag", resource_arn=arn)
    return result(True, resource_arn=arn, tag_keys=sorted(keys), backup_selection_match=False)


# =========================================================================== DataSync
def _task(task):
    return {"TaskArn": TASK_ARN, "Task": {"collection_status": "collected", "TaskArn": TASK_ARN, **task}}


def _task_detail(item):
    get(item, "TaskArn", str)
    body = detail(item, "Task")
    if body is None:
        raise Unavailable("DataSync task detail not found")
    return body


_LOG_GROUP = ARN_PREFIX.format("logs") + "log-group:/aws/datasync"


@install("aws.c2b.datasync.task_log_group", "datasync_task", "DataSync task has a CloudWatch log group",
    _task({"CloudWatchLogGroupArn": _LOG_GROUP}), _task({}),
    rows=[P + "datasync_task_logging_enabled"], severity="high", control="AU-2",
    remediation="Configure a CloudWatch log group on the DataSync task.", docs=[D_DATASYNC],
    note="Prowler: PASS when the task has CloudWatchLogGroupArn (the log level is not checked).")
def datasync_log_group(item, index):
    group = absent_or(_task_detail(item), "TaskArn", "CloudWatchLogGroupArn", None, str)
    return result(not group, log_group=group)


@install("aws.c2b.datasync.task_logging_level", "datasync_task", "DataSync task logs to CloudWatch at BASIC or TRANSFER level",
    _task({"CloudWatchLogGroupArn": _LOG_GROUP, "Options": {"LogLevel": "BASIC"}}), _task({"CloudWatchLogGroupArn": _LOG_GROUP, "Options": {"LogLevel": "OFF"}}),
    rows=[C + "datasync_task_logging_enabled", C + "foundational_security_datasync_1"], severity="medium", control="AU-2",
    remediation="Configure a CloudWatch log group and set Options.LogLevel to BASIC or TRANSFER on the DataSync task.",
    docs=[D_DATASYNC, "https://docs.aws.amazon.com/securityhub/latest/userguide/datasync-controls.html"],
    note="Steampipe: CloudWatchLogGroupArn set and Options.LogLevel in BASIC/TRANSFER.")
def datasync_log_level(item, index):
    task = _task_detail(item)
    group = absent_or(task, "TaskArn", "CloudWatchLogGroupArn", None, str)
    level = absent_or(task, "TaskArn", "Options.LogLevel", None, str)
    return result(not group or level not in ("BASIC", "TRANSFER"), log_group=group, log_level=level)


# =========================================================================== DAX
_DAX = {"ClusterName": "d1", "ClusterArn": DAX_ARN}

flag("aws.c2b.dax.encryption_at_rest", "dax_cluster", "DAX cluster encrypts data at rest", "SSEDescription.Status",
    rows=[P + "dynamodb_accelerator_cluster_encryption_enabled", C + "dax_cluster_encryption_at_rest_enabled", C + "foundational_security_dynamodb_3"],
    severity="medium", control="SC-28", sentinel="ClusterArn", base=_DAX, good="ENABLED", bad="DISABLED", default="DISABLED", expected=str,
    remediation="Create the DAX cluster with server-side encryption enabled (it cannot be enabled on an existing cluster).",
    docs=[D_DAX, D_DDB_SH], note="An omitted SSEDescription means encryption at rest is not enabled.")
flag("aws.c2b.dax.encryption_in_transit", "dax_cluster", "DAX cluster endpoint uses TLS", "ClusterEndpointEncryptionType",
    rows=[P + "dynamodb_accelerator_cluster_in_transit_encryption_enabled", C + "dax_cluster_encryption_in_transit_enabled", C + "foundational_security_dynamodb_7"],
    severity="medium", control="SC-8", sentinel="ClusterArn", base=_DAX, good="TLS", bad="NONE", default="NONE", expected=str,
    remediation="Create the DAX cluster with ClusterEndpointEncryptionType TLS.", docs=[D_DAX, D_DDB_SH],
    note="An omitted ClusterEndpointEncryptionType is the API default NONE.")


@install("aws.c2b.dax.multi_az", "dax_cluster", "DAX cluster nodes span more than one Availability Zone",
    dict(_DAX, Nodes=[{"AvailabilityZone": "us-east-1a"}, {"AvailabilityZone": "us-east-1b"}]),
    dict(_DAX, Nodes=[{"AvailabilityZone": "us-east-1a"}, {"AvailabilityZone": "us-east-1a"}]),
    rows=[P + "dynamodb_accelerator_cluster_multi_az"], severity="medium", control="CP-10",
    remediation="Add DAX nodes in at least two Availability Zones.", docs=[D_DAX],
    note="Prowler: PASS when the set of node Availability Zones has more than one member.")
def dax_multi_az(item, index):
    nodes = list_of_objects(absent_or(item, "ClusterArn", "Nodes", [], list))
    zones = sorted({get(n, "AvailabilityZone", str) for n in nodes})
    return result(len(zones) < 2, availability_zones=zones)


# =========================================================================== DLM
def _dlm_index(policies, snapshots=1):
    return indexes(inventory("ebs_snapshot", [{"SnapshotId": "snap-%d" % i} for i in range(snapshots)]), inventory("dlm_lifecycle_policy", policies))


def _dlm(cid, title, rows, severity, typed, note):
    good = {"PolicyId": "policy-1", "State": "ENABLED", "PolicyType": "EBS_SNAPSHOT_MANAGEMENT"}
    extra = {"pass_index": _dlm_index([good]), "fail_index": _dlm_index([] if not typed else [dict(good, PolicyType="IMAGE_MANAGEMENT")]),
             "not_applicable": ANCHOR, "not_applicable_index": _dlm_index([], snapshots=0)}

    @install(cid, "dlm_lifecycle_policy", title, ANCHOR, ANCHOR, rows=rows, severity=severity, control="CP-9", target="scope",
        dependencies=["ebs_snapshot", "dlm_lifecycle_policy"], docs=[D_DLM, "https://docs.aws.amazon.com/ebs/latest/userguide/snapshot-lifecycle.html"],
        remediation="Create an Amazon Data Lifecycle Manager EBS snapshot policy in every region that holds EBS snapshots.", extra=extra, note=note)
    def evaluate(item, index):
        scope = scope_of(item)
        if not complete_items(index, "ebs_snapshot"):
            return "NOT_APPLICABLE", {"scope": scope, "reason": "no EBS snapshots in region"}
        policies = complete_items(index, "dlm_lifecycle_policy")
        if typed:
            policies = [p for p in policies if get(p, "PolicyType", str).startswith("EBS_SNAPSHOT")]
        return result(not policies, scope=scope, policies=[p.get("PolicyId") for p in policies])
    evaluate.__name__ = cid.replace(".", "_")


_dlm("aws.c2b.dlm.policy_exists_with_snapshots", "Region with EBS snapshots has a DLM lifecycle policy", [P + "dlm_ebs_snapshot_lifecycle_policy_exists"],
     "medium", False, "Prowler: regions with EBS snapshots need at least one DLM lifecycle policy of any type; regions without snapshots are NOT_APPLICABLE.")
_dlm("aws.c2b.dlm.ebs_snapshot_policy_with_snapshots", "Region with EBS snapshots has a DLM EBS snapshot policy", [C + "dlm_ebs_snapshot_lifecycle_policy_enabled"],
     "medium", True, "Steampipe: regions with EBS snapshots need a DLM policy whose PolicyType starts with EBS_SNAPSHOT (policy state is not checked).")


# =========================================================================== DMS
def _ep(engine, **settings):
    return {"EndpointArn": EP_ARN, "EndpointType": "source", "EngineName": engine, **settings}


def _engine(item, *engines):
    engine = get(item, "EngineName", str)
    return None if engine in engines else {"engine": engine, "applicable_engines": list(engines)}


@install("aws.c2b.dms.endpoint_ssl", "dms_endpoint", "DMS endpoint does not use SslMode none",
    _ep("postgres", SslMode="verify-full"), _ep("postgres", SslMode="none"),
    rows=[P + "dms_endpoint_ssl_enabled", C + "dms_endpoint_ssl_configured", C + "foundational_security_dms_9"], severity="high", control="SC-8",
    remediation="Set the DMS endpoint SslMode to require, verify-ca or verify-full.", docs=[D_DMS_EP, D_DMS_SH],
    note="Prowler and steampipe: FAIL only when SslMode is none; an omitted SslMode passes in both upstreams.")
def dms_endpoint_ssl(item, index):
    mode = absent_or(item, "EndpointArn", "SslMode", None, str)
    return result(mode == "none", ssl_mode=mode)


@install("aws.c2b.dms.mongodb_auth", "dms_endpoint", "DMS MongoDB endpoint uses authentication",
    _ep("mongodb", MongoDbSettings={"AuthType": "password", "AuthMechanism": "default"}), _ep("mongodb", MongoDbSettings={"AuthType": "no"}),
    rows=[P + "dms_endpoint_mongodb_authentication_enabled"], severity="medium", control="IA-2",
    remediation="Set MongoDbSettings.AuthType to password on the DMS MongoDB endpoint.", docs=[D_DMS_MONGO, D_DMS_SH],
    extra={"not_applicable": _ep("postgres"), "no_settings": _ep("mongodb"), "no_settings_expect": "FAIL"},
    note="Prowler: MongoDB endpoints FAIL when AuthType is no; omitted settings default to no (prowler default). Other engines are NOT_APPLICABLE.")
def dms_mongodb_auth(item, index):
    skip = _engine(item, "mongodb")
    if skip:
        return "NOT_APPLICABLE", skip
    auth = absent_or(item, "EndpointArn", "MongoDbSettings.AuthType", "no", str)
    return result(auth == "no", auth_type=auth)


@install("aws.c2b.dms.neptune_iam_auth", "dms_endpoint", "DMS Neptune endpoint uses IAM authorization",
    _ep("neptune", NeptuneSettings={"IamAuthEnabled": True}), _ep("neptune", NeptuneSettings={"IamAuthEnabled": False}),
    rows=[P + "dms_endpoint_neptune_iam_authorization_enabled", C + "dms_endpoint_neptune_database_iam_authorization_enabled", C + "foundational_security_dms_10"],
    severity="medium", control="IA-2", remediation="Enable NeptuneSettings.IamAuthEnabled on the DMS Neptune endpoint.",
    docs=[D_DMS_NEPTUNE, D_DMS_SH], extra={"not_applicable": _ep("redis"), "unset": _ep("neptune", NeptuneSettings={}), "unset_expect": "FAIL"},
    note="Neptune endpoints only; an omitted IamAuthEnabled inside collected NeptuneSettings is false; missing NeptuneSettings is UNKNOWN.")
def dms_neptune_iam(item, index):
    skip = _engine(item, "neptune")
    if skip:
        return "NOT_APPLICABLE", skip
    settings = get(item, "NeptuneSettings", dict)
    enabled = optional(settings, "IamAuthEnabled", False, bool)
    return result(not enabled, iam_auth_enabled=enabled)


@install("aws.c2b.dms.redis_tls", "dms_endpoint", "DMS Redis endpoint uses ssl-encryption",
    _ep("redis", RedisSettings={"ServerName": "r", "SslSecurityProtocol": "ssl-encryption"}), _ep("redis", RedisSettings={"ServerName": "r", "SslSecurityProtocol": "plaintext"}),
    rows=[P + "dms_endpoint_redis_in_transit_encryption_enabled"], severity="medium", control="SC-8",
    remediation="Set RedisSettings.SslSecurityProtocol to ssl-encryption on the DMS Redis endpoint.", docs=[D_DMS_REDIS, D_DMS_SH],
    extra={"not_applicable": _ep("mongodb"), "default": _ep("redis", RedisSettings={"ServerName": "r"}), "default_expect": "PASS"},
    note="Redis endpoints only; PASS when SslSecurityProtocol is ssl-encryption. Deviation: an omitted SslSecurityProtocol is the documented API "
         "default ssl-encryption (prowler assumes plaintext).")
def dms_redis_tls(item, index):
    skip = _engine(item, "redis")
    if skip:
        return "NOT_APPLICABLE", skip
    protocol = absent_or(item, "RedisSettings.ServerName", "RedisSettings.SslSecurityProtocol", "ssl-encryption", str)
    return result(protocol != "ssl-encryption", ssl_security_protocol=protocol)


_LEVELS = ("LOGGER_SEVERITY_DEFAULT", "LOGGER_SEVERITY_DEBUG", "LOGGER_SEVERITY_DETAILED_DEBUG")


def task_logging(item):
    """(EnableLogging, {component: severity}) from the ReplicationTaskSettings JSON document."""
    get(item, "ReplicationTaskArn", str)
    raw = get(item, "ReplicationTaskSettings")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError as exc:
            raise Unavailable("malformed ReplicationTaskSettings") from exc
    if not isinstance(raw, dict):
        raise Unavailable("malformed ReplicationTaskSettings")
    logging = optional(raw, "Logging", {}, dict)
    enabled = optional(logging, "EnableLogging", False, bool)
    components = {}
    for component in list_of_objects(optional(logging, "LogComponents", [], list)):
        components.setdefault(component.get("Id"), []).append(component.get("Severity"))
    return enabled, components


def _rt(enabled, components):
    return {"ReplicationTaskArn": RT_ARN, "ReplicationTaskSettings": json.dumps(
        {"Logging": {"EnableLogging": enabled, "LogComponents": [{"Id": c, "Severity": s} for c, s in components]}})}


def _dms_logging(cid, side, components, rows):
    title = "DMS replication task logs " + " and ".join(components) + " at default severity or higher"
    good = [(c, "LOGGER_SEVERITY_DEFAULT") for c in components]

    @install(cid, "dms_replication_task", title, _rt(True, good), _rt(True, [(components[0], "LOGGER_SEVERITY_DEBUG"), (components[1], "LOGGER_SEVERITY_WARNING")]),
        rows=rows, severity="medium", control="AU-2",
        remediation="Enable task logging and set " + " and ".join(components) + " to LOGGER_SEVERITY_DEFAULT or more verbose.",
        docs=[D_DMS_TASK, D_DMS_SH], extra={"disabled": _rt(False, good), "disabled_expect": "FAIL"},
        note="Prowler and steampipe: EnableLogging true and both " + side + " components present with severity DEFAULT, DEBUG or DETAILED_DEBUG.")
    def evaluate(item, index):
        enabled, found = task_logging(item)
        missing = [c for c in components if not any(s in _LEVELS for s in found.get(c, []))]
        return result(not enabled or bool(missing), logging_enabled=enabled, missing_components=missing)
    evaluate.__name__ = cid.replace(".", "_")


_dms_logging("aws.c2b.dms.task_source_logging", "source", ["SOURCE_CAPTURE", "SOURCE_UNLOAD"],
    [P + "dms_replication_task_source_logging_enabled", C + "dms_replication_task_source_database_logging_enabled", C + "foundational_security_dms_8"])
_dms_logging("aws.c2b.dms.task_target_logging", "target", ["TARGET_APPLY", "TARGET_LOAD"],
    [P + "dms_replication_task_target_logging_enabled", C + "dms_replication_task_target_database_logging_enabled", C + "foundational_security_dms_7"])


@install("aws.c2b.dms.certificate_not_expired", "dms_certificate", "DMS certificate is not expired",
    {"CertificateArn": CERT_ARN, "ValidToDate": "2026-06-01T00:00:00+00:00"}, {"CertificateArn": CERT_ARN, "ValidToDate": "2025-06-01T00:00:00+00:00"},
    rows=[C + "dms_certificate_not_expired"], severity="medium", control="SC-12",
    remediation="Delete expired DMS certificates and import valid ones for the endpoints that need them.", docs=[D_DMS_CERT],
    extra={"index": {"context": dict(CONTEXT)}},
    note="Steampipe: alarm when ValidToDate < current_date - 1 second; current_date is the snapshot capture date (start of day, UTC).")
def dms_certificate(item, index):
    get(item, "CertificateArn", str)
    valid_to = parse_time(get(item, "ValidToDate"))
    now = clock(item, index)
    cutoff = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(seconds=1)
    return result(valid_to < cutoff, valid_to=valid_to.isoformat())


def world_open(rule):
    """Prowler check_security_group(rule, "-1", any_address=True, all_ports=True)."""
    cidrs = [r.get("CidrIp") for r in list_of_objects(rule.get("IpRanges", []))] + [r.get("CidrIpv6") for r in list_of_objects(rule.get("Ipv6Ranges", []))]
    if not any(c in ("0.0.0.0/0", "::/0") for c in cidrs):
        return False
    return str(rule.get("IpProtocol")) == "-1" or "FromPort" in rule


def _sg_index(cidr):
    return inventory("security_group", [{"GroupId": "sg-1", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": cidr}], "Ipv6Ranges": []}]}])


@install("aws.c2b.dms.public_instance_open_sg", "dms_replication_instance", "Publicly accessible DMS instance is not open to the Internet by its security groups",
    {"ReplicationInstanceArn": RI_ARN, "PubliclyAccessible": True, "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1"}]},
    {"ReplicationInstanceArn": RI_ARN, "PubliclyAccessible": True, "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1"}]},
    rows=[P + "dms_instance_no_public_access"], severity="critical", category="exposure", control="SC-7",
    dependencies=["dms_replication_instance", "security_group"],
    remediation="Disable PubliclyAccessible on the replication instance or remove 0.0.0.0/0 and ::/0 ingress from its security groups.",
    docs=[D_DMS_RI, "https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.Network.html"],
    extra={"pass_index": _sg_index("10.0.0.0/8"), "fail_index": _sg_index("0.0.0.0/0"),
           "private": {"ReplicationInstanceArn": RI_ARN, "PubliclyAccessible": False}, "private_expect": "PASS"},
    note="Prowler: FAIL only when the instance is publicly accessible and an attached security group has an ingress rule open to 0.0.0.0/0 "
         "or ::/0 (all protocols, or any rule with a port range). Public instances without security groups pass.")
def dms_public_open(item, index):
    if not get(item, "PubliclyAccessible", bool):
        return result(False, publicly_accessible=False)
    ids = [get(g, "VpcSecurityGroupId", str) for g in list_of_objects(absent_or(item, "ReplicationInstanceArn", "VpcSecurityGroups", [], list))]
    if not ids:
        return result(False, publicly_accessible=True, security_groups=[])
    open_groups = [get(g, "GroupId", str) for g in security_groups(index, ids)
                   if any(world_open(r) for r in list_of_objects(get(g, "IpPermissions", list)))]
    return result(bool(open_groups), publicly_accessible=True, open_security_groups=open_groups)


# =========================================================================== DocumentDB
def _doc(**extra):
    return {"DBClusterArn": DOC_ARN, "Engine": "docdb", **extra}


def _docdb(item):
    engine = get(item, "Engine", str)
    return None if engine == "docdb" else {"engine": engine, "reason": "not a DocumentDB cluster"}


@install("aws.c2b.docdb.cluster_tls_required", "docdb_cluster", "DocumentDB cluster parameter group requires TLS 1.2 or later",
    _doc(ClusterParameterGroupValues={"tls": "tls1.2+"}), _doc(ClusterParameterGroupValues={"tls": "enabled"}),
    rows=[C + "docdb_cluster_encryption_in_transit_enabled", C + "foundational_security_docdb_6"], severity="medium", control="SC-8",
    remediation="Set the tls parameter of the DocumentDB cluster parameter group to tls1.2+, tls1.3+ or fips-140-3.",
    docs=[D_DOCDB_TLS, D_DOCDB_SH], extra={"not_applicable": _doc(Engine="aurora-mysql", ClusterParameterGroupValues={})},
    note="Steampipe and Security Hub DocumentDB.6: FAIL when the cluster parameter group tls value is disabled or enabled. "
         "Needs ClusterParameterGroupValues.tls (DescribeDBClusterParameters); a missing tls value is UNKNOWN.")
def docdb_tls(item, index):
    skip = _docdb(item)
    if skip:
        return "NOT_APPLICABLE", skip
    tls = get(item, "ClusterParameterGroupValues.tls", str)
    return result(tls in ("disabled", "enabled"), tls=tls)


flag("aws.c2b.docdb.instance_storage_encrypted", "docdb_instance", "DocumentDB instance storage is encrypted", "StorageEncrypted",
    rows=[C + "docdb_cluster_instance_encryption_at_rest_enabled"], severity="medium", control="SC-28", sentinel="DBInstanceArn",
    base={"DBInstanceArn": DOC_INST_ARN, "Engine": "docdb"}, applies=_docdb, na_item={"DBInstanceArn": DOC_INST_ARN, "Engine": "postgres", "StorageEncrypted": False},
    remediation="Create DocumentDB clusters with storage encryption; restore an encrypted snapshot copy to encrypt an existing cluster.",
    docs=[D_DOCDB_INST], note="Steampipe: instance StorageEncrypted; non-docdb engines returned by the shared RDS API are NOT_APPLICABLE.")


_CSNAP = "Attributes.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes"


def _snap(values, engine="docdb"):
    return {"DBClusterSnapshotArn": ARN_PREFIX.format("rds") + "cluster-snapshot:s1", "Engine": engine,
            **nest(_CSNAP, [{"AttributeName": "restore", "AttributeValues": values}])}


def _snap_values(item):
    rows = list_of_objects(get(item, _CSNAP, list))
    return [strings(get(r, "AttributeValues", list), "AttributeValues") for r in rows]


@install("aws.c2b.docdb.snapshot_restore_not_all_exact", "rds_cluster_snapshot", "DocumentDB cluster snapshot restore attribute does not include public access",
    _snap([]), _snap(["all"]), rows=[C + "docdb_cluster_snapshot_restrict_public_access", C + "foundational_security_docdb_3"],
    severity="critical", category="exposure", control="AC-3",
    remediation="Remove 'all' from the DocumentDB snapshot restore attribute (ModifyDBClusterSnapshotAttribute ValuesToRemove=all).",
    docs=[D_CSNAP_ATTR, D_DOCDB_SH], extra={"not_applicable": _snap([], engine="aurora-mysql")},
    note="The pinned Steampipe row used exact [\"all\"] equality. DocumentDB's DescribeDBClusterSnapshotAttributes API defines a restore attribute containing 'all' as public even when account IDs are also present; non-docdb snapshots are NOT_APPLICABLE.")
def docdb_snap_exact(item, index):
    skip = _docdb(item)
    if skip:
        return "NOT_APPLICABLE", skip
    rows = list_of_objects(get(item, _CSNAP, list))
    attrs = [(get(row, "AttributeName", str), strings(get(row, "AttributeValues", list), "AttributeValues")) for row in rows]
    if not any(name == "restore" for name, _ in attrs):
        return unknown("snapshot restore attribute missing")
    public = any(name == "restore" and "all" in values for name, values in attrs)
    return result(public, public_restore_attribute=public)


@install("aws.c2b.docdb.snapshot_not_public_prowler", "rds_cluster_snapshot", "DocumentDB cluster snapshot is not publicly shared",
    _snap(["222222222222"]), _snap(["all", "222222222222"]), rows=[P + "documentdb_cluster_public_snapshot"],
    severity="critical", category="exposure", control="AC-3",
    remediation="Remove 'all' from the DocumentDB snapshot restore attribute.", docs=[D_CSNAP_ATTR],
    extra={"not_applicable": _snap([], engine="neptune")}, note="Prowler: 'all' in any attribute's AttributeValues.")
def docdb_snap_public(item, index):
    skip = _docdb(item)
    if skip:
        return "NOT_APPLICABLE", skip
    return result(public := any("all" in values for values in _snap_values(item)), public_attribute=public)


@install("aws.c2b.documentdb.backup_retention_7", "docdb_cluster", "DocumentDB cluster retains automated backups at least 7 days",
    _doc(BackupRetentionPeriod=7), _doc(BackupRetentionPeriod=1), rows=[P + "documentdb_cluster_backup_enabled"],
    severity="medium", control="CP-9", remediation="Set the DocumentDB cluster BackupRetentionPeriod to 7 days or more.",
    docs=[D_DOCDB], extra={"not_applicable": _doc(Engine="postgres", BackupRetentionPeriod=0)},
    note="Prowler: BackupRetentionPeriod >= minimum_snapshot_retention_period (default 7). Ported rather than merged into aws.b.docdb.* "
         "because those natives do not exclude the non-docdb engines the shared RDS API returns.")
def docdb_backup(item, index):
    skip = _docdb(item)
    if skip:
        return "NOT_APPLICABLE", skip
    days = get(item, "BackupRetentionPeriod", int)
    return result(days < 7, backup_retention_period=days)


@install("aws.c2b.documentdb.cluster_log_exports", "docdb_cluster", "DocumentDB cluster exports audit and profiler logs to CloudWatch",
    _doc(EnabledCloudwatchLogsExports=["audit", "profiler"]), _doc(EnabledCloudwatchLogsExports=["audit"]),
    rows=[P + "documentdb_cluster_cloudwatch_log_export"], severity="medium", control="AU-2",
    remediation="Enable the audit and profiler CloudWatch log exports on the DocumentDB cluster (and audit_logs / profiler parameters).",
    docs=[D_DOCDB, "https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html"],
    extra={"not_applicable": _doc(Engine="mysql"), "none": _doc(), "none_expect": "FAIL"},
    note="Prowler: PASS only when both audit and profiler are exported; an omitted EnabledCloudwatchLogsExports is no exports.")
def docdb_log_exports(item, index):
    skip = _docdb(item)
    if skip:
        return "NOT_APPLICABLE", skip
    exports = strings(absent_or(item, "DBClusterArn", "EnabledCloudwatchLogsExports", [], list), "EnabledCloudwatchLogsExports")
    return result(not {"audit", "profiler"} <= set(exports), exports=exports)


for _cid, _path, _title, _row, _remediation, _control in (
        ("deletion_protection", "DeletionProtection", "DocumentDB cluster has deletion protection", "documentdb_cluster_deletion_protection",
         "Enable DeletionProtection on the DocumentDB cluster.", "CP-9"),
        ("multi_az", "MultiAZ", "DocumentDB cluster has instances in multiple Availability Zones", "documentdb_cluster_multi_az_enabled",
         "Add a replica instance in another Availability Zone to the DocumentDB cluster.", "CP-10"),
        ("storage_encrypted", "StorageEncrypted", "DocumentDB cluster storage is encrypted", "documentdb_cluster_storage_encrypted",
         "Create DocumentDB clusters with storage encryption; restore an encrypted snapshot copy to encrypt an existing cluster.", "SC-28")):
    flag("aws.c2b.documentdb." + _cid, "docdb_cluster", _title, _path, rows=[P + _row], severity="medium", control=_control,
        sentinel="DBClusterArn", base={"DBClusterArn": DOC_ARN, "Engine": "docdb"}, applies=_docdb,
        na_item={"DBClusterArn": DOC_ARN, "Engine": "aurora-postgresql", _path: False}, remediation=_remediation, docs=[D_DOCDB],
        note="Prowler DocumentDB service lists engine=docdb clusters only; other engines are NOT_APPLICABLE here.")


# =========================================================================== DRS
@install("aws.c2b.drs.region_has_job", "drs_source_server", "Configured DRS source servers report continuous replication",
    ANCHOR, ANCHOR, rows=[P + "drs_job_exist", C + "drs_job_enabled"], severity="medium", control="CP-10", target="scope",
    dependencies=["drs_source_server"], remediation="Review the affected DRS source server's replication state and restore continuous replication; separately validate recovery readiness with the workload owner.",
    docs=[D_DRS, "https://docs.aws.amazon.com/drs/latest/APIReference/API_DataReplicationInfo.html",
        "https://docs.aws.amazon.com/drs/latest/userguide/recovery-dashboard.html"],
    extra={"pass_index": inventory("drs_source_server", [{"sourceServerID": "s-00000000000000001", "dataReplicationInfo": {"dataReplicationState": "CONTINUOUS"}}]),
        "fail_index": inventory("drs_source_server", [{"sourceServerID": "s-00000000000000001", "dataReplicationInfo": {"dataReplicationState": "STALLED"}}]),
        "not_applicable": ANCHOR, "not_applicable_index": inventory("drs_source_server", [])},
    note="Intentional semantic correction: pinned Prowler/Steampipe count historical DescribeJobs records, which cannot establish current enablement or recovery readiness. A complete DescribeSourceServers inventory with configured sources all reporting CONTINUOUS passes this narrower replication-state check; STOPPED/STALLED/DISCONNECTED fails, intermediate/unread states are UNKNOWN, and no sources are NOT_APPLICABLE absent an approved protection scope. Recovery drills, launch settings, and workload RTO remain manual.")
def drs_jobs(item, index):
    scope = scope_of(item)
    sources = complete_items(index, "drs_source_server")
    manual = "Recovery drills, launch settings, and workload RTO require separate owner review."
    if not sources:
        return "NOT_APPLICABLE", {"scope": scope, "source_servers": 0,
            "reason": "No DRS source servers are configured in this region; required protection scope is not established.",
            "manual_readiness": manual}
    counts, impaired, uncertain = {}, [], []
    for source in sources:
        try:
            source_id = get(source, "sourceServerID", str)
            state = get(source, "dataReplicationInfo.dataReplicationState", str)
        except Unavailable:
            counts["UNREAD"] = counts.get("UNREAD", 0) + 1
            continue
        counts[state] = counts.get(state, 0) + 1
        if state in {"STOPPED", "STALLED", "DISCONNECTED"}:
            impaired.append(source_id)
        elif state != "CONTINUOUS":
            uncertain.append(source_id)
    evidence = {"scope": scope, "source_servers": len(sources), "replication_states": counts,
        "impaired_source_ids": impaired[:5], "uncertain_source_ids": uncertain[:5],
        "manual_readiness": manual}
    if impaired:
        return result(True, **evidence)
    if uncertain or counts.get("UNREAD"):
        return unknown("Configured source replication is not proven continuous", **evidence)
    return result(False, **evidence)


# =========================================================================== DynamoDB
def _aas_index(dimensions, name="t1"):
    return inventory("appautoscaling_target", [{"ServiceNamespace": "dynamodb", "ResourceId": "table/" + name, "ScalableDimension": d} for d in dimensions])


_RW = ("dynamodb:table:ReadCapacityUnits", "dynamodb:table:WriteCapacityUnits")


@install("aws.c2b.dynamodb.capacity_autoscaling", "dynamodb_table", "Provisioned DynamoDB table auto scales read and write capacity",
    _table(BillingModeSummary={"BillingMode": "PROVISIONED"}), _table(),
    rows=[P + "dynamodb_table_autoscaling_enabled", C + "dynamodb_table_auto_scaling_enabled", C + "foundational_security_dynamodb_1"],
    severity="medium", control="CP-10", dependencies=["dynamodb_table", "appautoscaling_target"],
    remediation="Use on-demand capacity or register read and write capacity scalable targets for the table with Application Auto Scaling.",
    docs=[D_DDB, D_AAS, D_DDB_SH],
    extra={"pass_index": _aas_index(_RW), "fail_index": _aas_index(_RW[:1]),
           "on_demand": _table(BillingModeSummary={"BillingMode": "PAY_PER_REQUEST"}), "on_demand_expect": "PASS"},
    note="PAY_PER_REQUEST passes; otherwise (an omitted BillingModeSummary is PROVISIONED) both table read and write capacity scalable "
         "targets (ResourceId table/<name>) must exist. Index (GSI) capacity is not required, as upstream.")
def table_autoscaling(item, index):
    body = _table_body(item)
    mode = absent_or(body, "TableArn", "BillingModeSummary.BillingMode", "PROVISIONED", str)
    if mode == "PAY_PER_REQUEST":
        return result(False, billing_mode=mode)
    resource = "table/" + get(body, "TableName", str)
    dims = {get(t, "ScalableDimension", str) for t in complete_items(index, "appautoscaling_target")
            if t.get("ServiceNamespace") == "dynamodb" and t.get("ResourceId") == resource}
    missing = [d for d in _RW if d not in dims]
    return result(bool(missing), billing_mode=mode, missing_dimensions=missing)


@install("aws.c2b.dynamodb.sse_kms", "dynamodb_table", "DynamoDB table is encrypted with a KMS key",
    _table(SSEDescription={"Status": "ENABLED", "SSEType": "KMS", "KMSMasterKeyArn": KMS_ARN}), _table(),
    rows=[P + "dynamodb_tables_kms_cmk_encryption_enabled"], severity="medium", control="SC-28",
    remediation="Switch the table encryption to an AWS managed or customer managed KMS key (SSESpecification SSEType KMS).",
    docs=[D_DDB_SSE], note="Prowler: PASS when SSEType is KMS; an omitted SSEDescription is the DEFAULT AWS owned key and fails.")
def table_sse_kms(item, index):
    sse = absent_or(_table_body(item), "TableArn", "SSEDescription.SSEType", None, str)
    return result(sse != "KMS", sse_type=sse or "DEFAULT")


def _ddb_policy(statement):
    return {"collection_status": "collected", "Policy": json.dumps({"Version": "2012-10-17", "Statement": [statement]})}


_DDB_STMT = {"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": TABLE_ARN}


@install("aws.c2b.dynamodb.policy_not_cross_account", "dynamodb_table", "DynamoDB table resource policy does not allow other accounts",
    dict(_table(), ResourcePolicy=_ddb_policy(dict(_DDB_STMT, Principal={"AWS": "arn:aws:iam::" + ACCOUNT + ":root"}))),
    dict(_table(), ResourcePolicy=_ddb_policy(dict(_DDB_STMT, Principal={"AWS": "arn:aws:iam::222222222222:root"}))),
    rows=[P + "dynamodb_table_cross_account_access"], severity="medium", category="exposure", control="AC-3",
    remediation="Remove other-account and wildcard principals from the table resource policy, or restrict them with conditions.",
    docs=[D_DDB_POLICY], extra={"index": {"context": dict(CONTEXT)}, "not_applicable": dict(_table(), ResourcePolicy=ABSENT)},
    note="Prowler is_policy_public(policy, audited account, is_cross_account_allowed=False). A table without a resource policy is NOT_APPLICABLE.")
def table_cross_account(item, index):
    get(_table_body(item), "TableArn", str)
    body = detail(item, "ResourcePolicy")
    if body is None:
        return "NOT_APPLICABLE", {"reason": "table has no resource policy"}
    statements = policy_document(get(body, "Policy"))
    return result(public := is_policy_public(statements, account(index), is_cross_account_allowed=False), cross_account_policy=public)


# =========================================================================== ElastiCache
def _ec(**extra):
    return {"ARN": EC_ARN, "CacheClusterId": "c1-001", "Engine": "redis", "EngineVersion": "7.1", **extra}


def _net_index(public):
    route = [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}] if public else [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}]
    return indexes(inventory("elasticache_subnet_group", [{"CacheSubnetGroupName": "g1", "Subnets": [{"SubnetIdentifier": "subnet-1"}]}]),
                   inventory("subnet", [{"SubnetId": "subnet-1", "VpcId": "vpc-1"}]),
                   inventory("route_table", [{"RouteTableId": "rtb-1", "VpcId": "vpc-1", "Associations": [{"SubnetId": "subnet-1"}], "Routes": route}]))


def _cache_subnets(item, index):
    name = absent_or(item, "ARN", "CacheSubnetGroupName", None, str)
    if name is None:
        return None, []
    groups = [g for g in complete_items(index, "elasticache_subnet_group") if g.get("CacheSubnetGroupName") == name]
    if len(groups) != 1:
        raise Unavailable("cache subnet group join unresolved: " + name)
    return name, [get(s, "SubnetIdentifier", str) for s in list_of_objects(get(groups[0], "Subnets", list))]


def _ec_public(cid, title, rows, classify, note):
    @install(cid, "elasticache_cluster", title, _ec(CacheSubnetGroupName="g1"), _ec(CacheSubnetGroupName="g1"), rows=rows, severity="medium",
        category="exposure", control="SC-7", dependencies=["elasticache_cluster", "elasticache_subnet_group", "subnet", "route_table"],
        remediation="Place the cache cluster in a subnet group whose subnets have no default route to an internet gateway.",
        docs=[D_EC_CLUSTER, D_EC_SUBNET], extra={"pass_index": _net_index(False), "fail_index": _net_index(True)}, note=note)
    def evaluate(item, index):
        name, subnets = _cache_subnets(item, index)
        public = [s for s in subnets if classify(index, s)]
        return result(bool(public), subnet_group=name, public_subnets=public)
    evaluate.__name__ = cid.replace(".", "_")


_ec_public("aws.c2b.elasticache.cluster_public_subnet_prowler", "ElastiCache cluster does not use public subnets", [P + "elasticache_cluster_uses_public_subnet"],
    subnet_is_public_prowler, "Prowler: a subnet is public when its effective route table has 0.0.0.0/0 to an igw-. Clusters without a subnet group pass.")
alias_check("aws.c2b.elasticache.cluster_public_subnet", "aws.c2b.elasticache.cluster_public_subnet_prowler")


@install("aws.c2b.elasticache.cluster_no_default_subnet_group", "elasticache_cluster", "ElastiCache cluster does not use the default subnet group",
    _ec(CacheSubnetGroupName="g1"), _ec(CacheSubnetGroupName="default"),
    rows=[C + "elasticache_cluster_no_default_subnet_group", C + "foundational_security_elasticache_7"], severity="medium", control="SC-7",
    remediation="Create a dedicated cache subnet group and recreate or migrate the cluster into it.", docs=[D_EC_CLUSTER, D_EC_SH],
    extra={"absent": _ec()}, note="Steampipe: alarm when CacheSubnetGroupName is default; a cluster without a subnet group passes.")
def ec_default_subnet_group(item, index):
    name = absent_or(item, "ARN", "CacheSubnetGroupName", None, str)
    return result(name == "default", subnet_group=name)


_RG = {"ARN": RG_ARN, "ReplicationGroupId": "rg1"}

flag("aws.c2b.elasticache.rg_auto_minor_version_upgrade", "elasticache_replication_group", "ElastiCache replication group auto-applies minor version upgrades",
    "AutoMinorVersionUpgrade", rows=[P + "elasticache_redis_cluster_auto_minor_version_upgrades"], severity="high", control="SI-2",
    sentinel="ARN", base=_RG, remediation="Enable AutoMinorVersionUpgrade on the replication group.", docs=[D_EC_RG])
flag("aws.c2b.elasticache.rg_multi_az", "elasticache_replication_group", "ElastiCache replication group has Multi-AZ enabled",
    "MultiAZ", rows=[P + "elasticache_redis_cluster_multi_az_enabled"], severity="medium", control="CP-10", sentinel="ARN", base=_RG,
    good="enabled", bad="disabled", expected=str, remediation="Enable Multi-AZ (requires automatic failover) on the replication group.", docs=[D_EC_RG])


@install("aws.c2b.elasticache.rg_backup_retention_7", "elasticache_replication_group", "ElastiCache replication group retains snapshots at least 7 days",
    dict(_RG, SnapshotRetentionLimit=7), dict(_RG, SnapshotRetentionLimit=1), rows=[P + "elasticache_redis_cluster_backup_enabled"],
    severity="high", control="CP-9", remediation="Set SnapshotRetentionLimit to 7 days or more on the replication group.", docs=[D_EC_RG],
    extra={"unset": dict(_RG), "unset_expect": "FAIL"},
    note="Prowler: SnapshotRetentionLimit >= minimum_snapshot_retention_period (default 7); omitted means automatic backups are disabled (0).")
def rg_backup_7(item, index):
    days = absent_or(item, "ARN", "SnapshotRetentionLimit", 0, int)
    return result(days < 7, snapshot_retention_limit=days)


@install("aws.c2b.elasticache.rg_backup_retention_15", "elasticache_replication_group", "ElastiCache replication group retains snapshots at least 15 days",
    dict(_RG, SnapshotRetentionLimit=15), dict(_RG, SnapshotRetentionLimit=7),
    rows=[C + "elasticache_redis_cluster_automatic_backup_retention_15_days", C + "foundational_security_elasticache_1"], severity="medium",
    control="CP-9", remediation="Set SnapshotRetentionLimit to 15 days or more on the replication group.", docs=[D_EC_RG, D_EC_SH],
    note="The pinned Steampipe NULL comparison passed an omitted SnapshotRetentionLimit. ElastiCache CreateReplicationGroup defaults an omitted retention limit to zero (backups disabled); a missing field can be interpreted as zero only on a complete DescribeReplicationGroups response.")
def rg_backup_15(item, index):
    get(item, "ARN", str)
    if "SnapshotRetentionLimit" in item or "SnapshotRetentionLimit" in item.get("_coverage", {}):
        days = get(item, "SnapshotRetentionLimit", int)
    else:
        provenance = optional(item, "_provenance", {}, dict)
        if (provenance.get("operation") != "elasticache:DescribeReplicationGroups" or
                provenance.get("native_response_complete") is not True):
            return unknown("snapshot retention omitted from an unverified replication-group representation")
        days = 0
    if days < 0:
        return unknown("invalid snapshot retention value", snapshot_retention_limit=days)
    return result(days < 15, snapshot_retention_limit=days)


def engine_version(value):
    try:
        return tuple(int(part) for part in text(value).split("."))
    except ValueError as exc:
        raise Unavailable("non-numeric engine version") from exc


def _members_index(version):
    return inventory("elasticache_cluster", [_ec(ReplicationGroupId="rg1", EngineVersion=version)])


@install("aws.c2b.elasticache.redis_auth_pre6", "elasticache_replication_group", "ElastiCache replication group older than 6.0 uses Redis AUTH",
    dict(_RG, AuthTokenEnabled=True), dict(_RG, AuthTokenEnabled=False),
    rows=[P + "elasticache_redis_replication_group_auth_enabled", C + "elasticache_replication_group_redis_auth_enabled", C + "foundational_security_elasticache_6"],
    severity="medium", control="IA-2", dependencies=["elasticache_replication_group", "elasticache_cluster"],
    remediation="Enable an AUTH token on replication groups running Redis before 6.0, or upgrade to 6.0+ and use RBAC user groups.",
    docs=[D_EC_RG, D_EC_AUTH, D_EC_SH],
    extra={"pass_index": _members_index("5.0.6"), "fail_index": _members_index("5.0.6"),
           "not_applicable": dict(_RG, AuthTokenEnabled=False), "not_applicable_index": _members_index("6.2")},
    note="Engine version of the member clusters (joined by ReplicationGroupId); any member below 6.0 requires AuthTokenEnabled. "
         "Groups whose members are all 6.0+ are NOT_APPLICABLE (steampipe skip, prowler MANUAL ACL review). No member found is UNKNOWN.")
def redis_auth(item, index):
    group = get(item, "ReplicationGroupId", str)
    versions = [get(c, "EngineVersion", str) for c in complete_items(index, "elasticache_cluster") if c.get("ReplicationGroupId") == group]
    if not versions:
        raise Unavailable("no member cache clusters for replication group " + group)
    if all(engine_version(v) >= (6, 0) for v in versions):
        return "NOT_APPLICABLE", {"engine_versions": sorted(set(versions)), "reason": "Redis 6.0+ uses RBAC"}
    enabled = absent_or(item, "ARN", "AuthTokenEnabled", False, bool)
    return result(not enabled, engine_versions=sorted(set(versions)), auth_token_enabled=enabled)


def _kms_index(enabled=True):
    return inventory("kms_key", [{"Metadata": {"KeyMetadata": {"Arn": KMS_ARN, "KeyId": "k1", "KeyManager": "CUSTOMER", "Enabled": enabled}}}])


@install("aws.c2b.elasticache.cmk_enabled", "elasticache_replication_group", "ElastiCache replication group is encrypted at rest with an enabled KMS key",
    dict(_RG, AtRestEncryptionEnabled=True, KmsKeyId=KMS_ARN), dict(_RG, AtRestEncryptionEnabled=True, KmsKeyId=KMS_ARN),
    rows=[C + "elasticache_replication_group_encryption_at_rest_enabled_with_kms_cmk"], severity="medium", control="SC-28",
    dependencies=["elasticache_replication_group", "kms_key"],
    remediation="Create the replication group with at-rest encryption and a KMS key (KmsKeyId), and keep that key enabled.", docs=[D_EC_RG],
    extra={"pass_index": _kms_index(True), "fail_index": _kms_index(False),
           "default_key": dict(_RG, AtRestEncryptionEnabled=True), "default_key_index": _kms_index(True),
           "plain": dict(_RG, AtRestEncryptionEnabled=False), "plain_index": _kms_index(True), "plain_expect": "FAIL"},
    note="Steampipe: alarm when at-rest encryption is off, KmsKeyId is unset, or the joined KMS key is disabled. An unresolved key join "
         "(for example a key in another account) is UNKNOWN instead of alarm. KeyManager is not checked, as upstream.")
def rg_cmk(item, index):
    if not get(item, "AtRestEncryptionEnabled", bool):
        return result(True, at_rest_encryption=False)
    key = absent_or(item, "ARN", "KmsKeyId", None, str)
    if not key:
        return result(True, kms_key_id=None)
    matches = [get(k, "Metadata.KeyMetadata", dict) for k in complete_items(index, "kms_key")]
    matches = [m for m in matches if key in (m.get("Arn"), m.get("KeyId"))]
    if len(matches) != 1:
        raise Unavailable("KMS key join unresolved: " + key)
    enabled = get(matches[0], "Enabled", bool)
    return result(not enabled, kms_key_id=key, key_enabled=enabled)


# =========================================================================== dispositions
_SAME = "Identical predicate: "

MERGED = {
    P + "backup_vaults_exist": (["aws.b.backup_vault.regional_presence"],
        _SAME + "prowler FAILs a region whose complete backup vault inventory is empty; the native scope check does the same."),
    X + "dms_replication_instance_not_publicly_accessible": (["aws.b.dms.no_public_instance"],
        _SAME + "aws-perimeter alarms when the replication instance has PubliclyAccessible true, as the native does."),
    C + "dynamodb_table_deletion_protection_enabled": (["aws.b.dynamodb.deletion_protection"],
        _SAME + "steampipe alarms unless Table.DeletionProtectionEnabled is true, as the native does."),
    C + "foundational_security_dynamodb_6": (["aws.b.dynamodb.deletion_protection"],
        _SAME + "same query as dynamodb_table_deletion_protection_enabled (DeletionProtectionEnabled true)."),
    P + "elasticache_redis_cluster_automatic_failover_enabled": (["aws.b.elasticache.automatic_failover"],
        _SAME + "prowler PASSes replication groups whose AutomaticFailover is enabled, as the native does."),
    P + "elasticache_redis_cluster_in_transit_encryption_enabled": (["aws.b.elasticache.in_transit"],
        _SAME + "prowler PASSes replication groups with TransitEncryptionEnabled true, as the native does."),
    P + "elasticache_redis_cluster_rest_encryption_enabled": (["aws.b.elasticache.at_rest"],
        _SAME + "prowler PASSes replication groups with AtRestEncryptionEnabled true, as the native does."),
}

MANUAL = {}

_MONGO = {"classification": "invalid_predicate",
    "reason": "The pinned query (source endpoints with MongoDbSettings) alarms when AuthMechanism is 'default' and passes otherwise, without "
              "reading AuthType. AWS documents 'default' as a valid mechanism (SCRAM_SHA_1 on MongoDB 3.x+, unused when AuthType is no) and "
              "authentication itself as AuthType (no | password), so password-authenticated endpoints alarm and AuthType=no endpoints can pass. "
              "Corrected native predicate: AuthType is not 'no'.",
    "replacement": ["aws.c2b.dms.mongodb_auth"], "docs": [D_DMS_MONGO, D_DMS_SH]}
_REDIS = {"classification": "invalid_predicate",
    "reason": "The pinned query (target endpoints with RedisSettings) passes only when SslCaCertificateArn is set. AWS documents SslCaCertificateArn as "
              "optional ('If an ARN isn't given for a CA, DMS uses the Amazon root CA'), so TLS endpoints trusting the Amazon root CA are "
              "flagged. Corrected native predicate: SslSecurityProtocol is ssl-encryption (the documented default).",
    "replacement": ["aws.c2b.dms.redis_tls"], "docs": [D_DMS_REDIS, D_DMS_SH]}
_DOCLOG = {"classification": "invalid_predicate",
    "reason": "The pinned query requires instance EnabledCloudwatchLogsExports to contain 'error' and 'slowquery', which are not DocumentDB log "
              "types: DocumentDB exports audit and profiler logs at cluster level, and Security Hub DocumentDB.4 checks that the cluster "
              "publishes audit logs. Corrected native predicate: cluster exports audit and profiler.",
    "replacement": ["aws.c2b.documentdb.cluster_log_exports"],
    "docs": [D_DOCDB_SH, "https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html"]}

REJECTED = {
    C + "dms_endpoint_mongo_db_authentication_enabled": _MONGO,
    C + "foundational_security_dms_11": dict(_MONGO),
    C + "dms_endpoint_redis_tls_enabled": _REDIS,
    C + "foundational_security_dms_12": dict(_REDIS),
    C + "docdb_cluster_instance_logging_enabled": _DOCLOG,
    C + "foundational_security_docdb_4": dict(_DOCLOG),
}
