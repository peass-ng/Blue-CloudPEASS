"""Database/file-service metadata checks, with explicit joins and API eligibility."""
from . import result, unknown
from .facts import get, complete_items, list_of_objects
from .aws_b_core import install, scalar, threshold, SOURCES


for cid, kind, path, query, title in [
    ("aws.b.efs.at_rest_encryption", "efs_file_system", "Encrypted", "efs_file_system_encrypt_data_at_rest", "EFS file system encryption is enabled"),
    ("aws.b.docdb.storage_encryption", "docdb_cluster", "StorageEncrypted", "docdb_cluster_encryption_at_rest_enabled", "DocumentDB cluster storage encryption is enabled"),
    ("aws.b.docdb.deletion_protection", "docdb_cluster", "DeletionProtection", "docdb_cluster_deletion_protection_enabled", "DocumentDB cluster deletion protection is enabled"),
    ("aws.b.mq.automatic_minor_upgrade", "mq_broker", "Configuration.AutoMinorVersionUpgrade", "mq_broker_auto_minor_version_upgrade_enabled", "MQ broker automatic minor upgrade is enabled"),
]:
    scalar(cid, kind, path, True, False, title, query)
threshold("aws.b.docdb.seven_day_backups", "docdb_cluster", "BackupRetentionPeriod", 7, 7, 6, "DocumentDB cluster automatic backups are retained at least seven days", "docdb_cluster_backup_retention_period_7_days")


@install("aws.b.efs.customer_managed_key", "efs_file_system", "EFS encryption uses an enabled customer-managed KMS key", {"Encrypted": True, "KmsKeyId": "arn:aws:kms:us-east-1:111111111111:key/custom"}, {"Encrypted": False}, query="efs_file_system_encrypted_with_cmk", dependencies=["efs_file_system", "kms_key"], extra={"index": {"collections": {"kms_key": [{"status": "collected"}]}, "kms_key": [{"data": {"Metadata": {"KeyMetadata": {"Arn": "arn:aws:kms:us-east-1:111111111111:key/custom", "KeyManager": "CUSTOMER", "Enabled": True}}}}]}})
def customer_key(item, index):
    encrypted = get(item, "Encrypted", bool)
    if not encrypted:
        return result(True, encrypted=False)
    keys = complete_items(index, "kms_key")
    requested = get(item, "KmsKeyId", str)
    matches = []
    for key in keys:
        metadata = get(key, "Metadata.KeyMetadata", dict)
        if get(metadata, "Arn", str) == requested:
            matches.append(metadata)
    if len(matches) != 1:
        return unknown("KMS key join unresolved or ambiguous", key_reference=requested)
    manager = get(matches[0], "KeyManager", str)
    enabled = get(matches[0], "Enabled", bool)
    if manager not in ("CUSTOMER", "AWS"):
        return unknown("unknown KMS key manager")
    return result(not enabled or manager != "CUSTOMER", encrypted=encrypted, key_reference=requested, key_manager=manager, key_enabled=enabled)


for _engine, _suffix, _query in [("aurora-mysql", "mysql_copy_snapshot_tags", "rds_db_cluster_aurora_mysql_copy_tags_to_snapshot_enabled"), ("aurora-postgresql", "postgres_copy_snapshot_tags", "rds_db_cluster_aurora_postgres_copy_tags_to_snapshot_enabled")]:
    def _copy_tags(engine, suffix, query):
        @install("aws.b.aurora." + suffix, "rds_cluster", "Matching Aurora engine copies tags to snapshots", {"Engine": engine, "CopyTagsToSnapshot": True}, {"Engine": engine, "CopyTagsToSnapshot": False}, query=query, extra={"not_applicable": {"Engine": "other"}})
        def evaluate(item, index):
            actual = get(item, "Engine", str)
            if actual != engine:
                return "NOT_APPLICABLE", {"engine": actual, "required_engine": engine}
            copied = get(item, "CopyTagsToSnapshot", bool)
            return result(not copied, engine=actual, copy_tags_to_snapshot=copied)
    _copy_tags(_engine, _suffix, _query)


@install("aws.b.aurora.mysql_audit_export", "rds_cluster", "Aurora MySQL cluster exports audit logs", {"Engine": "aurora-mysql", "EnabledCloudwatchLogsExports": ["audit"]}, {"Engine": "aurora-mysql", "EnabledCloudwatchLogsExports": []}, query="rds_db_cluster_aurora_mysql_publish_audit_log_to_cloudwatch", extra={"not_applicable": {"Engine": "postgres"}})
def audit_export(item, index):
    engine = get(item, "Engine", str)
    if engine != "aurora-mysql":
        return "NOT_APPLICABLE", {"engine": engine}
    exports = get(item, "EnabledCloudwatchLogsExports", list)
    if any(not isinstance(name, str) for name in exports):
        return unknown("malformed log export types")
    return result("audit" not in exports, exports=exports)


# The source UNION assesses both relation families; neither is silently omitted.
for _kind in ("rds_instance", "rds_cluster"):
    def _ports(kind):
        path = "Endpoint.Port" if kind == "rds_instance" else "Port"
        good = {"Engine": "postgres", "Endpoint": {"Port": 15432}} if kind == "rds_instance" else {"Engine": "postgres", "Port": 15432}
        bad = {"Engine": "postgres", "Endpoint": {"Port": 5432}} if kind == "rds_instance" else {"Engine": "postgres", "Port": 5432}
        cid = "aws.b." + kind + ".nondefault_port_policy"
        @install(cid, kind, "RDS database endpoint avoids the pinned engine-default port policy", good, bad, severity="low")
        def evaluate(item, index):
            engine = get(item, "Engine", str)
            port = get(item, path, int)
            if not 1 <= port <= 65535:
                return unknown("invalid endpoint port")
            # Preserve the query's disjunction and order, including Aurora names.
            failed = ((any(word in engine for word in ("aurora", "mysql", "mariadb")) and port == 3306)
                or ("postgres" in engine and port == 5432) or (engine.startswith("oracle") and port == 1521)
                or (engine.startswith("sqlserver") and port == 1433))
            return result(failed, engine=engine, endpoint_port=port, semantics="Obscurity policy only; changing a port does not establish isolation or authentication strength.")
        SOURCES.setdefault("rds_db_instance_and_cluster_no_default_port", []).append(cid)
    _ports(_kind)
