"""Pinned database and file-system settings, evaluated without provider I/O."""
from . import result, unknown
from .facts import get
from .aws_b_core import install, scalar, threshold
from .aws_b_core import IDS as ALL_IDS

_previous_ids = set(ALL_IDS)


for _kind, _name, _field, _query in (
    ("rds_instance", "minor_upgrade", "AutoMinorVersionUpgrade", "rds_db_instance_automatic_minor_version_upgrade_enabled"),
    ("rds_instance", "iam_authentication", "IAMDatabaseAuthenticationEnabled", "rds_db_instance_iam_authentication_enabled"),
    ("rds_cluster", "iam_authentication", "IAMDatabaseAuthenticationEnabled", "rds_db_cluster_iam_authentication_enabled"),
    ("rds_cluster", "multiple_az", "MultiAZ", "rds_db_cluster_multiple_az_enabled"),
    ("rds_instance", "snapshot_tags", "CopyTagsToSnapshot", "rds_db_instance_copy_tags_to_snapshot_enabled"),
    ("neptune_cluster", "storage_encryption", "StorageEncrypted", "neptune_db_cluster_encryption_at_rest_enabled"),
    ("neptune_cluster", "deletion_protection", "DeletionProtection", "neptune_db_cluster_deletion_protection_enabled"),
    ("neptune_cluster", "iam_authentication", "IAMDatabaseAuthenticationEnabled", "neptune_db_cluster_iam_authentication_enabled"),
    ("neptune_cluster", "snapshot_tags", "CopyTagsToSnapshot", "neptune_db_cluster_copy_tags_to_snapshot_enabled"),
):
    scalar("aws.b." + _kind + "." + _name, _kind, _field, True, False,
           _kind.replace("_", " ").title() + " enables " + _name.replace("_", " "), _query)


threshold("aws.b.neptune.backup_retention_seven_days", "neptune_cluster", "BackupRetentionPeriod", 7, 7, 6,
          "Neptune cluster retains automatic backups for at least seven days", "neptune_db_cluster_automated_backup_enabled")


@install("aws.b.neptune.audit_logging", "neptune_cluster", "Neptune cluster exports audit logs",
         {"EnabledCloudwatchLogsExports": ["audit"]}, {"EnabledCloudwatchLogsExports": ["slowquery"]},
         query="neptune_db_cluster_audit_logging_enabled")
def neptune_logging(item, index):
    logs = get(item, "EnabledCloudwatchLogsExports", list)
    if any(not isinstance(value, str) for value in logs):
        return unknown("malformed exported log categories")
    return result("audit" not in logs, exported_categories=logs, required_category="audit")


@install("aws.b.rds_instance.multiple_az", "rds_instance", "Non-Aurora RDS instances enable Multi-AZ",
         {"Engine": "postgres", "MultiAZ": True}, {"Engine": "mysql", "MultiAZ": False},
         query="rds_db_instance_multiple_az_enabled",
         extra={"not_applicable": {"Engine": "aurora-mysql"}})
def rds_instance_multiaz(item, index):
    engine = get(item, "Engine", str)
    if "aurora-mysql" in engine.lower() or "aurora-postgres" in engine.lower():
        return "NOT_APPLICABLE", {"engine": engine, "reason": "Pinned source excludes Aurora cluster instances."}
    enabled = get(item, "MultiAZ", bool)
    return result(not enabled, engine=engine, multi_az=enabled)


def _filesystem(item, eligible):
    kind = get(item, "FileSystemType", str)
    if kind not in {"WINDOWS", "LUSTRE", "ONTAP", "OPENZFS"}:
        raise ValueError("unrecognized FSx file system type")
    return kind, kind == eligible


for _eligible, _configuration, _passing in (
    ("OPENZFS", "OpenZFSConfiguration", {"MULTI_AZ_1"}),
    ("ONTAP", "OntapConfiguration", {"MULTI_AZ_1", "MULTI_AZ_2"}),
    ("WINDOWS", "WindowsConfiguration", {"MULTI_AZ_1"}),
):
    def _deployment(eligible, configuration, passing):
        suffix = "netapp_ontap" if eligible == "ONTAP" else eligible.lower()
        @install("aws.b.fsx." + suffix + "_multi_az", "fsx_file_system", "FSx " + eligible + " uses a source-approved Multi-AZ deployment",
                 {"FileSystemType": eligible, configuration: {"DeploymentType": "MULTI_AZ_1"}},
                 {"FileSystemType": eligible, configuration: {"DeploymentType": "SINGLE_AZ_1"}},
                 query="fsx_" + suffix + "_file_system_multi_az_deployment_enabled",
                 extra={"not_applicable": {"FileSystemType": "LUSTRE"}})
        def evaluate(item, index):
            kind, applicable = _filesystem(item, eligible)
            if not applicable:
                return "NOT_APPLICABLE", {"file_system_type": kind, "source_type": eligible}
            deployment = get(item, configuration + ".DeploymentType", str)
            known = {"MULTI_AZ_1", "MULTI_AZ_2", "SINGLE_AZ_1", "SINGLE_AZ_2", "SINGLE_AZ_HA_1", "SINGLE_AZ_HA_2"}
            if deployment not in known:
                return unknown("unrecognized FSx deployment type", deployment=deployment)
            return result(deployment not in passing, file_system_type=kind, deployment_type=deployment, source_approved=sorted(passing))
    _deployment(_eligible, _configuration, _passing)


@install("aws.b.fsx.openzfs_copy_backup_and_volume_tags", "fsx_file_system", "FSx OpenZFS copies both backup and volume tags",
         {"FileSystemType": "OPENZFS", "OpenZFSConfiguration": {"CopyTagsToBackups": True, "CopyTagsToVolumes": True}},
         {"FileSystemType": "OPENZFS", "OpenZFSConfiguration": {"CopyTagsToBackups": True, "CopyTagsToVolumes": False}},
         query="fsx_file_system_copy_tags_to_backup_and_volume_enabled",
         extra={"not_applicable": {"FileSystemType": "WINDOWS"}})
def zfs_tags(item, index):
    kind, applicable = _filesystem(item, "OPENZFS")
    if not applicable:
        return "NOT_APPLICABLE", {"file_system_type": kind}
    backups = get(item, "OpenZFSConfiguration.CopyTagsToBackups", bool)
    volumes = get(item, "OpenZFSConfiguration.CopyTagsToVolumes", bool)
    return result(not (backups and volumes), copy_backup_tags=backups, copy_volume_tags=volumes)


@install("aws.b.fsx.lustre_copy_backup_tags", "fsx_file_system", "FSx Lustre copies backup tags",
         {"FileSystemType": "LUSTRE", "LustreConfiguration": {"CopyTagsToBackups": True}},
         {"FileSystemType": "LUSTRE", "LustreConfiguration": {"CopyTagsToBackups": False}},
         query="fsx_lustre_file_system_copy_tags_to_backup_enabled",
         extra={"not_applicable": {"FileSystemType": "OPENZFS"}})
def lustre_tags(item, index):
    kind, applicable = _filesystem(item, "LUSTRE")
    if not applicable:
        return "NOT_APPLICABLE", {"file_system_type": kind}
    enabled = get(item, "LustreConfiguration.CopyTagsToBackups", bool)
    return result(not enabled, copy_backup_tags=enabled)


IDS = [cid for cid in ALL_IDS if cid not in _previous_ids]
