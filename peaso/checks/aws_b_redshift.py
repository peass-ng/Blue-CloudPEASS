"""Redshift native configuration policies; no SQL connections or log contents."""
from . import alias_check, result, unknown
from .facts import get, optional, complete_items
from .aws_b_core import install, scalar, threshold, IDS as ALL_IDS

_before = set(ALL_IDS)

scalar("aws.b.redshift.allow_version_upgrade", "redshift_cluster", "AllowVersionUpgrade", True, False,
       "Redshift cluster permits version upgrades", "redshift_cluster_automatic_upgrade_major_versions_enabled")
scalar("aws.b.redshift.enhanced_vpc_routing", "redshift_cluster", "EnhancedVpcRouting", True, False,
       "Redshift cluster enables enhanced VPC routing", "redshift_cluster_enhanced_vpc_routing_enabled")
alias_check("aws.b.redshift.no_public_endpoint", "aws.cb.redshift.not_publicly_accessible")
scalar("aws.b.redshift.audit_logging", "redshift_cluster", "Logging.LoggingEnabled", True, False,
       "Redshift cluster enables audit log delivery configuration", "redshift_cluster_audit_logging_enabled")
threshold("aws.b.redshift.snapshots_seven_days", "redshift_cluster", "AutomatedSnapshotRetentionPeriod", 7, 7, 6,
          "Redshift automatic snapshots are retained for at least seven days", "redshift_cluster_automatic_snapshots_min_7_days")


for _field, _blocked, _suffix, _query in (
    ("MasterUsername", "awsuser", "nondefault_admin", "redshift_cluster_no_default_admin_name"),
    ("DBName", "dev", "nondefault_database", "redshift_cluster_no_default_database_name"),
):
    def _name(field, blocked, suffix, query):
        @install("aws.b.redshift." + suffix, "redshift_cluster", "Redshift configured " + field + " differs from the source default name",
                 {field: "application_owner"}, {field: blocked}, query=query, severity="low")
        def evaluate(item, index):
            name = get(item, field, str)
            return result(name == blocked, field=field, declared_name=name, source_default=blocked,
                          semantics="Exact case-sensitive naming policy only; changing a name does not establish stronger authentication.")
    _name(_field, _blocked, _suffix, _query)


@install("aws.b.redshift.kms_key_declared", "redshift_cluster", "Encrypted Redshift cluster declares a KMS encryption key",
         {"Encrypted": True, "KmsKeyId": "arn:aws:kms:us-east-1:111111111111:key/example"},
         {"Encrypted": False}, query="redshift_cluster_kms_enabled")
def kms(item, index):
    encrypted = get(item, "Encrypted", bool)
    if not encrypted:
        return result(True, encrypted=False, semantics="Pinned source requires both encryption and a non-null KMS key reference.")
    if "KmsKeyId" in item or "KmsKeyId" in item.get("_coverage", {}):
        key = get(item, "KmsKeyId", str)
        if not key:
            return unknown("empty KMS key reference")
        return result(False, encrypted=True, kms_key_id=key, semantics="Declared key reference only; customer-managed classification is a separate KMS join.")
    # A missing field is a known absence only if the complete scoped native
    # inventory identifies this exact observed cluster. Otherwise stay unknown.
    identity = get(item, "ClusterIdentifier", str)
    matches = [row for row in complete_items(index, "redshift_cluster") if row.get("ClusterIdentifier") == identity]
    if len(matches) != 1 or "KmsKeyId" in matches[0] or get(matches[0], "Encrypted", bool) != encrypted:
        return unknown("cluster key-reference absence not uniquely established")
    return result(True, encrypted=True, kms_key_id=None, cluster_identifier=identity,
                  semantics="Complete scoped native DescribeClusters metadata establishes an absent KMS key reference.")


IDS = [cid for cid in ALL_IDS if cid not in _before]
