"""DMS replication-instance configuration checks with native API fields."""
from .aws_b_core import scalar

scalar("aws.b.dms.no_public_instance", "dms_replication_instance", "PubliclyAccessible", False, True,
       "DMS replication instance does not declare public accessibility", "dms_replication_instance_not_publicly_accessible", category="exposure")
scalar("aws.b.dms.automatic_minor_upgrade", "dms_replication_instance", "AutoMinorVersionUpgrade", True, False,
       "DMS replication instance enables automatic minor version upgrades", "dms_replication_instance_automatic_minor_version_upgrade_enabled")
scalar("aws.b.dms.multi_az", "dms_replication_instance", "MultiAZ", True, False,
       "DMS replication instance uses Multi-AZ deployment", "dms_replication_instance_multiple_az_enabled")
