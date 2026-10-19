"""Concise scope observations bound to reviewed native applicability witnesses.

Only exact recorded source shapes are interpreted. Missing, malformed or new
applicability facts retain their existing fallback; verdicts are never changed.
"""
import json

REVIEWED_SCOPES=json.loads(r'''
[
  {
    "id": "aws.elbv2.drop_invalid_headers",
    "status": "NOT_APPLICABLE",
    "witness": {
      "load_balancer_type": "network"
    },
    "summary": "The load balancer is a network load balancer; this check evaluates application load balancers.",
    "case": "not_applicable"
  },
  {
    "id": "aws.elbv2.desync_mitigation",
    "status": "NOT_APPLICABLE",
    "witness": {
      "load_balancer_type": "network"
    },
    "summary": "The load balancer is a network load balancer; this check evaluates application load balancers.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.rds.cluster_event_categories",
    "status": "NOT_APPLICABLE",
    "witness": {
      "source_type": "other",
      "required_source_type": "db-cluster"
    },
    "summary": "The event subscription targets other; this check evaluates db-cluster subscriptions.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.rds.instance_event_categories",
    "status": "NOT_APPLICABLE",
    "witness": {
      "source_type": "other",
      "required_source_type": "db-instance"
    },
    "summary": "The event subscription targets other; this check evaluates db-instance subscriptions.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.rds.parameter_group_event_categories",
    "status": "NOT_APPLICABLE",
    "witness": {
      "source_type": "other",
      "required_source_type": "db-parameter-group"
    },
    "summary": "The event subscription targets other; this check evaluates db-parameter-group subscriptions.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.rds.security_group_event_categories",
    "status": "NOT_APPLICABLE",
    "witness": {
      "source_type": "other",
      "required_source_type": "db-security-group"
    },
    "summary": "The event subscription targets other; this check evaluates db-security-group subscriptions.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.alb.access_logs",
    "status": "NOT_APPLICABLE",
    "witness": {
      "type": "network"
    },
    "summary": "The load balancer is a network load balancer; this check evaluates application load balancers.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.alb.deletion_protection",
    "status": "NOT_APPLICABLE",
    "witness": {
      "type": "network"
    },
    "summary": "The load balancer is a network load balancer; this check evaluates application load balancers.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.alb.invalid_header_dropping",
    "status": "NOT_APPLICABLE",
    "witness": {
      "type": "network"
    },
    "summary": "The load balancer is a network load balancer; this check evaluates application load balancers.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.alb.desync_mode",
    "status": "NOT_APPLICABLE",
    "witness": {
      "type": "network"
    },
    "summary": "The load balancer is a network load balancer; this check evaluates application load balancers.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.acm.expiry_thirty_days",
    "status": "NOT_APPLICABLE",
    "witness": {
      "renewal_eligibility": "INELIGIBLE"
    },
    "summary": "The certificate is ineligible for renewal; this check evaluates renewal-eligible certificates.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.acm.transparency_logging",
    "status": "NOT_APPLICABLE",
    "witness": {
      "certificate_type": "IMPORTED"
    },
    "summary": "The certificate is imported; this check evaluates Amazon-issued certificates.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.acm.not_past_expiry_date",
    "status": "NOT_APPLICABLE",
    "witness": {
      "renewal_eligibility": "INELIGIBLE"
    },
    "summary": "The certificate is ineligible for renewal; this check evaluates renewal-eligible certificates.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.acm.rsa_minimum_2048",
    "status": "NOT_APPLICABLE",
    "witness": {
      "key_algorithm": "EC_prime256v1"
    },
    "summary": "The certificate uses an elliptic-curve key; the RSA key-length check does not apply.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.aurora.mysql_copy_snapshot_tags",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "other",
      "required_engine": "aurora-mysql"
    },
    "summary": "The recorded engine is other; this check evaluates aurora-mysql.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.aurora.postgres_copy_snapshot_tags",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "other",
      "required_engine": "aurora-postgresql"
    },
    "summary": "The recorded engine is other; this check evaluates aurora-postgresql.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.aurora.mysql_audit_export",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "postgres"
    },
    "summary": "The recorded engine is postgres; this check evaluates Aurora MySQL audit-log exports.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.ecs.host_network_nonprivileged",
    "status": "NOT_APPLICABLE",
    "witness": {
      "network_mode": "awsvpc"
    },
    "summary": "The task uses awsvpc networking; this check evaluates host-network containers.",
    "case": "not_applicable"
  },
  {
    "id": "aws.a.cloudtrail.bucket_mfa_delete",
    "status": "NOT_APPLICABLE",
    "witness": {
      "is_logging": false
    },
    "summary": "The trail is not logging; this check evaluates buckets belonging to logging trails.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.fsx.openzfs_multi_az",
    "status": "NOT_APPLICABLE",
    "witness": {
      "file_system_type": "LUSTRE",
      "source_type": "OPENZFS"
    },
    "summary": "The file system is LUSTRE; this check evaluates FSx for OpenZFS.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.fsx.netapp_ontap_multi_az",
    "status": "NOT_APPLICABLE",
    "witness": {
      "file_system_type": "LUSTRE",
      "source_type": "ONTAP"
    },
    "summary": "The file system is LUSTRE; this check evaluates FSx for ONTAP.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.fsx.windows_multi_az",
    "status": "NOT_APPLICABLE",
    "witness": {
      "file_system_type": "LUSTRE",
      "source_type": "WINDOWS"
    },
    "summary": "The file system is LUSTRE; this check evaluates FSx for Windows.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.fsx.openzfs_copy_backup_and_volume_tags",
    "status": "NOT_APPLICABLE",
    "witness": {
      "file_system_type": "WINDOWS"
    },
    "summary": "The file system is WINDOWS; this check evaluates FSx for OpenZFS.",
    "case": "not_applicable"
  },
  {
    "id": "aws.b.fsx.lustre_copy_backup_tags",
    "status": "NOT_APPLICABLE",
    "witness": {
      "file_system_type": "OPENZFS"
    },
    "summary": "The file system is OPENZFS; this check evaluates FSx for Lustre.",
    "case": "not_applicable"
  },
  {
    "id": "aws.claude_a.ebs.attached_volume_encrypted",
    "status": "NOT_APPLICABLE",
    "witness": {
      "state": "available"
    },
    "summary": "The EBS volume is available; this check evaluates attached volumes.",
    "case": "not_applicable"
  },
  {
    "id": "aws.claude_a.ebs.attached_delete_on_termination",
    "status": "NOT_APPLICABLE",
    "witness": {
      "state": "available"
    },
    "summary": "The EBS volume is available; this check evaluates attached volumes.",
    "case": "not_applicable"
  },
  {
    "id": "aws.claude_a.ec2.instance_profile_attached_not_terminated",
    "status": "NOT_APPLICABLE",
    "witness": {
      "state": "terminated"
    },
    "summary": "The instance is terminated; this check excludes terminated instances.",
    "case": "not_applicable"
  },
  {
    "id": "aws.claude_a.ec2.instance_no_public_ip_not_terminated",
    "status": "NOT_APPLICABLE",
    "witness": {
      "state": "terminated"
    },
    "summary": "The instance is terminated; this check excludes terminated instances.",
    "case": "not_applicable"
  },
  {
    "id": "aws.claude_a.ec2.internet_facing_without_profile",
    "status": "NOT_APPLICABLE",
    "witness": {
      "state": "terminated"
    },
    "summary": "The instance is terminated; this check excludes terminated instances.",
    "case": "not_applicable"
  },
  {
    "id": "aws.claude_a.ec2.running_instance_no_key_pair",
    "status": "NOT_APPLICABLE",
    "witness": {
      "state": "stopped"
    },
    "summary": "The instance is stopped; this check evaluates running instances.",
    "case": "not_applicable"
  },
  {
    "id": "aws.claude_a.ec2.instance_imdsv2_or_disabled",
    "status": "NOT_APPLICABLE",
    "witness": {
      "state": "terminated"
    },
    "summary": "The instance is terminated; this check excludes terminated instances.",
    "case": "not_applicable"
  },
  {
    "id": "aws.claude_a.ec2.instance_not_paravirtual_not_terminated",
    "status": "NOT_APPLICABLE",
    "witness": {
      "state": "terminated"
    },
    "summary": "The instance is terminated; this check excludes terminated instances.",
    "case": "not_applicable"
  },
  {
    "id": "aws.claude_a.ec2.running_instance_age_180_days",
    "status": "NOT_APPLICABLE",
    "witness": {
      "state": "stopped"
    },
    "summary": "The instance is stopped; this check evaluates running instances.",
    "case": "not_applicable"
  },
  {
    "id": "aws.claude_a.ec2.stopped_instance_30_days",
    "status": "NOT_APPLICABLE",
    "witness": {
      "state": "running"
    },
    "summary": "The instance is running; this check evaluates stopped instances.",
    "case": "not_applicable"
  },
  {
    "id": "aws.claude_a.ec2.stopped_instance_90_days",
    "status": "NOT_APPLICABLE",
    "witness": {
      "state": "running"
    },
    "summary": "The instance is running; this check evaluates stopped instances.",
    "case": "not_applicable"
  },
  {
    "id": "aws.claude_a.ec2.stopped_instance_more_than_30_days",
    "status": "NOT_APPLICABLE",
    "witness": {
      "state": "running"
    },
    "summary": "The instance is running; this check evaluates stopped instances.",
    "case": "not_applicable"
  },
  {
    "id": "aws.claude_a.ec2.instance_ssm_managed",
    "status": "NOT_APPLICABLE",
    "witness": {
      "state": "stopped"
    },
    "summary": "The instance is stopped; this check excludes stopped instances from SSM-management review.",
    "case": "not_applicable"
  },
  {
    "id": "aws.claude_a.ec2.active_instance_ssm_managed",
    "status": "NOT_APPLICABLE",
    "witness": {
      "state": "pending"
    },
    "summary": "The instance is pending; this SSM-management check excludes pending, stopped and terminated instances.",
    "case": "not_applicable"
  },
  {
    "id": "aws.claude_a.ec2.eni_source_dest_check",
    "status": "NOT_APPLICABLE",
    "witness": {
      "interface_type": "nat_gateway"
    },
    "summary": "The interface belongs to a NAT gateway; this check evaluates supported instance interfaces.",
    "case": "not_applicable"
  },
  {
    "id": "aws.claude_a.networkfirewall.in_vpc",
    "status": "NOT_APPLICABLE",
    "witness": {
      "placement": "transit_gateway",
      "transit_gateway_id": "tgw-1"
    },
    "summary": "The firewall is attached to a transit gateway; this check evaluates VPC placement.",
    "case": "not_applicable"
  },
  {
    "id": "aws.claude_a.s3.versioning_and_lifecycle",
    "status": "NOT_APPLICABLE",
    "witness": {
      "versioning": false
    },
    "summary": "Bucket versioning is disabled; this lifecycle check evaluates versioned buckets.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.fsx.copy_tags_to_backups",
    "status": "NOT_APPLICABLE",
    "witness": {
      "file_system_type": "ONTAP"
    },
    "summary": "The file system is ONTAP; this check evaluates FSx for Windows, Lustre and OpenZFS.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.fsx.copy_tags_to_volumes",
    "status": "NOT_APPLICABLE",
    "witness": {
      "file_system_type": "LUSTRE"
    },
    "summary": "The file system is LUSTRE; this check evaluates FSx for OpenZFS.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.fsx.openzfs_copy_tags_backups_and_volumes",
    "status": "NOT_APPLICABLE",
    "witness": {
      "file_system_type": "LUSTRE"
    },
    "summary": "The file system is LUSTRE; this check evaluates FSx for OpenZFS.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.fsx.lustre_copy_tags_to_backups",
    "status": "NOT_APPLICABLE",
    "witness": {
      "file_system_type": "WINDOWS"
    },
    "summary": "The file system is WINDOWS; this check evaluates FSx for Lustre.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.fsx.ontap_multi_az",
    "status": "NOT_APPLICABLE",
    "witness": {
      "file_system_type": "LUSTRE"
    },
    "summary": "The file system is LUSTRE; this check evaluates FSx for ONTAP.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.fsx.openzfs_multi_az",
    "status": "NOT_APPLICABLE",
    "witness": {
      "file_system_type": "LUSTRE"
    },
    "summary": "The file system is LUSTRE; this check evaluates FSx for OpenZFS.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.fsx.windows_multi_az_deployment",
    "status": "NOT_APPLICABLE",
    "witness": {
      "file_system_type": "LUSTRE"
    },
    "summary": "The file system is LUSTRE; this check evaluates FSx for Windows.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.fsx.windows_multiple_subnets",
    "status": "NOT_APPLICABLE",
    "witness": {
      "file_system_type": "LUSTRE"
    },
    "summary": "The file system is LUSTRE; this check evaluates FSx for Windows.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.glacier.vault_policy_prohibit_public_access",
    "status": "NOT_APPLICABLE",
    "witness": {
      "policy": null
    },
    "summary": "No Glacier vault resource policy is declared; this policy-content check does not apply.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.glue.connection_jdbc_enforce_ssl",
    "status": "NOT_APPLICABLE",
    "witness": {
      "connection_type": "NETWORK"
    },
    "summary": "The connection type is NETWORK; this check evaluates JDBC connections.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.glue.catalog_policy_not_public",
    "status": "NOT_APPLICABLE",
    "witness": {
      "policy": null
    },
    "summary": "No Glue Data Catalog resource policy is declared; this policy-content check does not apply.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.mediastore.container_policy_not_public",
    "status": "NOT_APPLICABLE",
    "witness": {
      "policy": null
    },
    "summary": "No MediaStore container resource policy is declared; this policy-content check does not apply.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.cluster_backtrack_window_positive",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "aurora-postgresql"
    },
    "summary": "The recorded engine is aurora-postgresql; this check evaluates Aurora MySQL Backtrack.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.aurora_backtracking_configured",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "postgres"
    },
    "summary": "The recorded engine is postgres; this check evaluates Aurora MySQL Backtrack.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.cluster_cloudwatch_log_exports",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "neptune"
    },
    "summary": "The recorded engine is neptune; this check evaluates Aurora MySQL/PostgreSQL and RDS MySQL/PostgreSQL clusters.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.multi_az_cluster_minor_upgrade",
    "status": "NOT_APPLICABLE",
    "witness": {
      "multi_az": false
    },
    "summary": "The cluster is not Multi-AZ; this check evaluates Multi-AZ cluster minor upgrades.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.instance_in_backup_plan_selection",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "aurora-mysql"
    },
    "summary": "The recorded engine is aurora-mysql; this check evaluates non-Aurora RDS instances.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.aurora_cluster_protected_resource",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "mysql"
    },
    "summary": "The recorded engine is mysql; this check evaluates Aurora clusters.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.aurora_mysql_server_audit_logging",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "aurora-postgresql"
    },
    "summary": "The recorded engine is aurora-postgresql; this check evaluates Aurora MySQL audit logging.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.aurora_postgres_postgresql_log_export",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "aurora-mysql"
    },
    "summary": "The recorded engine is aurora-mysql; this check evaluates Aurora PostgreSQL log exports.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.instance_enhanced_monitoring_except_m1_small",
    "status": "NOT_APPLICABLE",
    "witness": {
      "instance_class": "db.m1.small"
    },
    "summary": "The instance class is db.m1.small, which this monitoring check excludes.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.instance_tls_parameters",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "oracle-ee",
      "cluster": null
    },
    "summary": "The recorded engine is oracle-ee; this check evaluates supported standalone database TLS parameters.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.postgres_force_ssl_parameter",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "oracle-ee"
    },
    "summary": "The recorded engine is oracle-ee; this check evaluates the PostgreSQL TLS parameter.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.mariadb_require_secure_transport",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "oracle-ee"
    },
    "summary": "The recorded engine is oracle-ee; this check evaluates MariaDB secure transport.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.sqlserver_force_ssl_parameter",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "oracle-ee"
    },
    "summary": "The recorded engine is oracle-ee; this check evaluates SQL Server TLS parameters.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.mariadb_log_exports",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "oracle-ee"
    },
    "summary": "The recorded engine is oracle-ee; this check evaluates MariaDB log exports.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.postgres_log_exports",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "oracle-ee"
    },
    "summary": "The recorded engine is oracle-ee; this check evaluates PostgreSQL log exports.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.sqlserver_error_log_export",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "oracle-ee"
    },
    "summary": "The recorded engine is oracle-ee; this check evaluates SQL Server error-log exports.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.aurora_postgres_local_file_read_versions",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "mysql"
    },
    "summary": "The recorded engine is mysql; this check evaluates Aurora PostgreSQL versions.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.postgres_local_file_read_versions",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "mysql"
    },
    "summary": "The recorded engine is mysql; this check evaluates PostgreSQL versions.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.instance_iam_auth_supported_engines",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "oracle-ee"
    },
    "summary": "The recorded engine is oracle-ee; this check evaluates MySQL, MariaDB and PostgreSQL IAM authentication.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.rds.instance_multi_az_non_aurora",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "aurora-postgresql"
    },
    "summary": "The recorded engine is aurora-postgresql; this check evaluates non-Aurora Multi-AZ instances.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.opensearch.node_to_node_encryption_region_skip",
    "status": "NOT_APPLICABLE",
    "witness": {
      "region": "af-south-1"
    },
    "summary": "The domain is in af-south-1, which this check excludes from its regional scope.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.mq.activemq_active_standby",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "RABBITMQ"
    },
    "summary": "The recorded engine is RABBITMQ; this check evaluates ActiveMQ deployment mode.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.mq.rabbitmq_cluster_deployment",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "ACTIVEMQ"
    },
    "summary": "The recorded engine is ACTIVEMQ; this check evaluates RabbitMQ deployment mode.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.msk.client_broker_tls",
    "status": "NOT_APPLICABLE",
    "witness": {
      "cluster_type": "SERVERLESS"
    },
    "summary": "The MSK cluster is serverless; this check evaluates provisioned-cluster TLS settings.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.kafka.latest_version",
    "status": "NOT_APPLICABLE",
    "witness": {
      "cluster_type": "SERVERLESS"
    },
    "summary": "The MSK cluster is serverless; this version check evaluates provisioned clusters.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.sns.policy_prohibit_public_access_perimeter",
    "status": "NOT_APPLICABLE",
    "witness": {
      "policy": null
    },
    "summary": "No SNS topic resource policy is declared; this policy-content check does not apply.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.sns.subscription_not_http",
    "status": "NOT_APPLICABLE",
    "witness": {
      "subscription_arn": "PendingConfirmation"
    },
    "summary": "The SNS subscription is pending confirmation; no active subscription endpoint is assessed.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.sqs.policy_prohibit_public_access_perimeter",
    "status": "NOT_APPLICABLE",
    "witness": {
      "policy": null
    },
    "summary": "No SQS queue resource policy is declared; this policy-content check does not apply.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.ses.identity_policies_not_public",
    "status": "MANUAL",
    "witness": {
      "question": "Does the explicit Deny neutralise the public Allow in the SES identity policy?"
    },
    "summary": "The SES policy contains both a public Allow and an explicit Deny; review whether the Deny overrides that grant.",
    "case": "manual"
  },
  {
    "id": "aws.cb.ses.identity_policies_not_public",
    "status": "NOT_APPLICABLE",
    "witness": {
      "policies": 0
    },
    "summary": "The SES identity has no attached policies; no policy grants are assessed.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.lambda.vpc_multiple_az",
    "status": "NOT_APPLICABLE",
    "witness": {
      "vpc_id": null
    },
    "summary": "The Lambda function has no VPC reference; the VPC availability-zone check does not apply.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.lambda.policy_prohibit_public_access_perimeter",
    "status": "NOT_APPLICABLE",
    "witness": {
      "policy": null
    },
    "summary": "No Lambda function resource policy is declared; this policy-content check does not apply.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.lambda.runtime_not_deprecated_list",
    "status": "NOT_APPLICABLE",
    "witness": {
      "package_type": "Image"
    },
    "summary": "The function uses a container image; this check evaluates managed Lambda runtimes.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.route53.public_zone_query_logging",
    "status": "NOT_APPLICABLE",
    "witness": {
      "private_zone": true
    },
    "summary": "The hosted zone is private; this check evaluates public-zone query logging.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.secretsmanager.rotated_as_scheduled",
    "status": "NOT_APPLICABLE",
    "witness": {
      "primary_region": "eu-west-1"
    },
    "summary": "The secret is a replica of the eu-west-1 primary; rotation is assessed on the primary.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.secretsmanager.policy_not_public",
    "status": "NOT_APPLICABLE",
    "witness": {
      "policy": null
    },
    "summary": "No Secrets Manager secret resource policy is declared; this policy-content check does not apply.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.secretsmanager.policy_prohibit_public_access_perimeter",
    "status": "NOT_APPLICABLE",
    "witness": {
      "policy": null
    },
    "summary": "No Secrets Manager secret resource policy is declared; this policy-content check does not apply.",
    "case": "not_applicable"
  },
  {
    "id": "aws.cb.shield.internet_facing_alb_protected",
    "status": "NOT_APPLICABLE",
    "witness": {
      "type": "application",
      "scheme": "internal"
    },
    "summary": "The application load balancer is internal; this check evaluates internet-facing ALBs.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.lambda.policy_not_public",
    "status": "NOT_APPLICABLE",
    "witness": {
      "policy": null
    },
    "summary": "No Lambda function resource policy is declared; this policy-content check does not apply.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.lambda.url_cors_no_wildcard",
    "status": "NOT_APPLICABLE",
    "witness": {
      "function_url": null
    },
    "summary": "The function has no URL configuration; the function-URL CORS check does not apply.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.lambda.runtime_not_obsolete",
    "status": "NOT_APPLICABLE",
    "witness": {
      "runtime": null
    },
    "summary": "No managed runtime is declared; this check evaluates managed Lambda runtime versions.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.ecs.logging_non_blocking",
    "status": "NOT_APPLICABLE",
    "witness": {
      "containers_with_log_driver": []
    },
    "summary": "No container has a log-driver configuration; this check evaluates configured log drivers.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.ecs.container_instance_agents_connected",
    "status": "NOT_APPLICABLE",
    "witness": {
      "registered_container_instances": 0
    },
    "summary": "The cluster has no registered container instances; no ECS agent connection is assessed.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.ecs.cluster_instance_volumes_encrypted",
    "status": "NOT_APPLICABLE",
    "witness": {
      "registered_container_instances": 0
    },
    "summary": "The cluster has no registered container instances; no instance volumes are assessed.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.ecs.awsvpc_service_no_public_ip",
    "status": "NOT_APPLICABLE",
    "witness": {
      "network_mode": "bridge"
    },
    "summary": "The task uses bridge networking; this check evaluates awsvpc public-IP assignment.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.ecs.fargate_latest_platform",
    "status": "NOT_APPLICABLE",
    "witness": {
      "launch_type": "EC2"
    },
    "summary": "The service launches on EC2; this check evaluates Fargate platform versions.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.autoscaling.elb_health_check",
    "status": "NOT_APPLICABLE",
    "witness": {
      "load_balancers": [],
      "target_groups": []
    },
    "summary": "The Auto Scaling group has no load balancers or target groups; the ELB health-check requirement does not apply.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.autoscaling.capacity_rebalance",
    "status": "NOT_APPLICABLE",
    "witness": {
      "load_balancers": [],
      "target_groups": [
        "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/t/1"
      ]
    },
    "summary": "The Auto Scaling group has no classic load balancer; this check requires both a classic load balancer and a target group.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.autoscaling.instance_types_per_az",
    "status": "NOT_APPLICABLE",
    "witness": {
      "instances": 0
    },
    "summary": "The Auto Scaling group has no instances; no per-zone instance-type choices are assessed.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.autoscaling.group_lc_no_public_ip",
    "status": "NOT_APPLICABLE",
    "witness": {
      "launch_configuration": null
    },
    "summary": "The group has no launch configuration; this check evaluates launch-configuration public-IP assignment.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.autoscaling.group_lc_imdsv2",
    "status": "NOT_APPLICABLE",
    "witness": {
      "launch_configuration": null
    },
    "summary": "The group has no launch configuration; this check evaluates launch-configuration metadata settings.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.elbv2.cross_zone_enabled",
    "status": "NOT_APPLICABLE",
    "witness": {
      "type": "application"
    },
    "summary": "The load balancer is an ALB; this check evaluates network and gateway load balancers.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.elbv2.nlb_tls_termination",
    "status": "NOT_APPLICABLE",
    "witness": {
      "type": "application"
    },
    "summary": "The load balancer is an ALB; this check evaluates network-load-balancer TLS listeners.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.elbv2.http_listeners_redirect_https",
    "status": "NOT_APPLICABLE",
    "witness": {
      "type": "network"
    },
    "summary": "The load balancer is a network load balancer; this check evaluates application load balancers.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.elbv2.alb_waf_attached",
    "status": "NOT_APPLICABLE",
    "witness": {
      "type": "network"
    },
    "summary": "The load balancer is a network load balancer; this check evaluates application load balancers.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.elbv2.alb_wafv2_attached",
    "status": "NOT_APPLICABLE",
    "witness": {
      "type": "network"
    },
    "summary": "The load balancer is a network load balancer; this check evaluates application load balancers.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.elbv2.not_internet_facing",
    "status": "NOT_APPLICABLE",
    "witness": {
      "type": "gateway"
    },
    "summary": "The load balancer is a gateway load balancer, which this exposure check excludes.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.elbv2.alb_http_redirect_default",
    "status": "NOT_APPLICABLE",
    "witness": {
      "type": "network"
    },
    "summary": "The load balancer is a network load balancer; this check evaluates application load balancers.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.elbv2.alb_sg_outbound_rule",
    "status": "NOT_APPLICABLE",
    "witness": {
      "type": "network"
    },
    "summary": "The load balancer is a network load balancer; this check evaluates application load balancers.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.elbv2.listeners_acm_certificate",
    "status": "NOT_APPLICABLE",
    "witness": {
      "type": "gateway"
    },
    "summary": "The load balancer is a gateway load balancer; no application or network listener certificates are assessed.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.elbv2.listeners_secure_protocol",
    "status": "NOT_APPLICABLE",
    "witness": {
      "type": "gateway"
    },
    "summary": "The load balancer is a gateway load balancer; this check evaluates application and network listener protocols.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.appsync.graphql_no_api_key",
    "status": "NOT_APPLICABLE",
    "witness": {
      "api_type": "MERGED"
    },
    "summary": "The AppSync API is merged; this check evaluates source-API authentication.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.dms.mongodb_auth",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "postgres",
      "applicable_engines": [
        "mongodb"
      ]
    },
    "summary": "The DMS endpoint engine is postgres; this check evaluates mongodb endpoints.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.dms.neptune_iam_auth",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "redis",
      "applicable_engines": [
        "neptune"
      ]
    },
    "summary": "The DMS endpoint engine is redis; this check evaluates neptune endpoints.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.dms.redis_tls",
    "status": "NOT_APPLICABLE",
    "witness": {
      "engine": "mongodb",
      "applicable_engines": [
        "redis"
      ]
    },
    "summary": "The DMS endpoint engine is mongodb; this check evaluates redis endpoints.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.efs.policy_prohibit_public_access",
    "status": "NOT_APPLICABLE",
    "witness": {
      "policy": null
    },
    "summary": "No EFS file system resource policy is declared; this policy-content check does not apply.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.efs.access_points_no_root_directory",
    "status": "NOT_APPLICABLE",
    "witness": {
      "access_points": 0
    },
    "summary": "The file system has no access points; no access-point root directories are assessed.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.efs.access_points_posix_user",
    "status": "NOT_APPLICABLE",
    "witness": {
      "access_points": 0
    },
    "summary": "The file system has no access points; no access-point POSIX identities are assessed.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.emr.master_subnet_no_auto_public_ip",
    "status": "NOT_APPLICABLE",
    "witness": {
      "state": "TERMINATED"
    },
    "summary": "The EMR cluster is terminated; this check evaluates active-cluster networking.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.emr.master_no_public_dns",
    "status": "NOT_APPLICABLE",
    "witness": {
      "state": "TERMINATED"
    },
    "summary": "The EMR cluster is terminated; this check evaluates active-cluster networking.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.emr.cluster_not_publicly_accessible",
    "status": "NOT_APPLICABLE",
    "witness": {
      "state": "TERMINATED"
    },
    "summary": "The EMR cluster is terminated; this check evaluates active-cluster networking.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.es.policy_prohibit_public_access",
    "status": "NOT_APPLICABLE",
    "witness": {
      "policy": null
    },
    "summary": "No OpenSearch domain resource policy is declared; this policy-content check does not apply.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.acmpca.root_ca_disabled",
    "status": "NOT_APPLICABLE",
    "witness": {
      "type": "SUBORDINATE"
    },
    "summary": "The certificate authority is subordinate; this check evaluates root authorities.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.acmpca.pqc_key_algorithm",
    "status": "NOT_APPLICABLE",
    "witness": {
      "status": "DELETED"
    },
    "summary": "The certificate authority is deleted; no active key algorithm is assessed.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.directoryservice.sns_notifications",
    "status": "NOT_APPLICABLE",
    "witness": {
      "type": "SharedMicrosoftAD"
    },
    "summary": "The directory is Shared Microsoft AD; event-topic notifications are outside this check's supported scope.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.directoryservice.radius_mfa_enabled",
    "status": "NOT_APPLICABLE",
    "witness": {
      "type": "SimpleAD"
    },
    "summary": "The directory is Simple AD; RADIUS MFA is unsupported for this directory type.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.codebuild.s3_logs_encrypted_when_enabled",
    "status": "NOT_APPLICABLE",
    "witness": {
      "s3_logs_status": "DISABLED"
    },
    "summary": "S3 build logging is disabled; this check evaluates encryption for enabled S3 logs.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.codebuild.source_repo_oauth",
    "status": "NOT_APPLICABLE",
    "witness": {
      "source_type": "CODECOMMIT"
    },
    "summary": "The build source is CodeCommit; this check evaluates OAuth-based Git sources.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.codebuild.report_group_export_encrypted",
    "status": "NOT_APPLICABLE",
    "witness": {
      "export_type": "NO_EXPORT"
    },
    "summary": "The report group has no export; this check evaluates S3-export encryption.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.cloudformation.termination_protection_root_stacks",
    "status": "NOT_APPLICABLE",
    "witness": {
      "root_stack": "arn:aws:cloudformation:us-east-1:111111111111:stack/root/0"
    },
    "summary": "The stack is nested; this check evaluates termination protection on root stacks.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.cloudformation.cdktoolkit_bootstrap_version",
    "status": "NOT_APPLICABLE",
    "witness": {
      "stack": "s1"
    },
    "summary": "The stack is not CDKToolkit; the CDK bootstrap-version check does not apply.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.codedeploy.lambda_not_all_at_once",
    "status": "NOT_APPLICABLE",
    "witness": {
      "compute_platform": "Server"
    },
    "summary": "The deployment group uses the Server platform; this check evaluates Lambda traffic shifts.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.ecr.latest_image_no_medium_plus_findings",
    "status": "NOT_APPLICABLE",
    "witness": {
      "scan_on_push": false
    },
    "summary": "Scan on push is disabled; this check evaluates the latest scannable image in scan-on-push repositories.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.eventbridge.custom_bus_policy_attached",
    "status": "NOT_APPLICABLE",
    "witness": {
      "bus": "default"
    },
    "summary": "The event bus is the default bus; this check evaluates custom-bus policies.",
    "case": "not_applicable"
  },
  {
    "id": "aws.c2b.codeartifact.internal_packages_block_upstream",
    "status": "NOT_APPLICABLE",
    "witness": {
      "internal_packages": 0
    },
    "summary": "No internally published packages are recorded; no internal-package upstream controls are assessed.",
    "case": "not_applicable"
  },
  {
    "id": "aws.a.iam.active_key_age_90",
    "status": "NOT_APPLICABLE",
    "witness": {
      "status": "Inactive"
    },
    "summary": "The access key is inactive; this age check evaluates active keys.",
    "case": "not_applicable"
  },
  {
    "id": "aws.htbp.appsync.no_api_key_additional_auth",
    "status": "NOT_APPLICABLE",
    "witness": {
      "api_type": "MERGED"
    },
    "summary": "The AppSync API is merged; this check evaluates source-API additional authentication modes.",
    "case": "NOT_APPLICABLE"
  },
  {
    "id": "aws.htbp.opensearch.connection_peer_trust_boundary",
    "status": "NOT_APPLICABLE",
    "witness": {
      "status": "DELETED"
    },
    "summary": "The OpenSearch connection is deleted; no active peer trust is assessed.",
    "case": "NOT_APPLICABLE"
  },
  {
    "id": "aws.nist.acm_all_certificates_expiry_30_days",
    "status": "NOT_APPLICABLE",
    "witness": {
      "certificate_arn": "arn:aws:acm:eu-west-1:123456789012:certificate/a",
      "status": "PENDING_VALIDATION"
    },
    "summary": "The ACM certificate is pending validation; this expiry check evaluates issued certificates.",
    "case": "NOT_APPLICABLE"
  },
  {
    "id": "aws_nist_acm_certificate_expires_30_days",
    "status": "NOT_APPLICABLE",
    "witness": {
      "certificate_arn": "arn:aws:acm:eu-west-1:123456789012:certificate/a",
      "status": "PENDING_VALIDATION"
    },
    "summary": "The ACM certificate is pending validation; this expiry check evaluates issued certificates.",
    "case": "NOT_APPLICABLE"
  },
  {
    "id": "aws_nist_rds_db_cluster_aurora_backtracking_enabled",
    "status": "NOT_APPLICABLE",
    "witness": {
      "cluster_id": "cluster-1",
      "engine": "aurora-postgresql"
    },
    "summary": "The recorded engine is aurora-postgresql; this check evaluates Aurora MySQL Backtrack.",
    "case": "NOT_APPLICABLE"
  }
]
''')


def _same(actual,expected):
    if type(actual)is not type(expected):return False
    if isinstance(expected,dict):return all(k in actual and _same(actual[k],v)for k,v in expected.items())
    if isinstance(expected,list):return len(actual)==len(expected) and all(_same(a,b)for a,b in zip(actual,expected))
    return actual==expected


def evidence_summary(finding):
    if not isinstance(finding,dict)or finding.get('provider')!='aws':return None
    status=finding.get('status');cid=finding.get('check_id');e=finding.get('evidence')
    if status not in {'NOT_APPLICABLE','MANUAL'}or not isinstance(e,dict):return None
    for row in REVIEWED_SCOPES:
        if cid==row['id']and status==row['status']and _same(e,row['witness']):return row['summary']
    return None
