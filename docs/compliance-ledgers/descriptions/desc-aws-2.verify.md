
## Independent evaluator verification: desc-aws-2

- Input checks: 310; description entries: 310; unique IDs: 310.
- Entries corrected: 188. Each row below is one decision for one input ID.
- Source: evaluator bodies and generated-rule helpers under `peaso/checks/`; the check index registry source field is not the evaluator body.

| ID | Decision | Fields updated |
| --- | --- | --- |
| `aws.c2b.connect.contact_flow_logs` | Verified | — |
| `aws.c2b.datasync.task_log_group` | Verified | — |
| `aws.c2b.datasync.task_logging_level` | Verified | — |
| `aws.c2b.dax.encryption_at_rest` | Verified | — |
| `aws.c2b.dax.encryption_in_transit` | Verified | — |
| `aws.c2b.dax.multi_az` | Verified | — |
| `aws.c2b.directconnect.connection_redundancy` | Verified | — |
| `aws.c2b.directconnect.virtual_interface_redundancy` | Verified | — |
| `aws.c2b.directoryservice.certificate_not_within_90_days` | Verified | — |
| `aws.c2b.directoryservice.ldap_certificate_over_90_days` | Verified | — |
| `aws.c2b.directoryservice.log_forwarding` | Verified | — |
| `aws.c2b.directoryservice.manual_snapshot_quota` | Verified | — |
| `aws.c2b.directoryservice.radius_mfa_enabled` | Verified | — |
| `aws.c2b.directoryservice.radius_ms_chapv2` | Verified | — |
| `aws.c2b.directoryservice.shared_accounts_review` | Verified | — |
| `aws.c2b.directoryservice.sns_notifications` | Verified | — |
| `aws.c2b.dlm.ebs_snapshot_policy_with_snapshots` | Verified | — |
| `aws.c2b.dlm.policy_exists_with_snapshots` | Verified | — |
| `aws.c2b.dms.certificate_not_expired` | Verified | — |
| `aws.c2b.dms.endpoint_ssl` | Corrected | pass_when |
| `aws.c2b.dms.mongodb_auth` | Verified | — |
| `aws.c2b.dms.neptune_iam_auth` | Verified | — |
| `aws.c2b.dms.public_instance_open_sg` | Verified | — |
| `aws.c2b.dms.redis_tls` | Verified | — |
| `aws.c2b.dms.task_source_logging` | Verified | — |
| `aws.c2b.dms.task_target_logging` | Verified | — |
| `aws.c2b.docdb.cluster_tls_required` | Verified | — |
| `aws.c2b.docdb.instance_storage_encrypted` | Verified | — |
| `aws.c2b.docdb.snapshot_not_public_prowler` | Verified | — |
| `aws.c2b.docdb.snapshot_restore_not_all_exact` | Verified | — |
| `aws.c2b.documentdb.backup_retention_7` | Verified | — |
| `aws.c2b.documentdb.cluster_log_exports` | Verified | — |
| `aws.c2b.documentdb.deletion_protection` | Verified | — |
| `aws.c2b.documentdb.multi_az` | Verified | — |
| `aws.c2b.documentdb.storage_encrypted` | Verified | — |
| `aws.c2b.drs.region_has_job` | Verified | — |
| `aws.c2b.dynamodb.capacity_autoscaling` | Verified | — |
| `aws.c2b.dynamodb.policy_not_cross_account` | Verified | — |
| `aws.c2b.dynamodb.sse_kms` | Verified | — |
| `aws.c2b.dynamodb.table_in_backup_selection_or_tag` | Verified | — |
| `aws.c2b.dynamodb.table_in_backup_selection_prowler` | Verified | — |
| `aws.c2b.dynamodb.table_protected_resource` | Verified | — |
| `aws.c2b.ecr.latest_image_no_medium_plus_findings` | Corrected | fail_when, pass_when |
| `aws.c2b.ecr.registry_automated_scanning` | Verified | — |
| `aws.c2b.ecr.registry_enhanced_scanning` | Verified | — |
| `aws.c2b.ecr.repository_not_public` | Verified | — |
| `aws.c2b.ecr.repository_policy_no_wildcard_principal` | Corrected | fail_when, pass_when |
| `aws.c2b.ecr.repository_policy_prohibit_public_perimeter` | Verified | — |
| `aws.c2b.ecs.all_containers_logging` | Verified | — |
| `aws.c2b.ecs.awsvpc_service_no_public_ip` | Corrected | fail_when, pass_when |
| `aws.c2b.ecs.cluster_has_active_services` | Verified | — |
| `aws.c2b.ecs.cluster_has_registered_instances` | Verified | — |
| `aws.c2b.ecs.cluster_instance_volumes_encrypted` | Verified | — |
| `aws.c2b.ecs.container_insights` | Verified | — |
| `aws.c2b.ecs.container_insights_setting` | Verified | — |
| `aws.c2b.ecs.container_instance_agents_connected` | Verified | — |
| `aws.c2b.ecs.container_instance_in_vpc` | Verified | — |
| `aws.c2b.ecs.fargate_latest_platform` | Verified | — |
| `aws.c2b.ecs.host_network_root_user` | Verified | — |
| `aws.c2b.ecs.logging_non_blocking` | Verified | — |
| `aws.c2b.ecs.no_credential_named_env_vars` | Verified | — |
| `aws.c2b.ecs.service_load_balancer_attached` | Verified | — |
| `aws.c2b.ecs.service_no_public_ip` | Corrected | fail_when, pass_when |
| `aws.c2b.ecs.task_set_no_public_ip` | Corrected | fail_when, pass_when |
| `aws.c2b.efs.access_point_root_directory` | Corrected | fail_when, pass_when |
| `aws.c2b.efs.access_point_user_identity` | Verified | — |
| `aws.c2b.efs.access_points_no_root_directory` | Verified | — |
| `aws.c2b.efs.access_points_posix_user` | Verified | — |
| `aws.c2b.efs.automatic_backups_enabled` | Verified | — |
| `aws.c2b.efs.backup_not_disabled` | Verified | — |
| `aws.c2b.efs.file_system_protected_resource` | Verified | — |
| `aws.c2b.efs.mount_target_subnet_no_auto_public_ip` | Verified | — |
| `aws.c2b.efs.multi_az_mount_targets` | Verified | — |
| `aws.c2b.efs.no_public_mount_targets` | Verified | — |
| `aws.c2b.efs.policy_enforces_ssl` | Verified | — |
| `aws.c2b.efs.policy_no_wildcard_allow` | Verified | — |
| `aws.c2b.efs.policy_not_open_to_vpc_clients` | Verified | — |
| `aws.c2b.efs.policy_prohibit_public_access` | Verified | — |
| `aws.c2b.eks.cluster_security_group_present` | Verified | — |
| `aws.c2b.eks.deletion_protection` | Verified | — |
| `aws.c2b.eks.endpoint_not_public` | Verified | — |
| `aws.c2b.eks.endpoint_not_world_open` | Verified | — |
| `aws.c2b.eks.secrets_encryption_configured` | Verified | — |
| `aws.c2b.eks.single_security_group` | Verified | — |
| `aws.c2b.eks.version_at_least_1_19` | Verified | — |
| `aws.c2b.eks.version_at_least_1_28` | Verified | — |
| `aws.c2b.eks.vpc_cni_network_policy` | Verified | — |
| `aws.c2b.elasticache.cluster_no_default_subnet_group` | Verified | — |
| `aws.c2b.elasticache.cluster_public_subnet` | Verified | — |
| `aws.c2b.elasticache.cluster_public_subnet_prowler` | Verified | — |
| `aws.c2b.elasticache.cmk_enabled` | Verified | — |
| `aws.c2b.elasticache.redis_auth_pre6` | Verified | — |
| `aws.c2b.elasticache.rg_auto_minor_version_upgrade` | Verified | — |
| `aws.c2b.elasticache.rg_backup_retention_15` | Verified | — |
| `aws.c2b.elasticache.rg_backup_retention_7` | Verified | — |
| `aws.c2b.elasticache.rg_multi_az` | Verified | — |
| `aws.c2b.elasticbeanstalk.enhanced_health` | Verified | — |
| `aws.c2b.elasticbeanstalk.managed_updates` | Corrected | fail_when, pass_when |
| `aws.c2b.elasticbeanstalk.stream_logs` | Corrected | fail_when, pass_when |
| `aws.c2b.elbv2.alb_http_redirect_default` | Verified | — |
| `aws.c2b.elbv2.alb_sg_outbound_rule` | Verified | — |
| `aws.c2b.elbv2.alb_waf_attached` | Verified | — |
| `aws.c2b.elbv2.alb_wafv2_attached` | Verified | — |
| `aws.c2b.elbv2.cross_zone_enabled` | Verified | — |
| `aws.c2b.elbv2.has_listeners` | Verified | — |
| `aws.c2b.elbv2.http_listeners_redirect_https` | Verified | — |
| `aws.c2b.elbv2.insecure_ssl_ciphers` | Verified | — |
| `aws.c2b.elbv2.internet_facing_open_sg` | Verified | — |
| `aws.c2b.elbv2.listener_certificate_30_days` | Verified | — |
| `aws.c2b.elbv2.listener_certificate_7_days` | Verified | — |
| `aws.c2b.elbv2.listener_fips_tls` | Verified | — |
| `aws.c2b.elbv2.listener_pqc_tls` | Verified | — |
| `aws.c2b.elbv2.listeners_acm_certificate` | Verified | — |
| `aws.c2b.elbv2.listeners_secure_protocol` | Verified | — |
| `aws.c2b.elbv2.nlb_tls_termination` | Verified | — |
| `aws.c2b.elbv2.not_internet_facing` | Corrected | pass_when |
| `aws.c2b.elbv2.recommended_tls_policy` | Verified | — |
| `aws.c2b.emr.block_public_access_enabled` | Verified | — |
| `aws.c2b.emr.block_public_access_only_port_22` | Verified | — |
| `aws.c2b.emr.cluster_at_rest_cse_custom` | Verified | — |
| `aws.c2b.emr.cluster_at_rest_encryption` | Verified | — |
| `aws.c2b.emr.cluster_at_rest_sse_kms` | Verified | — |
| `aws.c2b.emr.cluster_in_transit_encryption` | Verified | — |
| `aws.c2b.emr.cluster_kerberos_enabled` | Verified | — |
| `aws.c2b.emr.cluster_local_disk_cmk` | Verified | — |
| `aws.c2b.emr.cluster_local_disk_encryption` | Verified | — |
| `aws.c2b.emr.cluster_not_publicly_accessible` | Verified | — |
| `aws.c2b.emr.cluster_security_configuration` | Verified | — |
| `aws.c2b.emr.master_no_public_dns` | Verified | — |
| `aws.c2b.emr.master_subnet_no_auto_public_ip` | Verified | — |
| `aws.c2b.emr.security_configuration_at_rest` | Verified | — |
| `aws.c2b.emr.security_configuration_in_transit` | Verified | — |
| `aws.c2b.es.all_logs_to_cloudwatch` | Corrected | fail_when, pass_when |
| `aws.c2b.es.audit_logs_to_cloudwatch` | Corrected | fail_when, pass_when |
| `aws.c2b.es.error_logs_to_cloudwatch` | Corrected | evaluated, fail_when, pass_when |
| `aws.c2b.es.in_vpc` | Corrected | evaluated, fail_when, pass_when |
| `aws.c2b.es.internal_user_database_enabled` | Corrected | evaluated, fail_when, pass_when |
| `aws.c2b.es.policy_prohibit_public_access` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.c2b.es.tls_1_2_policy` | Corrected | evaluated, fail_when, pass_when |
| `aws.c2b.eventbridge.bus_policy_no_cross_account` | Corrected | fail_when, pass_when |
| `aws.c2b.eventbridge.bus_policy_not_public` | Corrected | fail_when, pass_when |
| `aws.c2b.eventbridge.bus_policy_prohibit_public_perimeter` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.c2b.eventbridge.custom_bus_policy_attached` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.c2b.eventbridge.global_endpoint_replication` | Corrected | fail_when, pass_when |
| `aws.c2b.eventbridge.schema_registry_no_cross_account` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.c2b.firehose.encrypted_at_rest_or_msk_source` | Corrected | fail_when, pass_when |
| `aws.c2b.fms.policies_compliant` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.c2b.lambda.env_vars_cmk` | Corrected | fail_when, pass_when |
| `aws.c2b.lambda.invoke_cloudtrail_logged` | Corrected | fail_when, pass_when |
| `aws.c2b.lambda.no_cross_account_layers` | Corrected | fail_when, pass_when |
| `aws.c2b.lambda.policy_not_public` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.c2b.lambda.runtime_not_obsolete` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.c2b.lambda.url_cors_no_wildcard` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.c2b.rds.cluster_snapshot_encrypted_any_engine` | Corrected | fail_when, pass_when |
| `aws.c2b.rds.db_snapshot_encrypted` | Corrected | fail_when, pass_when |
| `aws.cb.apigatewayv2.stage_access_logging` | Corrected | fail_when, pass_when |
| `aws.cb.firehose.server_side_encryption` | Corrected | fail_when, pass_when |
| `aws.cb.fsx.copy_tags_to_backups` | Corrected | evaluated, fail_when, pass_when |
| `aws.cb.fsx.copy_tags_to_volumes` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.fsx.lustre_copy_tags_to_backups` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.fsx.ontap_multi_az` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.fsx.openzfs_copy_tags_backups_and_volumes` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.fsx.openzfs_multi_az` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.fsx.protected_by_backup_plan` | Corrected | evaluated, fail_when, pass_when |
| `aws.cb.fsx.windows_multi_az_deployment` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.fsx.windows_multiple_subnets` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.glacier.vault_policy_no_public_principal` | Corrected | fail_when, pass_when |
| `aws.cb.glacier.vault_policy_prohibit_public_access` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.glacier.vault_policy_star_principal` | Corrected | fail_when, pass_when |
| `aws.cb.glue.catalog_metadata_encryption` | Corrected | fail_when, pass_when |
| `aws.cb.glue.catalog_metadata_sse_kms_with_tables` | Corrected | fail_when, pass_when |
| `aws.cb.glue.catalog_password_encryption` | Corrected | fail_when, pass_when |
| `aws.cb.glue.catalog_password_encryption_with_tables` | Corrected | fail_when, pass_when |
| `aws.cb.glue.catalog_policy_not_public` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.glue.connection_jdbc_enforce_ssl` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.glue.dev_endpoint_bookmarks_encryption` | Corrected | fail_when, pass_when |
| `aws.cb.glue.dev_endpoint_cloudwatch_encryption` | Corrected | fail_when, pass_when |
| `aws.cb.glue.dev_endpoint_s3_encryption_all_modes` | Corrected | fail_when, pass_when |
| `aws.cb.glue.dev_endpoint_s3_encryption_first_mode` | Corrected | fail_when, pass_when |
| `aws.cb.glue.job_bookmarks_encryption` | Corrected | fail_when, pass_when |
| `aws.cb.glue.job_cloudwatch_encryption` | Corrected | fail_when, pass_when |
| `aws.cb.glue.job_continuous_cloudwatch_logging` | Corrected | fail_when, pass_when |
| `aws.cb.glue.job_s3_encryption_all_modes` | Corrected | fail_when, pass_when |
| `aws.cb.glue.job_s3_encryption_first_mode` | Corrected | fail_when, pass_when |
| `aws.cb.glue.ml_transform_encryption_configured` | Corrected | fail_when, pass_when |
| `aws.cb.glue.ml_transform_user_data_encryption` | Corrected | fail_when, pass_when |
| `aws.cb.glue.spark_job_version_3` | Corrected | fail_when, pass_when |
| `aws.cb.inspector2.coverage_recently_scanned` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.inspector2.coverage_scan_active` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.inspector2.enabled_for_present_resources` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.inspector2.findings_within_max_age` | Corrected | description, fail_when, not_applicable_when, pass_when |
| `aws.cb.inspector2.kev_findings_within_due_date` | Corrected | description, fail_when, not_applicable_when, pass_when |
| `aws.cb.inspector2.no_active_findings` | Corrected | description, fail_when, not_applicable_when, pass_when |
| `aws.cb.inspector2.no_known_exploited_findings` | Corrected | description, fail_when, not_applicable_when, pass_when |
| `aws.cb.kafka.cmk_encryption_at_rest` | Corrected | fail_when, pass_when |
| `aws.cb.kafka.enhanced_monitoring` | Corrected | fail_when, pass_when |
| `aws.cb.kafka.latest_version` | Corrected | fail_when, pass_when |
| `aws.cb.kafka.mutual_tls_authentication` | Corrected | fail_when, pass_when |
| `aws.cb.kafka.public_access_disabled` | Corrected | fail_when, pass_when |
| `aws.cb.kafka.tls_client_and_in_cluster` | Corrected | fail_when, pass_when |
| `aws.cb.kafka.unauthenticated_access_disabled` | Corrected | fail_when, pass_when |
| `aws.cb.kinesis.customer_kms_key` | Corrected | fail_when, pass_when |
| `aws.cb.kinesis.kms_encryption` | Corrected | fail_when, pass_when |
| `aws.cb.kinesis.retention_at_least_168h` | Corrected | fail_when, pass_when |
| `aws.cb.kinesis.retention_exactly_168h` | Corrected | fail_when, pass_when |
| `aws.cb.lambda.cloudtrail_data_events` | Corrected | fail_when, pass_when |
| `aws.cb.lambda.kms_key_configured` | Corrected | fail_when, pass_when |
| `aws.cb.lambda.logging_config_present` | Corrected | fail_when, pass_when |
| `aws.cb.lambda.policy_no_wildcard_allow` | Corrected | fail_when, pass_when |
| `aws.cb.lambda.policy_prohibit_public_access_perimeter` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.lambda.runtime_not_deprecated_list` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.lambda.vpc_multiple_az` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.lightsail.database_not_public` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.lightsail.instance_auto_snapshot` | Corrected | fail_when, pass_when |
| `aws.cb.lightsail.instance_ipv6_disabled` | Corrected | fail_when, pass_when |
| `aws.cb.lightsail.instance_not_public` | Corrected | fail_when, pass_when |
| `aws.cb.lightsail.rdp_restricted` | Corrected | fail_when, pass_when |
| `aws.cb.lightsail.ssh_rdp_http_world_closed` | Corrected | fail_when, pass_when |
| `aws.cb.lightsail.ssh_restricted` | Corrected | fail_when, pass_when |
| `aws.cb.lightsail.static_ip_attached` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.macie.automated_discovery` | Corrected | fail_when, pass_when |
| `aws.cb.macie.enabled_where_buckets` | Corrected | fail_when, pass_when |
| `aws.cb.mediastore.container_policy_not_public` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.memorydb.auto_minor_version_upgrade` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.memorydb.tls_enabled` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.mq.activemq_active_standby` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.mq.activemq_audit_logs` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.mq.engine_logging` | Corrected | fail_when, pass_when |
| `aws.cb.mq.not_publicly_accessible` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.mq.rabbitmq_cluster_deployment` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.msk.client_broker_tls` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.mskconnect.log_delivery` | Corrected | fail_when, pass_when |
| `aws.cb.mskconnect.tls_to_cluster` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.neptune.audit_log_export` | Corrected | fail_when, pass_when |
| `aws.cb.neptune.backup_retention_7_days` | Corrected | fail_when, pass_when |
| `aws.cb.neptune.copy_tags_to_snapshot` | Corrected | fail_when, pass_when |
| `aws.cb.neptune.deletion_protection` | Corrected | fail_when, pass_when |
| `aws.cb.neptune.iam_authentication` | Corrected | fail_when, pass_when |
| `aws.cb.neptune.multi_az` | Corrected | fail_when, pass_when |
| `aws.cb.neptune.no_public_subnet_prowler` | Corrected | fail_when, pass_when |
| `aws.cb.neptune.no_public_subnet_steampipe` | Corrected | fail_when, pass_when |
| `aws.cb.neptune.snapshot_encrypted` | Corrected | fail_when, pass_when |
| `aws.cb.neptune.snapshot_not_public_prowler` | Corrected | fail_when, pass_when |
| `aws.cb.neptune.snapshot_restore_not_all_exact` | Corrected | fail_when, pass_when |
| `aws.cb.neptune.storage_encrypted` | Corrected | fail_when, pass_when |
| `aws.cb.opensearch.access_policy_not_public` | Corrected | fail_when, pass_when |
| `aws.cb.opensearch.audit_logs_enabled` | Corrected | fail_when, pass_when |
| `aws.cb.opensearch.cognito_dashboards_auth` | Corrected | fail_when, pass_when |
| `aws.cb.opensearch.cognito_or_saml_dashboards_auth` | Corrected | fail_when, pass_when |
| `aws.cb.opensearch.data_node_fault_tolerance` | Corrected | fail_when, pass_when |
| `aws.cb.opensearch.dedicated_master_nodes` | Corrected | fail_when, pass_when |
| `aws.cb.opensearch.enabled_logs_have_log_group` | Corrected | fail_when, pass_when |
| `aws.cb.opensearch.encryption_at_rest` | Corrected | fail_when, pass_when |
| `aws.cb.opensearch.enforce_https` | Corrected | fail_when, pass_when |
| `aws.cb.opensearch.fine_grained_access_control` | Corrected | fail_when, pass_when |
| `aws.cb.opensearch.in_vpc_private_subnets` | Corrected | fail_when, pass_when |
| `aws.cb.opensearch.internal_user_database_disabled` | Corrected | fail_when, pass_when |
| `aws.cb.opensearch.node_to_node_encryption` | Corrected | fail_when, pass_when |
| `aws.cb.opensearch.node_to_node_encryption_region_skip` | Corrected | fail_when, pass_when |
| `aws.cb.opensearch.service_software_current` | Corrected | fail_when, pass_when |
| `aws.cb.opensearch.slow_logs_enabled` | Corrected | fail_when, pass_when |
| `aws.cb.ram.shared_with_accounts_review` | Corrected | pass_when |
| `aws.cb.ram.shared_with_organization_units_review` | Corrected | pass_when |
| `aws.cb.ram.shared_with_organizations_review` | Corrected | pass_when |
| `aws.cb.rds.aurora_backtracking_configured` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.rds.aurora_cluster_protected_resource` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.rds.aurora_mysql_server_audit_logging` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.rds.aurora_postgres_local_file_read_versions` | Corrected | fail_when, pass_when |
| `aws.cb.rds.aurora_postgres_postgresql_log_export` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.rds.ca_certificate_not_expiring_7_days` | Corrected | fail_when, pass_when |
| `aws.cb.rds.ca_certificate_valid_3_months` | Corrected | fail_when, pass_when |
| `aws.cb.rds.cluster_backtrack_window_positive` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.rds.cluster_cloudwatch_log_exports` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.rds.cluster_cmk_encryption` | Corrected | fail_when, pass_when |
| `aws.cb.rds.cluster_critical_event_subscription` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.rds.cluster_engine_default_port_prowler` | Corrected | description, fail_when, pass_when |
| `aws.cb.rds.cluster_in_backup_plan_selection` | Corrected | fail_when, pass_when |
| `aws.cb.rds.cluster_log_exports_declared` | Corrected | fail_when, pass_when |
| `aws.cb.rds.cluster_snapshot_encrypted` | Corrected | fail_when, pass_when |
| `aws.cb.rds.cluster_snapshot_not_public_prowler` | Corrected | fail_when, pass_when |
| `aws.cb.rds.cluster_snapshot_restore_not_all_exact` | Corrected | fail_when, pass_when |
| `aws.cb.rds.cluster_snapshot_shared_accounts_review` | Corrected | fail_when, pass_when |
| `aws.cb.rds.cluster_tls_parameters` | Corrected | fail_when, pass_when |
| `aws.cb.rds.engine_version_available` | Corrected | fail_when, pass_when |
| `aws.cb.rds.instance_backup_retention_nonzero_all` | Corrected | fail_when, pass_when |
| `aws.cb.rds.instance_copy_tags_all_engines` | Corrected | fail_when, pass_when |
| `aws.cb.rds.instance_critical_event_subscription` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.rds.instance_default_master_username` | Corrected | fail_when, pass_when |
| `aws.cb.rds.instance_engine_default_port_prowler` | Corrected | fail_when, pass_when |
| `aws.cb.rds.instance_enhanced_monitoring_except_m1_small` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.rds.instance_extended_support` | Corrected | fail_when, pass_when |
| `aws.cb.rds.instance_iam_auth_all_engines` | Corrected | fail_when, pass_when |
| `aws.cb.rds.instance_iam_auth_supported_engines` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.rds.instance_in_backup_plan_selection` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.rds.instance_in_backup_selection_or_tag` | Corrected | fail_when, pass_when |
| `aws.cb.rds.instance_internet_exposed` | Corrected | fail_when, pass_when |
| `aws.cb.rds.instance_multi_az_non_aurora` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.rds.instance_multi_az_or_cluster` | Corrected | fail_when, pass_when |
| `aws.cb.rds.instance_no_public_subnet` | Corrected | fail_when, pass_when |
| `aws.cb.rds.instance_protected_resource` | Corrected | fail_when, pass_when |
| `aws.cb.rds.instance_snapshot_not_public_prowler` | Corrected | fail_when, pass_when |
| `aws.cb.rds.instance_snapshot_restore_not_all_exact` | Corrected | fail_when, pass_when |
| `aws.cb.rds.instance_snapshot_shared_accounts_review` | Corrected | fail_when, pass_when |
| `aws.cb.rds.instance_tls_parameters` | Corrected | fail_when, pass_when |
| `aws.cb.rds.mariadb_log_exports` | Corrected | fail_when, pass_when |
| `aws.cb.rds.mariadb_require_secure_transport` | Corrected | fail_when, pass_when |
| `aws.cb.rds.multi_az_cluster_minor_upgrade` | Corrected | fail_when, pass_when |
| `aws.cb.rds.parameter_group_critical_event_subscription` | Corrected | fail_when, not_applicable_when, pass_when |
| `aws.cb.rds.postgres_force_ssl_parameter` | Corrected | fail_when, pass_when |
| `aws.cb.rds.postgres_local_file_read_versions` | Corrected | fail_when, pass_when |
