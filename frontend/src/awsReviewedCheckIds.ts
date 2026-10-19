// Explicit source-reviewed AWS predicate scope; kept in parity with backend review guards.
export const AWS_REVIEWED_CHECK_IDS = new Set<string>([
  "aws.a.accessanalyzer.region_active",
  "aws.a.accessanalyzer.region_present",
  "aws.a.account.organization_member",
  "aws.a.account.security_contact_present",
  "aws.a.cloudtrail.bucket_access_logging",
  "aws.a.cloudtrail.bucket_mfa_delete",
  "aws.a.cloudtrail.cloudwatch_delivery_24h",
  "aws.a.cloudtrail.home_bucket_access_logging",
  "aws.a.cloudtrail.home_bucket_mfa_join",
  "aws.a.cloudtrail.home_cloudwatch_date",
  "aws.a.cloudtrail.home_kms_encryption",
  "aws.a.cloudtrail.home_logging_with_insights",
  "aws.a.cloudtrail.home_multiregion_cloudwatch_date",
  "aws.a.cloudtrail.insights_logging_trail",
  "aws.a.cloudtrail.joined_bucket_declared_public_grants",
  "aws.a.cloudwatch.agentcore_data_protection",
  "aws.a.cloudwatch.alarm_actions_enabled",
  "aws.a.cloudwatch.alarm_state_actions",
  "aws.a.cloudwatch.any_state_actions",
  "aws.a.cloudwatch.cross_account_role_absent",
  "aws.a.cloudwatch.finite_retention_365",
  "aws.a.cloudwatch.log_kms_encryption",
  "aws.a.cloudwatch.log_retention_at_least_365",
  "aws.a.config.region_recorder_enabled",
  "aws.a.guardduty.region_enabled",
  "aws.a.iam.active_key_age_90",
  "aws.a.iam.attached_policy_no_star_star",
  "aws.a.iam.console_key_created_at_setup",
  "aws.a.iam.group_no_cloudshell_full_access",
  "aws.a.iam.password_policy_expiry_at_most_90",
  "aws.a.iam.password_policy_lowercase",
  "aws.a.iam.password_policy_minimum_length_14",
  "aws.a.iam.password_policy_numbers",
  "aws.a.iam.password_policy_reuse_at_least_24",
  "aws.a.iam.password_policy_strong_min_length_14_reuse_24_age_90",
  "aws.a.iam.password_policy_strong_min_length_8",
  "aws.a.iam.password_policy_symbols",
  "aws.a.iam.password_policy_uppercase",
  "aws.a.iam.report_all_mfa",
  "aws.a.iam.report_console_mfa",
  "aws.a.iam.role_no_cloudshell_full_access",
  "aws.a.iam.root_console_summary_mfa",
  "aws.a.iam.root_hardware_mfa",
  "aws.a.iam.root_summary_mfa",
  "aws.a.iam.root_summary_no_keys",
  "aws.a.iam.server_certificate_expiry_date",
  "aws.a.iam.unused_credentials_45_days",
  "aws.a.iam.unused_credentials_90_days",
  "aws.a.iam.user_no_cloudshell_full_access",
  "aws.a.iam.user_no_direct_policies",
  "aws.a.iam.user_no_managed_policies",
  "aws.a.kms.rotation_source_eligibility",
  "aws.a.s3.default_encryption_configuration",
  "aws.b.backup.report_plan_presence",
  "aws.b.backup_plan.regional_presence",
  "aws.b.backup_vault.regional_presence",
  "aws.b.classic_elb.access_logs",
  "aws.b.classic_elb.connection_draining",
  "aws.b.classic_elb.cross_zone",
  "aws.b.cloudfront.access_logging",
  "aws.b.cloudfront.sni",
  "aws.b.cognito.admin_only_signup",
  "aws.b.cognito.deletion_protection",
  "aws.b.cognito.enforced_threat_protection",
  "aws.b.cognito.no_guest_identities",
  "aws.b.cognito.password_lowercase",
  "aws.b.cognito.password_number",
  "aws.b.cognito.password_symbol",
  "aws.b.cognito.password_uppercase",
  "aws.b.cognito.required_mfa",
  "aws.b.dms.automatic_minor_upgrade",
  "aws.b.dms.multi_az",
  "aws.b.dms.no_public_instance",
  "aws.b.docdb.deletion_protection",
  "aws.b.docdb.seven_day_backups",
  "aws.b.docdb.storage_encryption",
  "aws.b.dynamodb.deletion_protection",
  "aws.b.dynamodb.encryption_type",
  "aws.b.dynamodb.kms_description",
  "aws.b.dynamodb.point_in_time_recovery",
  "aws.b.ecr.all_tags_immutable",
  "aws.b.ecr.effective_scan_configuration",
  "aws.b.ecr.lifecycle_rules",
  "aws.b.ecr.source_some_immutability",
  "aws.b.efs.at_rest_encryption",
  "aws.b.efs.customer_managed_key",
  "aws.b.eks.audit_log_category",
  "aws.b.eks.disable_public_endpoint",
  "aws.b.eks.no_default_vpc",
  "aws.b.eks.secret_envelope_encryption",
  "aws.b.elasticache.at_rest",
  "aws.b.elasticache.automatic_failover",
  "aws.b.elasticache.automatic_minor_upgrade",
  "aws.b.elasticache.in_transit",
  "aws.b.inspector.admin_ec2_auto_enable",
  "aws.b.inspector.admin_ecr_auto_enable",
  "aws.b.inspector.admin_lambda_auto_enable",
  "aws.b.inspector.admin_lambda_code_auto_enable",
  "aws.b.inspector.ec2_organization_auto_enable",
  "aws.b.inspector.ecr_organization_auto_enable",
  "aws.b.inspector.lambda_code_organization_auto_enable",
  "aws.b.inspector.lambda_organization_auto_enable",
  "aws.b.lambda.active_tracing",
  "aws.b.lambda.insights_layer",
  "aws.b.lambda.reserved_concurrency",
  "aws.b.lambda.url_cors_single_wildcard",
  "aws.b.mq.automatic_minor_upgrade",
  "aws.b.neptune.backup_retention_seven_days",
  "aws.b.neptune_cluster.deletion_protection",
  "aws.b.neptune_cluster.iam_authentication",
  "aws.b.neptune_cluster.snapshot_tags",
  "aws.b.neptune_cluster.storage_encryption",
  "aws.b.rds.backup_retention_seven_days",
  "aws.b.rds.cluster_event_categories",
  "aws.b.rds.cluster_minor_upgrade",
  "aws.b.rds.engine_log_exports",
  "aws.b.rds.instance_event_categories",
  "aws.b.rds.parameter_group_event_categories",
  "aws.b.rds.proxy_tls",
  "aws.b.rds.security_group_event_categories",
  "aws.b.rds_cluster.iam_authentication",
  "aws.b.rds_cluster.multiple_az",
  "aws.b.rds_cluster.nondefault_admin",
  "aws.b.rds_instance.iam_authentication",
  "aws.b.rds_instance.minor_upgrade",
  "aws.b.rds_instance.nondefault_admin",
  "aws.b.rds_instance.snapshot_tags",
  "aws.b.redshift.allow_version_upgrade",
  "aws.b.redshift.audit_logging",
  "aws.b.redshift.enhanced_vpc_routing",
  "aws.b.redshift.no_public_endpoint",
  "aws.b.redshift.snapshots_seven_days",
  "aws.b.ssm.document_not_public",
  "aws.b.ssm.parameter_secure_type",
  "aws.c2b.acm.in_use_not_expiring_7_days",
  "aws.c2b.acm.in_use_secure_key_algorithm",
  "aws.c2b.acm.in_use_transparency_logging",
  "aws.c2b.acmpca.pqc_key_algorithm",
  "aws.c2b.acmpca.root_ca_disabled",
  "aws.c2b.apigateway.authorizers_or_authorized_methods",
  "aws.c2b.apigateway.methods_authorization_type",
  "aws.c2b.apigateway.methods_request_validator",
  "aws.c2b.apigateway.public_rest_api_authorizer",
  "aws.c2b.apigateway.rest_api_has_authorizer",
  "aws.c2b.apigateway.rest_api_policy_not_public",
  "aws.c2b.apigateway.rest_api_private_only",
  "aws.c2b.apigateway.stage_cache_encrypted",
  "aws.c2b.apigateway.stage_execution_logging",
  "aws.c2b.appstream.no_default_internet",
  "aws.c2b.appsync.cache_at_rest_encryption",
  "aws.c2b.appsync.cache_in_transit_encryption",
  "aws.c2b.athena.results_encrypted",
  "aws.c2b.athena.results_encrypted_prowler",
  "aws.c2b.autoscaling.elb_health_check",
  "aws.c2b.autoscaling.group_lc_no_public_ip",
  "aws.c2b.autoscaling.lc_no_public_ip",
  "aws.c2b.backup.recovery_point_encrypted",
  "aws.c2b.backup.vault_encrypted",
  "aws.c2b.bedrock.agent_guardrail",
  "aws.c2b.bedrock.api_key_long_term_expired",
  "aws.c2b.bedrock.custom_model_cmk",
  "aws.c2b.bedrock.guardrail_contextual_grounding",
  "aws.c2b.bedrock.guardrail_prompt_attack_high",
  "aws.c2b.bedrock.guardrail_sensitive_information_filter",
  "aws.c2b.bedrock.guardrails_configured",
  "aws.c2b.bedrock.invocation_logs_encrypted",
  "aws.c2b.bedrock.knowledge_base_data_sources_cmk",
  "aws.c2b.bedrock.model_invocation_logging",
  "aws.c2b.bedrock.prompt_cmk",
  "aws.c2b.bedrock.prompt_management_exists",
  "aws.c2b.bedrock.role_no_full_access_policy",
  "aws.c2b.bedrock.vpc_endpoints",
  "aws.c2b.classic_elb.acm_certificates",
  "aws.c2b.classic_elb.ssl_listeners_only",
  "aws.c2b.cloudformation.cdktoolkit_bootstrap_version",
  "aws.c2b.cloudformation.drift_in_sync",
  "aws.c2b.cloudformation.notifications",
  "aws.c2b.cloudformation.rollback_enabled",
  "aws.c2b.cloudformation.termination_protection_all_stacks",
  "aws.c2b.cloudformation.termination_protection_root_stacks",
  "aws.c2b.cloudfront.custom_ssl_certificate",
  "aws.c2b.cloudfront.logging_any",
  "aws.c2b.cloudfront.origin_no_deprecated_ssl",
  "aws.c2b.cloudfront.origin_traffic_encrypted",
  "aws.c2b.cloudfront.recommended_tls_policy",
  "aws.c2b.cloudfront.s3_origin_bucket_exists",
  "aws.c2b.codeartifact.domain_policy_prohibit_public_perimeter",
  "aws.c2b.codeartifact.internal_packages_block_upstream",
  "aws.c2b.codeartifact.repository_policy_prohibit_public_perimeter",
  "aws.c2b.codebuild.buildspec_not_user_controlled",
  "aws.c2b.codebuild.buildspec_not_yml_file",
  "aws.c2b.codebuild.built_within_90_days",
  "aws.c2b.codebuild.invoked_last_90_days",
  "aws.c2b.codebuild.no_plaintext_sensitive_env_names",
  "aws.c2b.codebuild.project_private",
  "aws.c2b.codebuild.report_group_export_encrypted",
  "aws.c2b.codebuild.s3_logs_encrypted_when_enabled",
  "aws.c2b.codebuild.source_repo_oauth",
  "aws.c2b.codebuild.source_url_no_credentials",
  "aws.c2b.codebuild.webhook_filters_anchored",
  "aws.c2b.codedeploy.lambda_not_all_at_once",
  "aws.c2b.cognito.clients_prevent_user_existence_errors",
  "aws.c2b.cognito.clients_token_revocation",
  "aws.c2b.cognito.waf_web_acl_associated",
  "aws.c2b.connect.contact_flow_logs",
  "aws.c2b.dax.encryption_at_rest",
  "aws.c2b.dax.encryption_in_transit",
  "aws.c2b.directoryservice.certificate_not_within_90_days",
  "aws.c2b.directoryservice.ldap_certificate_over_90_days",
  "aws.c2b.directoryservice.log_forwarding",
  "aws.c2b.directoryservice.manual_snapshot_quota",
  "aws.c2b.directoryservice.radius_mfa_enabled",
  "aws.c2b.directoryservice.radius_ms_chapv2",
  "aws.c2b.directoryservice.sns_notifications",
  "aws.c2b.dms.public_instance_open_sg",
  "aws.c2b.docdb.cluster_tls_required",
  "aws.c2b.docdb.instance_storage_encrypted",
  "aws.c2b.documentdb.deletion_protection",
  "aws.c2b.documentdb.multi_az",
  "aws.c2b.documentdb.storage_encrypted",
  "aws.c2b.ecr.latest_image_no_medium_plus_findings",
  "aws.c2b.ecr.registry_automated_scanning",
  "aws.c2b.ecr.registry_enhanced_scanning",
  "aws.c2b.ecr.repository_not_public",
  "aws.c2b.ecr.repository_policy_no_wildcard_principal",
  "aws.c2b.ecr.repository_policy_prohibit_public_perimeter",
  "aws.c2b.ecs.all_containers_logging",
  "aws.c2b.ecs.awsvpc_service_no_public_ip",
  "aws.c2b.ecs.cluster_instance_volumes_encrypted",
  "aws.c2b.ecs.host_network_root_user",
  "aws.c2b.ecs.logging_non_blocking",
  "aws.c2b.ecs.service_no_public_ip",
  "aws.c2b.ecs.task_set_no_public_ip",
  "aws.c2b.efs.mount_target_subnet_no_auto_public_ip",
  "aws.c2b.efs.no_public_mount_targets",
  "aws.c2b.efs.policy_enforces_ssl",
  "aws.c2b.efs.policy_not_open_to_vpc_clients",
  "aws.c2b.eks.endpoint_not_world_open",
  "aws.c2b.eks.vpc_cni_network_policy",
  "aws.c2b.elasticache.cluster_public_subnet",
  "aws.c2b.elasticache.cluster_public_subnet_prowler",
  "aws.c2b.elasticache.cmk_enabled",
  "aws.c2b.elasticache.redis_auth_pre6",
  "aws.c2b.elasticache.rg_auto_minor_version_upgrade",
  "aws.c2b.elasticache.rg_multi_az",
  "aws.c2b.elbv2.alb_http_redirect_default",
  "aws.c2b.elbv2.alb_sg_outbound_rule",
  "aws.c2b.elbv2.alb_waf_attached",
  "aws.c2b.elbv2.alb_wafv2_attached",
  "aws.c2b.elbv2.has_listeners",
  "aws.c2b.elbv2.http_listeners_redirect_https",
  "aws.c2b.elbv2.insecure_ssl_ciphers",
  "aws.c2b.elbv2.internet_facing_open_sg",
  "aws.c2b.elbv2.listener_certificate_30_days",
  "aws.c2b.elbv2.listener_certificate_7_days",
  "aws.c2b.elbv2.listener_fips_tls",
  "aws.c2b.elbv2.listener_pqc_tls",
  "aws.c2b.elbv2.listeners_acm_certificate",
  "aws.c2b.elbv2.listeners_secure_protocol",
  "aws.c2b.elbv2.nlb_tls_termination",
  "aws.c2b.elbv2.not_internet_facing",
  "aws.c2b.elbv2.recommended_tls_policy",
  "aws.c2b.emr.block_public_access_only_port_22",
  "aws.c2b.emr.cluster_at_rest_cse_custom",
  "aws.c2b.emr.cluster_at_rest_encryption",
  "aws.c2b.emr.cluster_at_rest_sse_kms",
  "aws.c2b.emr.cluster_in_transit_encryption",
  "aws.c2b.emr.cluster_local_disk_cmk",
  "aws.c2b.emr.cluster_local_disk_encryption",
  "aws.c2b.emr.cluster_not_publicly_accessible",
  "aws.c2b.emr.master_no_public_dns",
  "aws.c2b.emr.master_subnet_no_auto_public_ip",
  "aws.c2b.emr.security_configuration_at_rest",
  "aws.c2b.emr.security_configuration_in_transit",
  "aws.c2b.es.internal_user_database_enabled",
  "aws.c2b.eventbridge.bus_policy_no_cross_account",
  "aws.c2b.eventbridge.bus_policy_not_public",
  "aws.c2b.eventbridge.bus_policy_prohibit_public_perimeter",
  "aws.c2b.eventbridge.custom_bus_policy_attached",
  "aws.c2b.eventbridge.global_endpoint_replication",
  "aws.c2b.eventbridge.schema_registry_no_cross_account",
  "aws.c2b.fms.policies_compliant",
  "aws.c2b.lambda.env_vars_cmk",
  "aws.c2b.lambda.policy_not_public",
  "aws.c2b.rds.cluster_snapshot_encrypted_any_engine",
  "aws.c2b.rds.db_snapshot_encrypted",
  "aws.cb.glue.dev_endpoint_s3_encryption_all_modes",
  "aws.cb.glue.job_s3_encryption_all_modes",
  "aws.cb.glue.job_s3_encryption_first_mode",
  "aws.cb.inspector2.coverage_recently_scanned",
  "aws.cb.inspector2.coverage_scan_active",
  "aws.cb.inspector2.enabled_for_present_resources",
  "aws.cb.inspector2.findings_within_max_age",
  "aws.cb.inspector2.kev_findings_within_due_date",
  "aws.cb.inspector2.no_active_findings",
  "aws.cb.inspector2.no_known_exploited_findings",
  "aws.cb.kafka.latest_version",
  "aws.cb.lightsail.database_not_public",
  "aws.cb.lightsail.static_ip_attached",
  "aws.cb.macie.automated_discovery",
  "aws.cb.macie.enabled_where_buckets",
  "aws.cb.memorydb.auto_minor_version_upgrade",
  "aws.cb.memorydb.tls_enabled",
  "aws.cb.mq.not_publicly_accessible",
  "aws.cb.mskconnect.tls_to_cluster",
  "aws.cb.neptune.copy_tags_to_snapshot",
  "aws.cb.neptune.deletion_protection",
  "aws.cb.neptune.iam_authentication",
  "aws.cb.neptune.multi_az",
  "aws.cb.neptune.storage_encrypted",
  "aws.cb.rds.aurora_mysql_server_audit_logging",
  "aws.cb.rds.cluster_cmk_encryption",
  "aws.cb.rds.instance_iam_auth_all_engines",
  "aws.cb.rds.instance_no_public_subnet",
  "aws.cb.rds.instance_tls_parameters",
  "aws.cb.redshift.allow_version_upgrade",
  "aws.cb.redshift.encrypted",
  "aws.cb.redshift.enhanced_vpc_routing",
  "aws.cb.redshift.multi_az",
  "aws.cb.redshift.not_publicly_accessible",
  "aws.cb.redshiftserverless.enhanced_vpc_routing",
  "aws.cb.redshiftserverless.not_publicly_accessible",
  "aws.cb.resourceexplorer2.index_exists",
  "aws.cb.rolesanywhere.trust_anchor_pqc",
  "aws.cb.route53.domain_auto_renew",
  "aws.cb.route53.domain_expires_after_30_days",
  "aws.cb.route53.domain_expires_after_7_days",
  "aws.cb.route53.domain_not_expired",
  "aws.cb.route53.domain_privacy_protection",
  "aws.cb.route53.domain_transfer_lock",
  "aws.cb.route53.public_zone_query_logging",
  "aws.cb.sagemaker.model_network_isolation",
  "aws.cb.sagemaker.notebook_no_direct_internet",
  "aws.cb.sagemaker.notebook_root_access_disabled",
  "aws.cb.sagemaker.training_intercontainer_encryption",
  "aws.cb.sagemaker.training_network_isolation",
  "aws.cb.secretsmanager.accessed_within_90_calendar_days",
  "aws.cb.secretsmanager.accessed_within_90_days",
  "aws.cb.secretsmanager.changed_within_365_days",
  "aws.cb.secretsmanager.changed_within_90_days",
  "aws.cb.secretsmanager.cmk_encryption",
  "aws.cb.secretsmanager.policy_not_public",
  "aws.cb.secretsmanager.policy_prohibit_public_access_perimeter",
  "aws.cb.secretsmanager.rotated_as_scheduled",
  "aws.cb.secretsmanager.rotated_within_90_days",
  "aws.cb.secretsmanager.rotation_lambda",
  "aws.cb.secretsmanager.rotation_rules_present",
  "aws.cb.secretsmanager.used_after_creation_day",
  "aws.cb.servicecatalog.no_account_shares",
  "aws.cb.servicecatalog.org_member_no_account_shares",
  "aws.cb.shield.classic_load_balancer_protected",
  "aws.cb.shield.cloudfront_protected",
  "aws.cb.shield.elastic_ip_protected",
  "aws.cb.shield.global_accelerator_protected",
  "aws.cb.shield.internet_facing_alb_protected",
  "aws.cb.shield.route53_zone_protected",
  "aws.cb.ssm.automation_logs_to_cloudwatch",
  "aws.cb.ssm.block_public_document_sharing",
  "aws.cb.ssm.document_shared_only_with_trusted",
  "aws.cb.ssm.instance_association_compliant",
  "aws.cb.ssm.instance_patch_compliant",
  "aws.cb.ssm.resource_compliance_summary_compliant",
  "aws.cb.ssmincidents.active_with_response_plans",
  "aws.cb.trustedadvisor.check_ok",
  "aws.cb.trustedadvisor.premium_support",
  "aws.cb.waf.rule_group_not_empty",
  "aws.cb.waf.rule_has_conditions",
  "aws.cb.waf.web_acl_has_rules",
  "aws.cb.waf.web_acl_logging",
  "aws.cb.wafregional.rule_group_not_empty",
  "aws.cb.wafregional.rule_has_conditions",
  "aws.cb.wafregional.web_acl_associated",
  "aws.cb.wafregional.web_acl_has_rules",
  "aws.cb.wafregional.web_acl_logging",
  "aws.cb.wafv2.rule_group_metrics",
  "aws.cb.wafv2.web_acl_has_rules",
  "aws.cb.wafv2.web_acl_has_rules_or_fms_groups",
  "aws.cb.wafv2.web_acl_logging",
  "aws.cb.wafv2.web_acl_rule_metrics",
  "aws.cb.wellarchitected.no_high_or_medium_risks",
  "aws.claude2_a.cloudtrail.threat_detection_enumeration",
  "aws.claude2_a.cloudtrail.threat_detection_llm_jacking",
  "aws.claude2_a.cloudtrail.threat_detection_privilege_escalation",
  "aws.claude2_a.cloudwatch.cross_account_sharing_role_absent",
  "aws.claude_a.accessanalyzer.active_without_findings",
  "aws.claude_a.cloudtrail.account_has_logging_multi_region_trail",
  "aws.claude_a.guardduty.detector_no_findings",
  "aws.claude_a.guardduty.ebs_malware_protection_feature",
  "aws.claude_a.guardduty.ec2_runtime_agent_management",
  "aws.claude_a.guardduty.ecs_runtime_agent_management",
  "aws.claude_a.guardduty.eks_runtime_monitoring_feature",
  "aws.claude_a.guardduty.finding_archived",
  "aws.claude_a.guardduty.prowler_ai_protection",
  "aws.claude_a.guardduty.prowler_centrally_managed",
  "aws.claude_a.guardduty.prowler_delegated_admin_region",
  "aws.claude_a.guardduty.prowler_ec2_malware_protection",
  "aws.claude_a.guardduty.prowler_eks_audit_logs",
  "aws.claude_a.guardduty.prowler_eks_runtime_monitoring",
  "aws.claude_a.guardduty.prowler_lambda_protection",
  "aws.claude_a.guardduty.prowler_no_high_severity_findings",
  "aws.claude_a.guardduty.prowler_rds_protection",
  "aws.claude_a.guardduty.prowler_runtime_monitoring",
  "aws.claude_a.guardduty.prowler_s3_protection",
  "aws.claude_a.guardduty.region_centrally_configured",
  "aws.claude_a.iam.access_key_age_365",
  "aws.claude_a.iam.access_keys_rotated_90",
  "aws.claude_a.iam.access_keys_used_45",
  "aws.claude_a.iam.admin_user_has_mfa",
  "aws.claude_a.iam.attached_policy_no_star_star",
  "aws.claude_a.iam.aws_managed_policy_attached_to_role",
  "aws.claude_a.iam.cloudshell_full_access_not_attached",
  "aws.claude_a.iam.console_password_used_45",
  "aws.claude_a.iam.custom_attached_policy_no_star_star",
  "aws.claude_a.iam.custom_policy_attached_to_role",
  "aws.claude_a.iam.custom_policy_in_use",
  "aws.claude_a.iam.custom_policy_kms_decrypt_restricted",
  "aws.claude_a.iam.custom_policy_no_blocked_kms_actions",
  "aws.claude_a.iam.custom_policy_no_cloudtrail_star",
  "aws.claude_a.iam.custom_policy_no_kms_star",
  "aws.claude_a.iam.custom_policy_no_service_wildcard",
  "aws.claude_a.iam.custom_policy_no_star_star",
  "aws.claude_a.iam.custom_unattached_policy_no_star_star",
  "aws.claude_a.iam.group_inline_kms_decrypt_restricted",
  "aws.claude_a.iam.group_inline_no_admin",
  "aws.claude_a.iam.group_inline_no_blocked_kms_actions",
  "aws.claude_a.iam.group_no_cloudshell_full_access",
  "aws.claude_a.iam.group_no_inline_policies",
  "aws.claude_a.iam.group_not_empty",
  "aws.claude_a.iam.no_unused_initial_access_key",
  "aws.claude_a.iam.not_two_active_keys",
  "aws.claude_a.iam.policy_in_use",
  "aws.claude_a.iam.prowler_admin_group_members_mfa",
  "aws.claude_a.iam.prowler_aws_attached_policy_no_admin",
  "aws.claude_a.iam.prowler_console_password_used_45",
  "aws.claude_a.iam.prowler_customer_attached_policy_no_admin",
  "aws.claude_a.iam.prowler_customer_policy_no_cloudtrail_full_access",
  "aws.claude_a.iam.prowler_customer_policy_no_kms_full_access",
  "aws.claude_a.iam.prowler_customer_policy_no_marketplace_subscribe",
  "aws.claude_a.iam.prowler_customer_policy_no_permissive_role_assumption",
  "aws.claude_a.iam.prowler_customer_policy_no_privilege_escalation",
  "aws.claude_a.iam.prowler_customer_unattached_policy_no_admin",
  "aws.claude_a.iam.prowler_group_inline_no_admin",
  "aws.claude_a.iam.prowler_group_inline_no_cloudtrail_full_access",
  "aws.claude_a.iam.prowler_group_inline_no_kms_full_access",
  "aws.claude_a.iam.prowler_group_inline_no_marketplace_subscribe",
  "aws.claude_a.iam.prowler_group_inline_no_privilege_escalation",
  "aws.claude_a.iam.prowler_group_no_administratoraccess",
  "aws.claude_a.iam.prowler_policy_agentcore_token_scoped",
  "aws.claude_a.iam.prowler_policy_passrole_agentcore_restricted",
  "aws.claude_a.iam.prowler_role_confused_deputy_prevented",
  "aws.claude_a.iam.prowler_role_inline_no_admin",
  "aws.claude_a.iam.prowler_role_inline_no_cloudtrail_full_access",
  "aws.claude_a.iam.prowler_role_inline_no_kms_full_access",
  "aws.claude_a.iam.prowler_role_inline_no_marketplace_subscribe",
  "aws.claude_a.iam.prowler_role_inline_no_privilege_escalation",
  "aws.claude_a.iam.prowler_role_no_administratoraccess",
  "aws.claude_a.iam.prowler_role_readonly_not_cross_account",
  "aws.claude_a.iam.prowler_role_service_trust_bound_to_account",
  "aws.claude_a.iam.prowler_root_hardware_mfa",
  "aws.claude_a.iam.prowler_user_hardware_mfa",
  "aws.claude_a.iam.prowler_user_inline_no_admin",
  "aws.claude_a.iam.prowler_user_inline_no_cloudtrail_full_access",
  "aws.claude_a.iam.prowler_user_inline_no_kms_full_access",
  "aws.claude_a.iam.prowler_user_inline_no_marketplace_subscribe",
  "aws.claude_a.iam.prowler_user_inline_no_privilege_escalation",
  "aws.claude_a.iam.prowler_user_no_administratoraccess",
  "aws.claude_a.iam.role_bedrock_access_not_stale",
  "aws.claude_a.iam.role_inline_kms_decrypt_restricted",
  "aws.claude_a.iam.role_inline_no_admin",
  "aws.claude_a.iam.role_inline_no_blocked_kms_actions",
  "aws.claude_a.iam.role_no_administrator_access",
  "aws.claude_a.iam.role_no_cloudshell_full_access",
  "aws.claude_a.iam.role_no_inline_policies",
  "aws.claude_a.iam.role_readonly_not_cross_account",
  "aws.claude_a.iam.role_trust_not_public",
  "aws.claude_a.iam.role_used_within_60_days",
  "aws.claude_a.iam.root_console_has_mfa",
  "aws.claude_a.iam.root_credentials_management",
  "aws.claude_a.iam.saml_provider_present",
  "aws.claude_a.iam.securityaudit_role_exists",
  "aws.claude_a.iam.server_certificate_not_expired_now",
  "aws.claude_a.iam.support_role_exists",
  "aws.claude_a.iam.user_bedrock_access_not_stale",
  "aws.claude_a.iam.user_in_group",
  "aws.claude_a.iam.user_inline_kms_decrypt_restricted",
  "aws.claude_a.iam.user_inline_no_admin",
  "aws.claude_a.iam.user_inline_no_assume_role_text",
  "aws.claude_a.iam.user_inline_no_blocked_kms_actions",
  "aws.claude_a.iam.user_long_lived_keys_only_iam_sts",
  "aws.claude_a.iam.user_no_cloudshell_full_access",
  "aws.claude_a.iam.user_no_inline_policies",
  "aws.claude_a.iam.user_one_active_key",
  "aws.claude_a.iam.user_sagemaker_access_not_stale",
  "aws.claude_a.kms.customer_key_enabled_or_pending_deletion",
  "aws.claude_a.kms.customer_key_not_pending_deletion",
  "aws.claude_a.kms.key_policy_not_public",
  "aws.claude_a.kms.prowler_cmk_rotation",
  "aws.claude_a.kms.prowler_cmk_single_region",
  "aws.claude_a.kms.prowler_cmk_used",
  "aws.claude_a.kms.prowler_key_not_public",
  "aws.claude_a.networkfirewall.deletion_protection",
  "aws.claude_a.networkfirewall.firewall_fragment_default",
  "aws.claude_a.networkfirewall.firewall_full_packets_default",
  "aws.claude_a.networkfirewall.firewall_policy_has_rule_groups",
  "aws.claude_a.networkfirewall.in_use_vpc_has_firewall",
  "aws.claude_a.networkfirewall.in_vpc",
  "aws.claude_a.networkfirewall.logging",
  "aws.claude_a.networkfirewall.multi_az",
  "aws.claude_a.networkfirewall.policy_fragment_default",
  "aws.claude_a.networkfirewall.policy_full_packets_default",
  "aws.claude_a.networkfirewall.policy_has_rule_groups",
  "aws.claude_a.networkfirewall.stateless_rule_group_not_empty",
  "aws.claude_a.networkfirewall.subnet_change_protection",
  "aws.claude_a.organizations.ai_services_opt_out",
  "aws.claude_a.organizations.scp_restricts_regions",
  "aws.claude_a.organizations.tag_policy_attached",
  "aws.claude_a.s3.default_encryption_kms_key",
  "aws.claude_a.s3.object_level_logging",
  "aws.claude_a.s3.policy_restrict_public_access",
  "aws.claude_a.s3.protected_by_macie",
  "aws.claude_a.s3.prowler_cross_region_replication",
  "aws.claude_a.s3.prowler_public_access",
  "aws.claude_a.s3.restrict_public_read",
  "aws.claude_a.s3.static_website_disabled",
  "aws.claude_a.securityhub.enabled_with_standard_or_integration",
  "aws.claude_a.securityhub.prowler_delegated_admin_region",
  "aws.claude_a.vpc.block_public_access_igw",
  "aws.claude_a.vpc.default_sg_in_use_no_rules",
  "aws.claude_a.vpc.default_sg_no_rules",
  "aws.claude_a.vpc.endpoint_policy_trust_boundary",
  "aws.claude_a.vpc.endpoint_service_acceptance_required",
  "aws.claude_a.vpc.endpoint_service_principals_trusted",
  "aws.claude_a.vpc.flow_logs_active",
  "aws.claude_a.vpc.gateway_endpoint_policy_not_open",
  "aws.claude_a.vpc.igw_attached",
  "aws.claude_a.vpc.in_use_subnet_no_auto_public_ip",
  "aws.claude_a.vpc.in_use_vpc_ec2_endpoint",
  "aws.claude_a.vpc.in_use_vpc_has_flow_log",
  "aws.claude_a.vpc.in_use_vpc_public_and_private_subnets",
  "aws.claude_a.vpc.in_use_vpc_subnets_multi_az",
  "aws.claude_a.vpc.interface_endpoint_ecr_api",
  "aws.claude_a.vpc.interface_endpoint_ecr_dkr",
  "aws.claude_a.vpc.interface_endpoint_multi_az",
  "aws.claude_a.vpc.interface_endpoint_ssm",
  "aws.claude_a.vpc.interface_endpoint_ssm_contacts",
  "aws.claude_a.vpc.interface_endpoint_ssm_incidents",
  "aws.claude_a.vpc.launch_wizard_sg_not_attached",
  "aws.claude_a.vpc.nacl_associated",
  "aws.claude_a.vpc.nacl_no_world_all_ports",
  "aws.claude_a.vpc.nacl_no_world_remote_admin",
  "aws.claude_a.vpc.nacl_no_world_tcp_22",
  "aws.claude_a.vpc.nacl_no_world_tcp_3389",
  "aws.claude_a.vpc.nondefault_nacl_associated",
  "aws.claude_a.vpc.nondefault_vpcs_in_multiple_regions",
  "aws.claude_a.vpc.peering_route_tables_least_privilege",
  "aws.claude_a.vpc.peering_routes_least_privilege",
  "aws.claude_a.vpc.peering_same_account_active",
  "aws.claude_a.vpc.public_and_private_subnets",
  "aws.claude_a.vpc.route_table_no_default_igw_route",
  "aws.claude_a.vpc.sg_attached_to_eni",
  "aws.claude_a.vpc.sg_attached_to_eni_or_instance",
  "aws.claude_a.vpc.sg_in_use_anywhere",
  "aws.claude_a.vpc.sg_name_not_launch_wizard",
  "aws.claude_a.vpc.sg_no_public_ip_any_port",
  "aws.claude_a.vpc.sg_no_wide_public_ipv4",
  "aws.claude_a.vpc.sg_no_world_all_traffic",
  "aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis",
  "aws.claude_a.vpc.sg_no_world_cassandra",
  "aws.claude_a.vpc.sg_no_world_elasticsearch_kibana",
  "aws.claude_a.vpc.sg_no_world_ftp",
  "aws.claude_a.vpc.sg_no_world_high_risk_tcp_ports",
  "aws.claude_a.vpc.sg_no_world_kafka",
  "aws.claude_a.vpc.sg_no_world_memcached",
  "aws.claude_a.vpc.sg_no_world_mongodb",
  "aws.claude_a.vpc.sg_no_world_mysql",
  "aws.claude_a.vpc.sg_no_world_oracle",
  "aws.claude_a.vpc.sg_no_world_postgres",
  "aws.claude_a.vpc.sg_no_world_rdp",
  "aws.claude_a.vpc.sg_no_world_redis",
  "aws.claude_a.vpc.sg_no_world_sqlserver",
  "aws.claude_a.vpc.sg_no_world_ssh",
  "aws.claude_a.vpc.sg_no_world_telnet",
  "aws.claude_a.vpc.sg_rule_count_within_50",
  "aws.claude_a.vpc.sg_world_any_cifs",
  "aws.claude_a.vpc.sg_world_any_kafka",
  "aws.claude_a.vpc.sg_world_any_kibana",
  "aws.claude_a.vpc.sg_world_any_redis",
  "aws.claude_a.vpc.sg_world_any_remote_admin",
  "aws.claude_a.vpc.sg_world_v4_cassandra",
  "aws.claude_a.vpc.sg_world_v4_common20",
  "aws.claude_a.vpc.sg_world_v4_common6",
  "aws.claude_a.vpc.sg_world_v4_memcached",
  "aws.claude_a.vpc.sg_world_v4_mongodb",
  "aws.claude_a.vpc.sg_world_v4_no_tcp_udp",
  "aws.claude_a.vpc.sg_world_v4_only_80_443",
  "aws.claude_a.vpc.sg_world_v4_oracle",
  "aws.claude_a.vpc.sg_world_v4_rdp",
  "aws.claude_a.vpc.sg_world_v4_ssh",
  "aws.claude_a.vpc.sg_world_v6_remote_admin",
  "aws.claude_a.vpc.subnet_no_auto_public_ip",
  "aws.claude_a.vpc.subnets_in_multiple_azs",
  "aws.claude_a.vpc.vpc_endpoint_ec2",
  "aws.claude_a.vpc.vpc_has_subnets",
  "aws.claude_a.vpc.vpcs_in_multiple_regions",
  "aws.claude_a.vpc.vpn_both_tunnels_up",
  "aws.claude_a.vpc.vpn_tunnel_logging",
  "aws.cloudtrail.log_validation",
  "aws.cloudtrail.logging",
  "aws.cloudtrail.management_events",
  "aws.cloudtrail.multi_region",
  "aws.ebs.encryption",
  "aws.ecr.immutable_tags",
  "aws.ecr.scan_on_push",
  "aws.eks.private_endpoint",
  "aws.eks.secrets_encryption",
  "aws.elbv2.access_logging",
  "aws.elbv2.desync_mitigation",
  "aws.elbv2.drop_invalid_headers",
  "aws.gap.account.distinct_primary_billing_operations_security_contacts",
  "aws.gap.cloudtrail.bedrock_api_logging",
  "aws.gap.cloudtrail.multi_region_read_write_management",
  "aws.gap.cloudtrail.region_logging_management_events",
  "aws.gap.cloudtrail.s3_all_buckets_read_data_events",
  "aws.gap.cloudtrail.s3_all_buckets_write_data_events",
  "aws.gap.cloudtrail.trail_security_best_practices",
  "aws.gap.cloudwatch.cis_alarm.cloudtrail_configuration_changes",
  "aws.gap.cloudwatch.cis_alarm.cmk_disable_or_scheduled_deletion",
  "aws.gap.cloudwatch.cis_alarm.config_configuration_changes",
  "aws.gap.cloudwatch.cis_alarm.console_authentication_failures",
  "aws.gap.cloudwatch.cis_alarm.console_sign_in_without_mfa",
  "aws.gap.cloudwatch.cis_alarm.iam_policy_changes",
  "aws.gap.cloudwatch.cis_alarm.network_acl_changes",
  "aws.gap.cloudwatch.cis_alarm.network_gateway_changes",
  "aws.gap.cloudwatch.cis_alarm.organizations_changes",
  "aws.gap.cloudwatch.cis_alarm.root_account_usage",
  "aws.gap.cloudwatch.cis_alarm.route_table_changes",
  "aws.gap.cloudwatch.cis_alarm.s3_bucket_policy_changes",
  "aws.gap.cloudwatch.cis_alarm.security_group_changes",
  "aws.gap.cloudwatch.cis_alarm.unauthorized_api_calls",
  "aws.gap.cloudwatch.cis_alarm.vpc_changes",
  "aws.gap.cloudwatch.metric_alarm.cloudtrail_configuration_changes",
  "aws.gap.cloudwatch.metric_alarm.cmk_disable_or_scheduled_deletion",
  "aws.gap.cloudwatch.metric_alarm.config_configuration_changes",
  "aws.gap.cloudwatch.metric_alarm.console_authentication_failures",
  "aws.gap.cloudwatch.metric_alarm.console_sign_in_without_mfa",
  "aws.gap.cloudwatch.metric_alarm.iam_policy_changes",
  "aws.gap.cloudwatch.metric_alarm.network_acl_changes",
  "aws.gap.cloudwatch.metric_alarm.network_gateway_changes",
  "aws.gap.cloudwatch.metric_alarm.organizations_changes",
  "aws.gap.cloudwatch.metric_alarm.root_account_usage",
  "aws.gap.cloudwatch.metric_alarm.route_table_changes",
  "aws.gap.cloudwatch.metric_alarm.s3_bucket_policy_changes",
  "aws.gap.cloudwatch.metric_alarm.security_group_changes",
  "aws.gap.cloudwatch.metric_alarm.unauthorized_api_calls",
  "aws.gap.cloudwatch.metric_alarm.vpc_changes",
  "aws.gap.ec2.instance_no_iam_role_attached_with_credentials_exposure_access",
  "aws.gap.ec2.instance_no_iam_role_with_org_write_access",
  "aws.gap.ec2.instance_no_iam_with_write_level_access",
  "aws.gap.iam.active_keys_used_within_45_days",
  "aws.gap.iam.root_not_used_1_day",
  "aws.gap.iam.root_not_used_90_days",
  "aws.gap.s3.bucket_policy_denies_insecure_transport",
  "aws.gap.s3.no_public_write_acl_or_policy",
  "aws.gap.s3.object_read_events_logged",
  "aws.gap.s3.object_read_write_events_logged",
  "aws.gap.s3.object_write_events_logged",
  "aws.iam.access_key_count",
  "aws.iam.console_mfa",
  "aws.iam.no_root_keys",
  "aws.iam.password_lowercase",
  "aws.iam.password_max_age",
  "aws.iam.password_numbers",
  "aws.iam.password_symbols",
  "aws.iam.password_uppercase",
  "aws.iam.restrict_public_trust",
  "aws.iam.root_mfa",
  "aws.nist.all_cloudtrail_destination_bucket_access_logging",
  "aws.nist.all_iam_policies_no_star_star",
  "aws.nist.all_managed_policies_no_service_wildcard",
  "aws.nist.cloudtrail_cloudwatch_integration",
  "aws.nist.codebuild_exact_aws_key_env_names",
  "aws.pci.codebuild.aws_key_environment_vars",
  "aws.pci.codepipeline.first_stage_single_deploy",
  "aws.pci.iam.wildcard_action_scoped_resource",
  "aws.rds.auto_minor_upgrade",
  "aws.rds.cluster_copy_snapshot_tags",
  "aws.rds.cluster_deletion_protection",
  "aws.rds.cluster_encryption",
  "aws.rds.cluster_iam_authentication",
  "aws.rds.cluster_multi_az",
  "aws.rds.deletion_protection",
  "aws.rds.encryption",
  "aws.rds.snapshot_encryption",
  "aws.s3.default_encryption",
  "aws.s3.no_public_acl",
  "aws.s3.public_access_block",
  "aws.secretsmanager.rotation",
  "aws.sqs.encryption",
  "aws_backup_failure_notification",
  "aws_cis_batch_job_cloudwatch_logging",
  "aws_cis_lambda_config_recorded",
  "aws_cis_lightsail_bucket_access_logging",
  "aws_client_vpn_authentication_configured",
  "aws_ec2_running_instance_cpu_alarm_present",
  "aws_ec2_status_alarm",
  "aws_eventbridge_iam_user_change_alert",
  "aws_eventbridge_snapshot_change_alert",
  "aws_fedramp_cloudtrail_destination_kms",
  "aws_g6_all_cloudtrail_destination_bucket_access_logging",
  "aws_g6_cloudtrail_all_trails_cloudwatch_integration",
  "aws_g6_cloudtrail_kms_destination_join",
  "aws_g6_ecr_public_repositories_absent",
  "aws_g6_ecs_all_containers_logging",
  "aws_g6_iam_all_policy_service_wildcard",
  "aws_g6_iam_all_policy_star_star",
  "aws_g6_rds_cluster_members_enhanced_monitoring",
  "aws_kms_imported_key_origin_spec",
  "aws_lambda_code_signing_configured",
  "aws_msk_in_cluster_tls_enabled",
  "aws_nist_cloudtrail_s3_logging_enabled",
  "aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk",
  "aws_nist_dynamodb_table_encrypted_with_kms",
  "aws_nist_iam_all_policy_no_service_wild_card",
  "aws_nist_iam_policy_no_star_star",
  "aws_nist_rds_db_instance_and_cluster_enhanced_monitoring_enabled",
  "aws_route53_hosted_zone_dnssec_enabled",
  "aws_security_group_common_ports_ipv6_all",
  "aws_security_group_ssh_ipv6_all",
  "aws_security_group_tcp_udp_ipv6_all",
  "aws_sns_delivery_failure_alarm_present",
  "aws_sqs_queue_depth_alarm_present"
]);

export const AWS_SCALAR_EVIDENCE_REVIEW: Record<string, {field: string; label: string; boolean: boolean; expected: unknown[]}> = {
  "aws.b.classic_elb.access_logs": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "Attributes.LoadBalancerAttributes.AccessLog.Enabled",
    "label": "Classic Load Balancer access logging"
  },
  "aws.b.classic_elb.connection_draining": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "Attributes.LoadBalancerAttributes.ConnectionDraining.Enabled",
    "label": "Classic Load Balancer connection draining"
  },
  "aws.b.classic_elb.cross_zone": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "Attributes.LoadBalancerAttributes.CrossZoneLoadBalancing.Enabled",
    "label": "Classic Load Balancer cross-zone balancing"
  },
  "aws.b.cloudfront.access_logging": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "Config.DistributionConfig.Logging.Enabled",
    "label": "CloudFront legacy access logging"
  },
  "aws.b.cloudfront.sni": {
    "boolean": false,
    "expected": [
      "sni-only"
    ],
    "field": "Config.DistributionConfig.ViewerCertificate.SSLSupportMethod",
    "label": "CloudFront certificate support method"
  },
  "aws.b.cognito.admin_only_signup": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "AdminCreateUserConfig.AllowAdminCreateUserOnly",
    "label": "Administrator-only user creation"
  },
  "aws.b.cognito.deletion_protection": {
    "boolean": false,
    "expected": [
      "ACTIVE"
    ],
    "field": "DeletionProtection",
    "label": "User-pool deletion-protection mode"
  },
  "aws.b.cognito.enforced_threat_protection": {
    "boolean": false,
    "expected": [
      "ENFORCED"
    ],
    "field": "UserPoolAddOns.AdvancedSecurityMode",
    "label": "Cognito threat-protection mode"
  },
  "aws.b.cognito.no_guest_identities": {
    "boolean": true,
    "expected": [
      false
    ],
    "field": "Configuration.AllowUnauthenticatedIdentities",
    "label": "Unauthenticated identity access"
  },
  "aws.b.cognito.password_lowercase": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "Policies.PasswordPolicy.RequireLowercase",
    "label": "Password requirement for lowercase characters"
  },
  "aws.b.cognito.password_number": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "Policies.PasswordPolicy.RequireNumbers",
    "label": "Password requirement for numbers"
  },
  "aws.b.cognito.password_symbol": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "Policies.PasswordPolicy.RequireSymbols",
    "label": "Password requirement for symbols"
  },
  "aws.b.cognito.password_uppercase": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "Policies.PasswordPolicy.RequireUppercase",
    "label": "Password requirement for uppercase characters"
  },
  "aws.b.cognito.required_mfa": {
    "boolean": false,
    "expected": [
      "ON"
    ],
    "field": "MfaConfiguration",
    "label": "User-pool MFA mode"
  },
  "aws.b.dms.automatic_minor_upgrade": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "AutoMinorVersionUpgrade",
    "label": "Automatic minor-version upgrades"
  },
  "aws.b.dms.multi_az": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "MultiAZ",
    "label": "Multi-AZ deployment"
  },
  "aws.b.dms.no_public_instance": {
    "boolean": true,
    "expected": [
      false
    ],
    "field": "PubliclyAccessible",
    "label": "DMS public accessibility"
  },
  "aws.b.docdb.deletion_protection": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "DeletionProtection",
    "label": "Deletion protection"
  },
  "aws.b.docdb.storage_encryption": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "StorageEncrypted",
    "label": "DocumentDB storage encryption"
  },
  "aws.b.dynamodb.deletion_protection": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "Table.Table.DeletionProtectionEnabled",
    "label": "Deletion protection"
  },
  "aws.b.dynamodb.point_in_time_recovery": {
    "boolean": false,
    "expected": [
      "ENABLED"
    ],
    "field": "ContinuousBackups.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus",
    "label": "DynamoDB point-in-time recovery"
  },
  "aws.b.efs.at_rest_encryption": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "Encrypted",
    "label": "File-system encryption at rest"
  },
  "aws.b.elasticache.at_rest": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "AtRestEncryptionEnabled",
    "label": "Cache encryption at rest"
  },
  "aws.b.elasticache.automatic_failover": {
    "boolean": false,
    "expected": [
      "enabled"
    ],
    "field": "AutomaticFailover",
    "label": "Cache automatic failover"
  },
  "aws.b.elasticache.automatic_minor_upgrade": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "AutoMinorVersionUpgrade",
    "label": "Automatic minor-version upgrades"
  },
  "aws.b.elasticache.in_transit": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "TransitEncryptionEnabled",
    "label": "Cache encryption in transit"
  },
  "aws.b.lambda.active_tracing": {
    "boolean": false,
    "expected": [
      "Active"
    ],
    "field": "Configuration.TracingConfig.Mode",
    "label": "Lambda tracing mode"
  },
  "aws.b.mq.automatic_minor_upgrade": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "Configuration.AutoMinorVersionUpgrade",
    "label": "Automatic minor-version upgrades"
  },
  "aws.b.neptune_cluster.deletion_protection": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "DeletionProtection",
    "label": "Deletion protection"
  },
  "aws.b.neptune_cluster.iam_authentication": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "IAMDatabaseAuthenticationEnabled",
    "label": "IAM database authentication"
  },
  "aws.b.neptune_cluster.snapshot_tags": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "CopyTagsToSnapshot",
    "label": "Copying resource tags to snapshots"
  },
  "aws.b.neptune_cluster.storage_encryption": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "StorageEncrypted",
    "label": "Neptune storage encryption"
  },
  "aws.b.rds.cluster_minor_upgrade": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "AutoMinorVersionUpgrade",
    "label": "Automatic minor-version upgrades"
  },
  "aws.b.rds.proxy_tls": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "RequireTLS",
    "label": "Proxy TLS requirement"
  },
  "aws.b.rds_cluster.iam_authentication": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "IAMDatabaseAuthenticationEnabled",
    "label": "IAM database authentication"
  },
  "aws.b.rds_cluster.multiple_az": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "MultiAZ",
    "label": "Multi-AZ deployment"
  },
  "aws.b.rds_instance.iam_authentication": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "IAMDatabaseAuthenticationEnabled",
    "label": "IAM database authentication"
  },
  "aws.b.rds_instance.minor_upgrade": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "AutoMinorVersionUpgrade",
    "label": "Automatic minor-version upgrades"
  },
  "aws.b.rds_instance.snapshot_tags": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "CopyTagsToSnapshot",
    "label": "Copying resource tags to snapshots"
  },
  "aws.b.redshift.allow_version_upgrade": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "AllowVersionUpgrade",
    "label": "Redshift version upgrades"
  },
  "aws.b.redshift.audit_logging": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "Logging.LoggingEnabled",
    "label": "Redshift audit logging"
  },
  "aws.b.redshift.enhanced_vpc_routing": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "EnhancedVpcRouting",
    "label": "Enhanced VPC routing"
  },
  "aws.b.redshift.no_public_endpoint": {
    "boolean": true,
    "expected": [
      false
    ],
    "field": "PubliclyAccessible",
    "label": "Redshift public accessibility"
  },
  "aws.b.ssm.parameter_secure_type": {
    "boolean": false,
    "expected": [
      "SecureString"
    ],
    "field": "Type",
    "label": "Parameter type"
  },
  "aws.c2b.appstream.no_default_internet": {
    "boolean": true,
    "expected": [
      false
    ],
    "field": "EnableDefaultInternetAccess",
    "label": "AppStream default Internet access"
  },
  "aws.c2b.documentdb.deletion_protection": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "DeletionProtection",
    "label": "Deletion protection"
  },
  "aws.c2b.documentdb.multi_az": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "MultiAZ",
    "label": "Multi-AZ deployment"
  },
  "aws.c2b.elasticache.rg_auto_minor_version_upgrade": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "AutoMinorVersionUpgrade",
    "label": "Automatic minor-version upgrades"
  },
  "aws.c2b.elasticache.rg_multi_az": {
    "boolean": false,
    "expected": [
      "enabled"
    ],
    "field": "MultiAZ",
    "label": "Multi-AZ deployment"
  },
  "aws.cb.lightsail.database_not_public": {
    "boolean": true,
    "expected": [
      false
    ],
    "field": "publiclyAccessible",
    "label": "Lightsail database public accessibility"
  },
  "aws.cb.lightsail.static_ip_attached": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "isAttached",
    "label": "Static-IP attachment"
  },
  "aws.cb.memorydb.auto_minor_version_upgrade": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "AutoMinorVersionUpgrade",
    "label": "Automatic minor-version upgrades"
  },
  "aws.cb.memorydb.tls_enabled": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "TLSEnabled",
    "label": "MemoryDB TLS"
  },
  "aws.cb.mq.not_publicly_accessible": {
    "boolean": true,
    "expected": [
      false
    ],
    "field": "Configuration.PubliclyAccessible",
    "label": "Amazon MQ public accessibility"
  },
  "aws.cb.mskconnect.tls_to_cluster": {
    "boolean": false,
    "expected": [
      "TLS"
    ],
    "field": "kafkaClusterEncryptionInTransit.encryptionType",
    "label": "Connector-to-cluster encryption type"
  },
  "aws.cb.neptune.copy_tags_to_snapshot": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "CopyTagsToSnapshot",
    "label": "Copying resource tags to snapshots"
  },
  "aws.cb.neptune.deletion_protection": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "DeletionProtection",
    "label": "Deletion protection"
  },
  "aws.cb.neptune.iam_authentication": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "IAMDatabaseAuthenticationEnabled",
    "label": "IAM database authentication"
  },
  "aws.cb.neptune.multi_az": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "MultiAZ",
    "label": "Multi-AZ deployment"
  },
  "aws.cb.neptune.storage_encrypted": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "StorageEncrypted",
    "label": "Neptune storage encryption"
  },
  "aws.cb.redshift.allow_version_upgrade": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "AllowVersionUpgrade",
    "label": "Redshift version upgrades"
  },
  "aws.cb.redshift.encrypted": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "Encrypted",
    "label": "Redshift cluster encryption"
  },
  "aws.cb.redshift.enhanced_vpc_routing": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "EnhancedVpcRouting",
    "label": "Enhanced VPC routing"
  },
  "aws.cb.redshift.multi_az": {
    "boolean": false,
    "expected": [
      "Enabled"
    ],
    "field": "MultiAZ",
    "label": "Multi-AZ deployment"
  },
  "aws.cb.redshift.not_publicly_accessible": {
    "boolean": true,
    "expected": [
      false
    ],
    "field": "PubliclyAccessible",
    "label": "Redshift public accessibility"
  },
  "aws.cb.redshiftserverless.enhanced_vpc_routing": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "enhancedVpcRouting",
    "label": "Enhanced VPC routing"
  },
  "aws.cb.redshiftserverless.not_publicly_accessible": {
    "boolean": true,
    "expected": [
      false
    ],
    "field": "publiclyAccessible",
    "label": "Redshift public accessibility"
  },
  "aws.cb.route53.domain_auto_renew": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "Detail.AutoRenew",
    "label": "Domain automatic renewal"
  },
  "aws.cb.route53.domain_privacy_protection": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "Detail.AdminPrivacy",
    "label": "Domain administrative-contact privacy"
  },
  "aws.cb.sagemaker.model_network_isolation": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "EnableNetworkIsolation",
    "label": "Workload network isolation"
  },
  "aws.cb.sagemaker.notebook_no_direct_internet": {
    "boolean": false,
    "expected": [
      "Disabled"
    ],
    "field": "DirectInternetAccess",
    "label": "Notebook direct Internet access"
  },
  "aws.cb.sagemaker.notebook_root_access_disabled": {
    "boolean": false,
    "expected": [
      "Disabled"
    ],
    "field": "RootAccess",
    "label": "Notebook root access"
  },
  "aws.cb.sagemaker.training_intercontainer_encryption": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "EnableInterContainerTrafficEncryption",
    "label": "Training inter-container traffic encryption"
  },
  "aws.cb.sagemaker.training_network_isolation": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "EnableNetworkIsolation",
    "label": "Workload network isolation"
  },
  "aws.cb.trustedadvisor.premium_support": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "PremiumSupport",
    "label": "Premium support"
  },
  "aws.cloudtrail.log_validation": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "LogFileValidationEnabled",
    "label": "CloudTrail log-file validation"
  },
  "aws.cloudtrail.logging": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "Status.IsLogging",
    "label": "CloudTrail logging"
  },
  "aws.cloudtrail.multi_region": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "IsMultiRegionTrail",
    "label": "Multi-Region trail coverage"
  },
  "aws.ecr.immutable_tags": {
    "boolean": false,
    "expected": [
      "IMMUTABLE"
    ],
    "field": "imageTagMutability",
    "label": "Repository tag mutability"
  },
  "aws.ecr.scan_on_push": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "imageScanningConfiguration.scanOnPush",
    "label": "Repository scan on push"
  },
  "aws.eks.private_endpoint": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "Cluster.cluster.resourcesVpcConfig.endpointPrivateAccess",
    "label": "Private EKS endpoint access"
  },
  "aws.iam.password_lowercase": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "PasswordPolicy.RequireLowercaseCharacters",
    "label": "Password requirement for lowercase characters"
  },
  "aws.iam.password_numbers": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "PasswordPolicy.RequireNumbers",
    "label": "Password requirement for numbers"
  },
  "aws.iam.password_symbols": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "PasswordPolicy.RequireSymbols",
    "label": "Password requirement for symbols"
  },
  "aws.iam.password_uppercase": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "PasswordPolicy.RequireUppercaseCharacters",
    "label": "Password requirement for uppercase characters"
  },
  "aws.rds.auto_minor_upgrade": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "AutoMinorVersionUpgrade",
    "label": "Automatic minor-version upgrades"
  },
  "aws.rds.cluster_copy_snapshot_tags": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "CopyTagsToSnapshot",
    "label": "Copying resource tags to snapshots"
  },
  "aws.rds.cluster_deletion_protection": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "DeletionProtection",
    "label": "Deletion protection"
  },
  "aws.rds.cluster_iam_authentication": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "IAMDatabaseAuthenticationEnabled",
    "label": "IAM database authentication"
  },
  "aws.rds.cluster_multi_az": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "MultiAZ",
    "label": "Multi-AZ deployment"
  },
  "aws.rds.deletion_protection": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "DeletionProtection",
    "label": "Deletion protection"
  },
  "aws.rds.snapshot_encryption": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "Encrypted",
    "label": "Snapshot encryption"
  },
  "aws.secretsmanager.rotation": {
    "boolean": true,
    "expected": [
      true
    ],
    "field": "RotationEnabled",
    "label": "Automatic secret rotation"
  }
};

export const AWS_GUARDDUTY_PROTECTION_LABELS: Record<string, string> = {
  "aws.claude_a.guardduty.ebs_malware_protection_feature": "EBS malware protection",
  "aws.claude_a.guardduty.ec2_runtime_agent_management": "EC2 agent management",
  "aws.claude_a.guardduty.ecs_runtime_agent_management": "ECS Fargate agent management",
  "aws.claude_a.guardduty.eks_runtime_monitoring_feature": "EKS runtime monitoring",
  "aws.claude_a.guardduty.prowler_ec2_malware_protection": "EC2 malware protection",
  "aws.claude_a.guardduty.prowler_eks_audit_logs": "EKS audit-log monitoring",
  "aws.claude_a.guardduty.prowler_eks_runtime_monitoring": "EKS runtime monitoring",
  "aws.claude_a.guardduty.prowler_lambda_protection": "Lambda Protection",
  "aws.claude_a.guardduty.prowler_rds_protection": "RDS Protection",
  "aws.claude_a.guardduty.prowler_s3_protection": "S3 Protection"
};
