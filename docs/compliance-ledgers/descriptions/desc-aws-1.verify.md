
## Independent evaluator review

Reviewed all 310 input IDs against the registered evaluator bodies and their return branches. The supplied check-index source points to the shared registry; concrete evaluator locations are recorded below. `corrected` means at least one description field changed; `retained` means all fields survived review.

| ID | Evaluator | Decision | Fields changed |
| --- | --- | --- | --- |
| `aws.a.accessanalyzer.region_active` | `peaso/checks/aws_a_accessanalyzer.py:23` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.accessanalyzer.region_present` | `peaso/checks/aws_a_accessanalyzer.py:11` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.account.organization_member` | `peaso/checks/aws_a_account.py:37` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.account.security_contact_present` | `peaso/checks/aws_a_account.py:19` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.cloudtrail.bucket_access_logging` | `peaso/checks/aws_a_cloudtrail.py:90` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.cloudtrail.bucket_mfa_delete` | `peaso/checks/aws_a_cloudtrail.py:64` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.a.cloudtrail.cloudwatch_delivery_24h` | `peaso/checks/aws_a_cloudtrail.py:31` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.cloudtrail.home_bucket_access_logging` | `peaso/checks/aws_a_cloudtrail_variants.py:107` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.a.cloudtrail.home_bucket_mfa_join` | `peaso/checks/aws_a_cloudtrail_variants.py:181` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.a.cloudtrail.home_cloudwatch_date` | `peaso/checks/aws_a_cloudtrail_variants.py:61` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.a.cloudtrail.home_kms_encryption` | `peaso/checks/aws_a_cloudtrail_variants.py:22` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.a.cloudtrail.home_logging_with_insights` | `peaso/checks/aws_a_cloudtrail_variants.py:35` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.a.cloudtrail.home_multiregion_cloudwatch_date` | `peaso/checks/aws_a_cloudtrail_variants.py:61` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.a.cloudtrail.insights_logging_trail` | `peaso/checks/aws_a_cloudtrail.py:14` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.a.cloudtrail.joined_bucket_declared_public_grants` | `peaso/checks/aws_a_cloudtrail_variants.py:132` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.a.cloudwatch.agentcore_data_protection` | `peaso/checks/aws_a_cloudwatch.py:81` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.a.cloudwatch.alarm_actions_enabled` | `peaso/checks/aws_a_cloudwatch.py:13` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.cloudwatch.alarm_state_actions` | `peaso/checks/aws_a_cloudwatch.py:22` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.cloudwatch.any_state_actions` | `peaso/checks/aws_a_cloudwatch.py:33` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.cloudwatch.cross_account_role_absent` | `peaso/checks/aws_a_cloudwatch.py:69` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.cloudwatch.finite_retention_365` | `peaso/checks/aws_a_cloudtrail_variants.py:94` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.cloudwatch.log_kms_encryption` | `peaso/checks/aws_a_cloudwatch.py:45` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.cloudwatch.log_retention_at_least_365` | `peaso/checks/aws_a_cloudwatch.py:55` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.config.region_recorder_enabled` | `peaso/checks/aws_a_regional.py:33` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.guardduty.region_enabled` | `peaso/checks/aws_a_regional.py:13` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.active_key_age_90` | `peaso/checks/aws_a_iam_lifecycle.py:25` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.a.iam.attached_policy_no_star_star` | `peaso/checks/aws_a_iam_policies.py:25` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.a.iam.console_key_created_at_setup` | `peaso/checks/aws_a_iam_lifecycle.py:53` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.group_no_cloudshell_full_access` | `peaso/checks/aws_a_iam_policies.py:13` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.password_policy_expiry_at_most_90` | `peaso/checks/aws_a_iam.py:34` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.password_policy_lowercase` | `peaso/checks/aws_a_iam.py:34` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.password_policy_minimum_length_14` | `peaso/checks/aws_a_iam.py:34` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.password_policy_numbers` | `peaso/checks/aws_a_iam.py:34` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.password_policy_reuse_at_least_24` | `peaso/checks/aws_a_iam.py:34` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.password_policy_strong_min_length_14_reuse_24_age_90` | `peaso/checks/aws_a_iam.py:57` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.password_policy_strong_min_length_8` | `peaso/checks/aws_a_iam.py:57` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.password_policy_symbols` | `peaso/checks/aws_a_iam.py:34` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.password_policy_uppercase` | `peaso/checks/aws_a_iam.py:34` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.report_all_mfa` | `peaso/checks/aws_a_iam.py:115` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.report_console_mfa` | `peaso/checks/aws_a_iam.py:105` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.role_no_cloudshell_full_access` | `peaso/checks/aws_a_iam_policies.py:13` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.root_console_summary_mfa` | `peaso/checks/aws_a_iam_lifecycle.py:123` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.root_hardware_mfa` | `peaso/checks/aws_a_iam_lifecycle.py:89` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.root_summary_mfa` | `peaso/checks/aws_a_iam.py:83` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.root_summary_no_keys` | `peaso/checks/aws_a_iam.py:94` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.server_certificate_expiry_date` | `peaso/checks/aws_a_iam_lifecycle.py:42` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.unused_credentials_45_days` | `peaso/checks/aws_a_iam_usage.py:34` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.unused_credentials_90_days` | `peaso/checks/aws_a_iam_usage.py:34` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.user_no_cloudshell_full_access` | `peaso/checks/aws_a_iam_policies.py:13` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.user_no_direct_policies` | `peaso/checks/aws_a_iam_lifecycle.py:76` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.iam.user_no_managed_policies` | `peaso/checks/aws_a_iam_lifecycle.py:76` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.kms.rotation_source_eligibility` | `peaso/checks/aws_a_kms.py:11` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.a.s3.bucket_account_public_blocks` | `peaso/checks/aws_a_s3.py:52` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.s3.default_encryption_configuration` | `peaso/checks/aws_a_s3.py:11` | corrected | description, evaluated, pass_when, fail_when |
| `aws.a.s3.mfa_delete_enabled` | `peaso/checks/aws_a_s3.py:28` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.acm.expiry_thirty_days` | `peaso/checks/aws_b_loadbalancing.py:129` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.acm.no_failed_validation` | `peaso/checks/aws_b_loadbalancing.py:163` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.acm.no_wildcard_domain` | `peaso/checks/aws_b_loadbalancing.py:157` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.acm.not_past_expiry_date` | `peaso/checks/aws_b_loadbalancing.py:181` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.acm.pending_validation_review` | `peaso/checks/aws_b_loadbalancing.py:171` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.acm.rsa_minimum_2048` | `peaso/checks/aws_b_loadbalancing.py:194` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.acm.transparency_logging` | `peaso/checks/aws_b_loadbalancing.py:143` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.alb.access_logs` | `peaso/checks/aws_b_loadbalancing.py:30` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.alb.deletion_protection` | `peaso/checks/aws_b_loadbalancing.py:30` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.alb.desync_mode` | `peaso/checks/aws_b_loadbalancing.py:47` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.alb.invalid_header_dropping` | `peaso/checks/aws_b_loadbalancing.py:30` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.apigateway.client_certificate` | `peaso/checks/aws_b_apigateway.py:61` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.apigateway.http_execution_logging` | `peaso/checks/aws_b_apigateway.py:37` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.apigateway.private_endpoint_type` | `peaso/checks/aws_b_apigateway.py:71` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.apigateway.rest_execution_logging` | `peaso/checks/aws_b_apigateway.py:37` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.apigateway.rest_xray` | `peaso/checks/aws_b_apigateway.py:52` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.apigateway.waf_reference` | `peaso/checks/aws_b_apigateway.py:61` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.apigateway.wildcard_cache_encryption` | `peaso/checks/aws_b_apigateway.py:21` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.aurora.mysql_audit_export` | `peaso/checks/aws_b_storage.py:50` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.aurora.mysql_copy_snapshot_tags` | `peaso/checks/aws_b_storage.py:40` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.aurora.postgres_copy_snapshot_tags` | `peaso/checks/aws_b_storage.py:40` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.backup.report_plan_presence` | `peaso/checks/aws_b_regional.py:27` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.backup_plan.regional_presence` | `peaso/checks/aws_b_regional.py:13` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.backup_vault.regional_presence` | `peaso/checks/aws_b_regional.py:13` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.classic_elb.access_logs` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.classic_elb.connection_draining` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.classic_elb.cross_zone` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.classic_elb.desync_mode` | `peaso/checks/aws_b_loadbalancing.py:107` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.classic_elb.encrypted_listeners` | `peaso/checks/aws_b_loadbalancing.py:98` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.classic_elb.multiple_az` | `peaso/checks/aws_b_loadbalancing.py:65` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cloudfront.access_logging` | `peaso/checks/aws_b_core.py:39` | corrected | description, pass_when, fail_when |
| `aws.b.cloudfront.custom_acm_certificate` | `peaso/checks/aws_b_cloudfront.py:69` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cloudfront.custom_origin_encryption` | `peaso/checks/aws_b_cloudfront.py:120` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cloudfront.default_root_object` | `peaso/checks/aws_b_cloudfront.py:62` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cloudfront.field_level_encryption` | `peaso/checks/aws_b_cloudfront.py:62` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cloudfront.geo_restrictions` | `peaso/checks/aws_b_cloudfront.py:46` | corrected | description, pass_when, fail_when |
| `aws.b.cloudfront.no_sslv3_origin` | `peaso/checks/aws_b_cloudfront.py:100` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.cloudfront.origin_group_metadata` | `peaso/checks/aws_b_cloudfront.py:78` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cloudfront.origin_secure_protocols` | `peaso/checks/aws_b_cloudfront.py:100` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.cloudfront.sni` | `peaso/checks/aws_b_core.py:39` | corrected | description, pass_when, fail_when |
| `aws.b.cloudfront.viewer_encryption` | `peaso/checks/aws_b_cloudfront.py:36` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cloudfront.waf_reference` | `peaso/checks/aws_b_cloudfront.py:62` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.codebuild.artifact_encryption` | `peaso/checks/aws_b_compute.py:119` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.codebuild.logs_enabled` | `peaso/checks/aws_b_compute.py:103` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.codebuild.nonprivileged` | `peaso/checks/aws_b_compute.py:97` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.codebuild.s3_artifact_encryption` | `peaso/checks/aws_b_compute.py:151` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.codebuild.s3_log_encryption` | `peaso/checks/aws_b_compute.py:176` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cognito.admin_only_signup` | `peaso/checks/aws_b_cognito.py:30` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cognito.block_all_takeover_risks` | `peaso/checks/aws_b_cognito.py:104` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cognito.block_compromised_signin` | `peaso/checks/aws_b_cognito.py:82` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cognito.deletion_protection` | `peaso/checks/aws_b_cognito.py:30` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cognito.enforced_threat_protection` | `peaso/checks/aws_b_cognito.py:30` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cognito.no_guest_identities` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cognito.password_lowercase` | `peaso/checks/aws_b_cognito.py:30` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cognito.password_minimum_fourteen` | `peaso/checks/aws_b_cognito.py:51` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cognito.password_number` | `peaso/checks/aws_b_cognito.py:30` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cognito.password_policy` | `peaso/checks/aws_b_compute.py:74` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cognito.password_symbol` | `peaso/checks/aws_b_cognito.py:30` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cognito.password_uppercase` | `peaso/checks/aws_b_cognito.py:30` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cognito.required_mfa` | `peaso/checks/aws_b_cognito.py:30` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.cognito.temporary_password_seven_days` | `peaso/checks/aws_b_cognito.py:61` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.dms.automatic_minor_upgrade` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.dms.multi_az` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.dms.no_public_instance` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.docdb.deletion_protection` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.docdb.seven_day_backups` | `peaso/checks/aws_b_core.py:48` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.docdb.storage_encryption` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.dynamodb.deletion_protection` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.dynamodb.encryption_type` | `peaso/checks/aws_b_regional.py:93` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.dynamodb.kms_description` | `peaso/checks/aws_b_regional.py:83` | corrected | description, pass_when, fail_when |
| `aws.b.dynamodb.point_in_time_recovery` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.ecr.all_tags_immutable` | `peaso/checks/aws_b_ecr.py:9` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.ecr.effective_scan_configuration` | `peaso/checks/aws_b_ecr.py:33` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.ecr.lifecycle_rules` | `peaso/checks/aws_b_ecr.py:17` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.ecr.source_some_immutability` | `peaso/checks/aws_b_ecr.py:60` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.ecs.all_readonly_roots` | `peaso/checks/aws_b_compute.py:52` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.ecs.declared_nonroot_users` | `peaso/checks/aws_b_compute.py:182` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.ecs.host_network_nonprivileged` | `peaso/checks/aws_b_compute.py:207` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.ecs.no_host_pid` | `peaso/checks/aws_b_compute.py:43` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.ecs.no_privileged_containers` | `peaso/checks/aws_b_compute.py:17` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.ecs.some_logging_configuration` | `peaso/checks/aws_b_compute.py:30` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.efs.at_rest_encryption` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.efs.customer_managed_key` | `peaso/checks/aws_b_storage.py:17` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.eks.audit_log_category` | `peaso/checks/aws_b_core.py:175` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.eks.disable_public_endpoint` | `peaso/checks/aws_b_core.py:63` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.eks.no_default_vpc` | `peaso/checks/aws_b_core.py:208` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.eks.secret_envelope_encryption` | `peaso/checks/aws_b_core.py:188` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.elasticache.at_rest` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.elasticache.automatic_failover` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.elasticache.automatic_minor_upgrade` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.elasticache.in_transit` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.elbv2.listener_presence` | `peaso/checks/aws_b_loadbalancing.py:84` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.elbv2.multiple_az` | `peaso/checks/aws_b_loadbalancing.py:74` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.fsx.lustre_copy_backup_tags` | `peaso/checks/aws_b_databases.py:96` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.fsx.netapp_ontap_multi_az` | `peaso/checks/aws_b_databases.py:65` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.fsx.openzfs_copy_backup_and_volume_tags` | `peaso/checks/aws_b_databases.py:82` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.fsx.openzfs_multi_az` | `peaso/checks/aws_b_databases.py:65` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.fsx.windows_multi_az` | `peaso/checks/aws_b_databases.py:65` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.inspector.admin_ec2_auto_enable` | `peaso/checks/aws_b_inspector.py:23` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.inspector.admin_ecr_auto_enable` | `peaso/checks/aws_b_inspector.py:23` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.inspector.admin_lambda_auto_enable` | `peaso/checks/aws_b_inspector.py:23` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.inspector.admin_lambda_code_auto_enable` | `peaso/checks/aws_b_inspector.py:23` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.inspector.ec2_organization_auto_enable` | `peaso/checks/aws_b_regional.py:43` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.inspector.ecr_organization_auto_enable` | `peaso/checks/aws_b_regional.py:43` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.inspector.lambda_code_organization_auto_enable` | `peaso/checks/aws_b_regional.py:43` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.inspector.lambda_organization_auto_enable` | `peaso/checks/aws_b_regional.py:43` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.lambda.active_tracing` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.lambda.insights_layer` | `peaso/checks/aws_b_core.py:147` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.lambda.reserved_concurrency` | `peaso/checks/aws_b_core.py:136` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.lambda.url_cors_single_wildcard` | `peaso/checks/aws_b_core.py:161` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.mq.automatic_minor_upgrade` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.neptune.audit_logging` | `peaso/checks/aws_b_databases.py:29` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.neptune.backup_retention_seven_days` | `peaso/checks/aws_b_core.py:48` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.neptune_cluster.deletion_protection` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.neptune_cluster.iam_authentication` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.neptune_cluster.snapshot_tags` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.neptune_cluster.storage_encryption` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.rds.backup_retention_seven_days` | `peaso/checks/aws_b_core.py:48` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.rds.cluster_event_categories` | `peaso/checks/aws_b_core.py:122` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.rds.cluster_minor_upgrade` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.rds.engine_log_exports` | `peaso/checks/aws_b_core.py:94` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.rds.instance_event_categories` | `peaso/checks/aws_b_core.py:122` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.rds.parameter_group_event_categories` | `peaso/checks/aws_b_core.py:122` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.rds.proxy_tls` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.rds.security_group_event_categories` | `peaso/checks/aws_b_core.py:122` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.rds_cluster.iam_authentication` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.rds_cluster.multiple_az` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.rds_cluster.nondefault_admin` | `peaso/checks/aws_b_core.py:87` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.rds_cluster.nondefault_port_policy` | `peaso/checks/aws_b_storage.py:68` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.rds_instance.iam_authentication` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.rds_instance.minor_upgrade` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.rds_instance.multiple_az` | `peaso/checks/aws_b_databases.py:39` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.rds_instance.nondefault_admin` | `peaso/checks/aws_b_core.py:87` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.rds_instance.nondefault_port_policy` | `peaso/checks/aws_b_storage.py:68` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.rds_instance.snapshot_tags` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.redshift.allow_version_upgrade` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.redshift.audit_logging` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.redshift.enhanced_vpc_routing` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.redshift.kms_key_declared` | `peaso/checks/aws_b_redshift.py:34` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.redshift.no_public_endpoint` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.redshift.nondefault_admin` | `peaso/checks/aws_b_redshift.py:25` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.redshift.nondefault_database` | `peaso/checks/aws_b_redshift.py:25` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.redshift.snapshots_seven_days` | `peaso/checks/aws_b_core.py:48` | corrected | description, evaluated, pass_when, fail_when |
| `aws.b.ssm.document_not_public` | `peaso/checks/aws_b_regional.py:67` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.b.ssm.parameter_secure_type` | `peaso/checks/aws_b_core.py:39` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.acm.in_use_not_expiring_7_days` | `peaso/checks/claude2_aws_b_identity.py:68` | corrected | pass_when |
| `aws.c2b.acm.in_use_secure_key_algorithm` | `peaso/checks/claude2_aws_b_identity.py:116` | corrected | pass_when |
| `aws.c2b.acm.in_use_transparency_logging` | `peaso/checks/claude2_aws_b_identity.py:91` | corrected | pass_when |
| `aws.c2b.acmpca.pqc_key_algorithm` | `peaso/checks/claude2_aws_b_identity.py:161` | corrected | pass_when |
| `aws.c2b.acmpca.root_ca_disabled` | `peaso/checks/claude2_aws_b_identity.py:143` | corrected | pass_when |
| `aws.c2b.apigateway.authorizers_or_authorized_methods` | `peaso/checks/claude2_aws_b_edge.py:949` | corrected | description, pass_when, fail_when |
| `aws.c2b.apigateway.domain_pqc_tls` | `peaso/checks/claude2_aws_b_edge.py:938` | corrected | pass_when |
| `aws.c2b.apigateway.methods_authorization_type` | `peaso/checks/claude2_aws_b_edge.py:1027` | corrected | pass_when |
| `aws.c2b.apigateway.methods_request_validator` | `peaso/checks/claude2_aws_b_edge.py:1043` | corrected | pass_when |
| `aws.c2b.apigateway.public_rest_api_authorizer` | `peaso/checks/claude2_aws_b_edge.py:1000` | corrected | pass_when |
| `aws.c2b.apigateway.rest_api_has_authorizer` | `peaso/checks/claude2_aws_b_edge.py:1015` | corrected | pass_when |
| `aws.c2b.apigateway.rest_api_policy_not_public` | `peaso/checks/claude2_aws_b_edge.py:1072` | corrected | pass_when |
| `aws.c2b.apigateway.rest_api_private_only` | `peaso/checks/claude2_aws_b_edge.py:990` | corrected | pass_when |
| `aws.c2b.apigateway.stage_cache_encrypted` | `peaso/checks/claude2_aws_b_edge.py:966` | corrected | pass_when |
| `aws.c2b.apigateway.stage_execution_logging` | `peaso/checks/claude2_aws_b_edge.py:979` | corrected | pass_when |
| `aws.c2b.apigatewayv2.api_has_authorizer` | `peaso/checks/claude2_aws_b_edge.py:1111` | corrected | pass_when |
| `aws.c2b.apigatewayv2.routes_authorization_type` | `peaso/checks/claude2_aws_b_edge.py:1121` | corrected | pass_when |
| `aws.c2b.apigatewayv2.routes_authorizer` | `peaso/checks/claude2_aws_b_edge.py:1135` | corrected | pass_when |
| `aws.c2b.appstream.disconnect_timeout_5m` | `peaso/checks/claude2_aws_b_compute.py:995` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.appstream.idle_disconnect_10m` | `peaso/checks/claude2_aws_b_compute.py:1004` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.appstream.max_user_duration_under_10h` | `peaso/checks/claude2_aws_b_compute.py:986` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.appstream.no_default_internet` | `peaso/checks/claude2_aws_b_common.py:107` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.appsync.cache_at_rest_encryption` | `peaso/checks/claude2_aws_b_edge.py:1201` | corrected | pass_when |
| `aws.c2b.appsync.cache_in_transit_encryption` | `peaso/checks/claude2_aws_b_edge.py:1201` | corrected | pass_when |
| `aws.c2b.appsync.field_level_logging` | `peaso/checks/claude2_aws_b_edge.py:1164` | corrected | pass_when |
| `aws.c2b.appsync.graphql_no_api_key` | `peaso/checks/claude2_aws_b_edge.py:1174` | corrected | pass_when |
| `aws.c2b.appsync.no_api_key_auth` | `peaso/checks/claude2_aws_b_edge.py:1186` | corrected | pass_when |
| `aws.c2b.athena.cloudwatch_metrics` | `peaso/checks/claude2_aws_b_data.py:189` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.athena.cloudwatch_metrics_prowler` | `peaso/checks/claude2_aws_b_data.py:189` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.c2b.athena.enforce_configuration` | `peaso/checks/claude2_aws_b_data.py:189` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.athena.enforce_configuration_prowler` | `peaso/checks/claude2_aws_b_data.py:189` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.c2b.athena.results_encrypted` | `peaso/checks/claude2_aws_b_data.py:156` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.athena.results_encrypted_prowler` | `peaso/checks/claude2_aws_b_data.py:171` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.c2b.autoscaling.capacity_rebalance` | `peaso/checks/claude2_aws_b_compute.py:808` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.c2b.autoscaling.elb_health_check` | `peaso/checks/claude2_aws_b_compute.py:794` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.c2b.autoscaling.group_lc_imdsv2` | `peaso/checks/claude2_aws_b_compute.py:920` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.c2b.autoscaling.group_lc_no_public_ip` | `peaso/checks/claude2_aws_b_compute.py:898` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.c2b.autoscaling.instance_types_per_az` | `peaso/checks/claude2_aws_b_compute.py:826` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.c2b.autoscaling.lc_hop_limit` | `peaso/checks/claude2_aws_b_compute.py:961` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.autoscaling.lc_imdsv2_required` | `peaso/checks/claude2_aws_b_compute.py:947` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.autoscaling.lc_no_public_ip` | `peaso/checks/claude2_aws_b_common.py:107` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.autoscaling.mixed_policy_multiple_types` | `peaso/checks/claude2_aws_b_compute.py:848` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.autoscaling.multiple_az` | `peaso/checks/claude2_aws_b_compute.py:762` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.autoscaling.no_suspended_processes` | `peaso/checks/claude2_aws_b_compute.py:867` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.autoscaling.tags_propagate` | `peaso/checks/claude2_aws_b_compute.py:877` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.autoscaling.uses_launch_template` | `peaso/checks/claude2_aws_b_compute.py:772` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.backup.plan_rules_retention_35` | `peaso/checks/claude2_aws_b_data.py:291` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.c2b.backup.plans_exist_when_vaults` | `peaso/checks/claude2_aws_b_data.py:223` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.c2b.backup.recovery_point_encrypted` | `peaso/checks/claude2_aws_b_common.py:107` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.backup.recovery_point_retention_35` | `peaso/checks/claude2_aws_b_data.py:276` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.backup.report_plans_when_plans` | `peaso/checks/claude2_aws_b_data.py:242` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when |
| `aws.c2b.backup.vault_encrypted` | `peaso/checks/claude2_aws_b_data.py:258` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.backup.vault_policy_denies_recovery_point_deletion` | `peaso/checks/claude2_aws_b_data.py:344` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.backup.vault_policy_not_public` | `peaso/checks/claude2_aws_b_data.py:374` | corrected | description, evaluated, pass_when, fail_when |
| `aws.c2b.bedrock.agent_guardrail` | `peaso/checks/claude2_aws_b_identity.py:604` | corrected | pass_when |
| `aws.c2b.bedrock.api_key_long_term_expired` | `peaso/checks/claude2_aws_b_identity.py:848` | corrected | pass_when |
| `aws.c2b.bedrock.custom_model_cmk` | `peaso/checks/claude2_aws_b_identity.py:622` | corrected | pass_when |
| `aws.c2b.bedrock.guardrail_contextual_grounding` | `peaso/checks/claude2_aws_b_identity.py:541` | corrected | pass_when |
| `aws.c2b.bedrock.guardrail_prompt_attack_high` | `peaso/checks/claude2_aws_b_identity.py:512` | corrected | pass_when |
| `aws.c2b.bedrock.guardrail_sensitive_information_filter` | `peaso/checks/claude2_aws_b_identity.py:526` | corrected | pass_when |
| `aws.c2b.bedrock.guardrails_configured` | `peaso/checks/claude2_aws_b_identity.py:586` | corrected | pass_when |
| `aws.c2b.bedrock.invocation_logs_encrypted` | `peaso/checks/claude2_aws_b_identity.py:713` | corrected | description, pass_when, fail_when |
| `aws.c2b.bedrock.knowledge_base_data_sources_cmk` | `peaso/checks/claude2_aws_b_identity.py:650` | corrected | pass_when |
| `aws.c2b.bedrock.model_invocation_logging` | `peaso/checks/claude2_aws_b_identity.py:696` | corrected | pass_when |
| `aws.c2b.bedrock.prompt_cmk` | `peaso/checks/claude2_aws_b_identity.py:622` | corrected | pass_when |
| `aws.c2b.bedrock.prompt_management_exists` | `peaso/checks/claude2_aws_b_identity.py:749` | corrected | pass_when |
| `aws.c2b.bedrock.role_no_full_access_policy` | `peaso/checks/claude2_aws_b_identity.py:826` | corrected | pass_when |
| `aws.c2b.bedrock.vpc_endpoints` | `peaso/checks/claude2_aws_b_identity.py:790` | corrected | pass_when |
| `aws.c2b.classic_elb.acm_certificates` | `peaso/checks/claude2_aws_b_edge.py:839` | corrected | pass_when |
| `aws.c2b.classic_elb.has_registered_instances` | `peaso/checks/claude2_aws_b_edge.py:856` | corrected | pass_when |
| `aws.c2b.classic_elb.insecure_ssl_ciphers` | `peaso/checks/claude2_aws_b_edge.py:819` | corrected | pass_when |
| `aws.c2b.classic_elb.not_internet_facing` | `peaso/checks/claude2_aws_b_edge.py:830` | corrected | pass_when |
| `aws.c2b.classic_elb.sg_inbound_rule` | `peaso/checks/claude2_aws_b_edge.py:871` | corrected | pass_when |
| `aws.c2b.classic_elb.sg_outbound_rule` | `peaso/checks/claude2_aws_b_edge.py:871` | corrected | pass_when |
| `aws.c2b.classic_elb.ssl_listeners_only` | `peaso/checks/claude2_aws_b_edge.py:808` | corrected | pass_when |
| `aws.c2b.cloudformation.cdktoolkit_bootstrap_version` | `peaso/checks/claude2_aws_b_devtools.py:409` | corrected | pass_when |
| `aws.c2b.cloudformation.drift_in_sync` | `peaso/checks/claude2_aws_b_devtools.py:345` | corrected | pass_when |
| `aws.c2b.cloudformation.notifications` | `peaso/checks/claude2_aws_b_devtools.py:359` | corrected | pass_when |
| `aws.c2b.cloudformation.rollback_enabled` | `peaso/checks/claude2_aws_b_devtools.py:370` | corrected | pass_when |
| `aws.c2b.cloudformation.termination_protection_all_stacks` | `peaso/checks/claude2_aws_b_devtools.py:380` | corrected | pass_when |
| `aws.c2b.cloudformation.termination_protection_root_stacks` | `peaso/checks/claude2_aws_b_devtools.py:391` | corrected | pass_when, not_applicable_when |
| `aws.c2b.cloudfront.custom_ssl_certificate` | `peaso/checks/claude2_aws_b_edge.py:151` | corrected | pass_when |
| `aws.c2b.cloudfront.default_behavior_https` | `peaso/checks/claude2_aws_b_edge.py:162` | corrected | pass_when |
| `aws.c2b.cloudfront.https_sni` | `peaso/checks/claude2_aws_b_edge.py:173` | corrected | pass_when |
| `aws.c2b.cloudfront.logging_any` | `peaso/checks/claude2_aws_b_edge.py:193` | corrected | pass_when |
| `aws.c2b.cloudfront.origin_no_deprecated_ssl` | `peaso/checks/claude2_aws_b_edge.py:317` | corrected | pass_when |
| `aws.c2b.cloudfront.origin_traffic_encrypted` | `peaso/checks/claude2_aws_b_edge.py:216` | corrected | pass_when, fail_when |
| `aws.c2b.cloudfront.pqc_tls` | `peaso/checks/claude2_aws_b_edge.py:240` | corrected | pass_when |
| `aws.c2b.cloudfront.recommended_tls_policy` | `peaso/checks/claude2_aws_b_edge.py:348` | corrected | pass_when, fail_when |
| `aws.c2b.cloudfront.s3_origin_access_control` | `peaso/checks/claude2_aws_b_edge.py:254` | corrected | pass_when |
| `aws.c2b.cloudfront.s3_origin_access_identity` | `peaso/checks/claude2_aws_b_edge.py:329` | corrected | pass_when |
| `aws.c2b.cloudfront.s3_origin_bucket_exists` | `peaso/checks/claude2_aws_b_edge.py:274` | corrected | pass_when |
| `aws.c2b.codeartifact.domain_policy_prohibit_public_perimeter` | `peaso/checks/claude2_aws_b_devtools.py:734` | corrected | pass_when |
| `aws.c2b.codeartifact.internal_packages_block_upstream` | `peaso/checks/claude2_aws_b_devtools.py:766` | corrected | pass_when |
| `aws.c2b.codeartifact.repository_policy_prohibit_public_perimeter` | `peaso/checks/claude2_aws_b_devtools.py:734` | corrected | pass_when |
| `aws.c2b.codebuild.buildspec_not_user_controlled` | `peaso/checks/claude2_aws_b_devtools.py:155` | corrected | pass_when |
| `aws.c2b.codebuild.buildspec_not_yml_file` | `peaso/checks/claude2_aws_b_devtools.py:168` | corrected | pass_when |
| `aws.c2b.codebuild.built_within_90_days` | `peaso/checks/claude2_aws_b_devtools.py:292` | corrected | pass_when, fail_when |
| `aws.c2b.codebuild.invoked_last_90_days` | `peaso/checks/claude2_aws_b_devtools.py:270` | corrected | pass_when, fail_when |
| `aws.c2b.codebuild.no_plaintext_sensitive_env_names` | `peaso/checks/claude2_aws_b_devtools.py:220` | corrected | pass_when |
| `aws.c2b.codebuild.project_private` | `peaso/checks/claude2_aws_b_devtools.py:89` | corrected | pass_when |
| `aws.c2b.codebuild.report_group_export_encrypted` | `peaso/checks/claude2_aws_b_devtools.py:320` | corrected | pass_when |
| `aws.c2b.codebuild.s3_logs_encrypted_when_enabled` | `peaso/checks/claude2_aws_b_devtools.py:99` | corrected | pass_when |
| `aws.c2b.codebuild.source_repo_oauth` | `peaso/checks/claude2_aws_b_devtools.py:240` | corrected | pass_when |
| `aws.c2b.codebuild.source_url_no_credentials` | `peaso/checks/claude2_aws_b_devtools.py:133` | corrected | pass_when |
| `aws.c2b.codebuild.webhook_filters_anchored` | `peaso/checks/claude2_aws_b_devtools.py:194` | corrected | pass_when |
| `aws.c2b.codedeploy.lambda_not_all_at_once` | `peaso/checks/claude2_aws_b_devtools.py:433` | corrected | pass_when |
| `aws.c2b.cognito.clients_prevent_user_existence_errors` | `peaso/checks/claude2_aws_b_identity.py:221` | corrected | pass_when |
| `aws.c2b.cognito.clients_token_revocation` | `peaso/checks/claude2_aws_b_identity.py:221` | corrected | pass_when |
| `aws.c2b.cognito.waf_web_acl_associated` | `peaso/checks/claude2_aws_b_identity.py:243` | corrected | pass_when |

Coverage: 310 input IDs, 310 unique output IDs, 310 corrected, 0 retained.
Known source title mismatch: `aws.b.dynamodb.kms_description` only checks SSEDescription presence; an AES256 description passes. No unresolved description uncertainty remains from this review.

### Predicate wording refinement

Replaced 23 formula-shaped fail conditions with the exact failing branch in plain language for these IDs: `aws.c2b.acmpca.pqc_key_algorithm`, `aws.c2b.acmpca.root_ca_disabled`, `aws.c2b.apigateway.domain_pqc_tls`, `aws.c2b.apigateway.rest_api_policy_not_public`, `aws.c2b.apigateway.rest_api_private_only`, `aws.c2b.apigateway.stage_cache_encrypted`, `aws.c2b.appsync.cache_at_rest_encryption`, `aws.c2b.appsync.cache_in_transit_encryption`, `aws.c2b.appsync.field_level_logging`, `aws.c2b.classic_elb.not_internet_facing`, `aws.c2b.cloudformation.cdktoolkit_bootstrap_version`, `aws.c2b.cloudformation.drift_in_sync`, `aws.c2b.cloudformation.rollback_enabled`, `aws.c2b.cloudfront.logging_any`, `aws.c2b.codeartifact.domain_policy_prohibit_public_perimeter`, `aws.c2b.codeartifact.repository_policy_prohibit_public_perimeter`, `aws.c2b.codebuild.buildspec_not_user_controlled`, `aws.c2b.codebuild.buildspec_not_yml_file`, `aws.c2b.codebuild.project_private`, `aws.c2b.codebuild.source_repo_oauth`, `aws.c2b.codebuild.source_url_no_credentials`, `aws.c2b.codebuild.webhook_filters_anchored`, `aws.c2b.codedeploy.lambda_not_all_at_once`.

### Applicability refinement

`aws.b.cloudfront.no_sslv3_origin` and `aws.b.cloudfront.origin_secure_protocols` skip non-custom origins inside the loop but return PASS if no prohibited custom-origin protocol is found; they do not emit NOT_APPLICABLE. Their applicability fields are now null.

### Evaluated fact paths

Replaced the evaluated-field lists for the 79 checks without a hand-written draft. These now name the field, collection join, or captured clock actually read by the evaluator rather than a pass/fail fixture index.

### Fixture prose refinement

Replaced 24 generated descriptions that described a sample fixture value rather than the complete evaluator predicate. The full ID set is `aws.c2b.acmpca.pqc_key_algorithm`, `aws.c2b.acmpca.root_ca_disabled`, `aws.c2b.apigateway.domain_pqc_tls`, `aws.c2b.apigateway.rest_api_policy_not_public`, `aws.c2b.apigateway.rest_api_private_only`, `aws.c2b.apigateway.stage_cache_encrypted`, `aws.c2b.appsync.cache_at_rest_encryption`, `aws.c2b.appsync.cache_in_transit_encryption`, `aws.c2b.appsync.field_level_logging`, `aws.c2b.classic_elb.not_internet_facing`, `aws.c2b.cloudformation.cdktoolkit_bootstrap_version`, `aws.c2b.cloudformation.drift_in_sync`, `aws.c2b.cloudformation.rollback_enabled`, `aws.c2b.cloudfront.logging_any`, `aws.c2b.cloudfront.origin_traffic_encrypted`, `aws.c2b.codeartifact.domain_policy_prohibit_public_perimeter`, `aws.c2b.codeartifact.repository_policy_prohibit_public_perimeter`, `aws.c2b.codebuild.buildspec_not_user_controlled`, `aws.c2b.codebuild.buildspec_not_yml_file`, `aws.c2b.codebuild.project_private`, `aws.c2b.codebuild.source_repo_oauth`, `aws.c2b.codebuild.source_url_no_credentials`, `aws.c2b.codebuild.webhook_filters_anchored`, `aws.c2b.codedeploy.lambda_not_all_at_once`.

### Joined-resource and exception branches

Corrected the imported ACM transparency exception, absent Bedrock prompt-attack filter, Amazon-issued ACM certificate requirement, CloudFront S3 bucket HeadBucket 404/200/301/403 outcomes, and CodeBuild source-credential fact paths. IDs: `aws.c2b.acm.in_use_transparency_logging`, `aws.c2b.bedrock.guardrail_prompt_attack_high`, `aws.c2b.classic_elb.acm_certificates`, `aws.c2b.cloudfront.s3_origin_bucket_exists`, `aws.c2b.codebuild.source_repo_oauth`.

### Exact policy and URL predicates

Corrected exact classic ELB listener/protocol-policy matching, Bitbucket-only credential URL regex scope, the missing CloudFront certificate case, and CodeBuild’s strict 90-day boundary. IDs: `aws.c2b.classic_elb.ssl_listeners_only`, `aws.c2b.classic_elb.insecure_ssl_ciphers`, `aws.c2b.codebuild.source_url_no_credentials`, `aws.c2b.cloudfront.recommended_tls_policy`, `aws.c2b.codebuild.built_within_90_days`.

### Final helper predicate corrections

`aws.c2b.cloudfront.logging_any` reads Logging.Enabled and LogDeliveries.deliveries, not the legacy bucket name. `aws.c2b.codeartifact.internal_packages_block_upstream` also selects UNKNOWN-origin packages, including those without versions.

`aws.a.s3.default_encryption_configuration` now describes configuration presence and string-valued rules without implying KMS or object-level encryption.
