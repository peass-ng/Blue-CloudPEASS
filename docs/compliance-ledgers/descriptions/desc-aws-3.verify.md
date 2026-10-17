# desc-aws-3 independent verification

Input: `inputs/desc-aws-3.json`; output: `descriptions/desc-aws-3.json`. Each row below records one decision after reading the registered evaluator source. Indexed kinds and targets were checked against the runtime registry.

| Check ID | Evaluator | Decision | Fields changed |
| --- | --- | --- | --- |
| `aws.cb.rds.postgres_log_exports` | `peaso/checks/claude_aws_b_db.py:365` | verified | — |
| `aws.cb.rds.security_group_critical_event_subscription` | `peaso/checks/claude_aws_b_db.py:720` | verified | — |
| `aws.cb.rds.sqlserver_error_log_export` | `peaso/checks/claude_aws_b_db.py:365` | corrected | description, fail_when, not_applicable_when |
| `aws.cb.rds.sqlserver_force_ssl_parameter` | `peaso/checks/claude_aws_b_db.py:345` | corrected | description, fail_when, not_applicable_when |
| `aws.cb.redshift.allow_version_upgrade` | `peaso/checks/claude_aws_b_common.py:564` | verified | — |
| `aws.cb.redshift.audit_logging` | `peaso/checks/claude_aws_b_db.py:879` | verified | — |
| `aws.cb.redshift.cmk_encryption` | `peaso/checks/claude_aws_b_db.py:952` | verified | — |
| `aws.cb.redshift.encrypted` | `peaso/checks/claude_aws_b_common.py:564` | verified | — |
| `aws.cb.redshift.encrypted_and_logging` | `peaso/checks/claude_aws_b_db.py:889` | verified | — |
| `aws.cb.redshift.enhanced_vpc_routing` | `peaso/checks/claude_aws_b_common.py:564` | verified | — |
| `aws.cb.redshift.has_snapshot` | `peaso/checks/claude_aws_b_db.py:915` | verified | — |
| `aws.cb.redshift.internet_exposed` | `peaso/checks/claude_aws_b_db.py:970` | verified | — |
| `aws.cb.redshift.kms_key_declared` | `peaso/checks/claude_aws_b_db.py:943` | verified | — |
| `aws.cb.redshift.maintenance_settings` | `peaso/checks/claude_aws_b_db.py:934` | verified | — |
| `aws.cb.redshift.multi_az` | `peaso/checks/claude_aws_b_common.py:564` | verified | — |
| `aws.cb.redshift.non_default_database_name` | `peaso/checks/claude_aws_b_db.py:871` | verified | — |
| `aws.cb.redshift.non_default_master_username` | `peaso/checks/claude_aws_b_db.py:871` | verified | — |
| `aws.cb.redshift.not_publicly_accessible` | `peaso/checks/claude_aws_b_common.py:564` | verified | — |
| `aws.cb.redshift.require_ssl` | `peaso/checks/claude_aws_b_db.py:900` | verified | — |
| `aws.cb.redshift.security_group_port_restricted` | `peaso/checks/claude_aws_b_db.py:1002` | corrected | description, pass_when, fail_when |
| `aws.cb.redshift.snapshot_retention_7_days` | `peaso/checks/claude_aws_b_db.py:926` | verified | — |
| `aws.cb.redshiftserverless.connection_user_log_exports` | `peaso/checks/claude_aws_b_db.py:1022` | verified | — |
| `aws.cb.redshiftserverless.enhanced_vpc_routing` | `peaso/checks/claude_aws_b_common.py:564` | verified | — |
| `aws.cb.redshiftserverless.non_default_admin_username` | `peaso/checks/claude_aws_b_db.py:1034` | verified | — |
| `aws.cb.redshiftserverless.non_default_database_name` | `peaso/checks/claude_aws_b_db.py:1034` | verified | — |
| `aws.cb.redshiftserverless.not_publicly_accessible` | `peaso/checks/claude_aws_b_common.py:564` | verified | — |
| `aws.cb.redshiftserverless.require_ssl` | `peaso/checks/claude_aws_b_db.py:1042` | verified | — |
| `aws.cb.resourceexplorer2.index_exists` | `peaso/checks/claude_aws_b_security.py:323` | corrected | description, pass_when, fail_when |
| `aws.cb.rolesanywhere.trust_anchor_pqc` | `peaso/checks/claude_aws_b_security.py:349` | verified | — |
| `aws.cb.route53.domain_auto_renew` | `peaso/checks/claude_aws_b_common.py:564` | verified | — |
| `aws.cb.route53.domain_expires_after_30_days` | `peaso/checks/claude_aws_b_security.py:397` | verified | — |
| `aws.cb.route53.domain_expires_after_7_days` | `peaso/checks/claude_aws_b_security.py:397` | verified | — |
| `aws.cb.route53.domain_not_expired` | `peaso/checks/claude_aws_b_security.py:397` | verified | — |
| `aws.cb.route53.domain_privacy_protection` | `peaso/checks/claude_aws_b_common.py:564` | verified | — |
| `aws.cb.route53.domain_transfer_lock` | `peaso/checks/claude_aws_b_security.py:386` | verified | — |
| `aws.cb.route53.public_zone_query_logging` | `peaso/checks/claude_aws_b_security.py:418` | verified | — |
| `aws.cb.sagemaker.clarify_job_exists` | `peaso/checks/claude_aws_b_compute.py:434` | corrected | description, evaluated, pass_when, fail_when |
| `aws.cb.sagemaker.domain_sso` | `peaso/checks/claude_aws_b_compute.py:414` | corrected | description, pass_when, fail_when |
| `aws.cb.sagemaker.endpoint_config_kms` | `peaso/checks/claude_aws_b_compute.py:378` | verified | — |
| `aws.cb.sagemaker.endpoint_variants_more_than_one` | `peaso/checks/claude_aws_b_compute.py:390` | verified | — |
| `aws.cb.sagemaker.endpoint_variants_not_exactly_one` | `peaso/checks/claude_aws_b_compute.py:400` | verified | — |
| `aws.cb.sagemaker.model_network_isolation` | `peaso/checks/claude_aws_b_common.py:564` | verified | — |
| `aws.cb.sagemaker.model_registry_approved_package` | `peaso/checks/claude_aws_b_compute.py:434` | corrected | description, evaluated, pass_when, fail_when |
| `aws.cb.sagemaker.model_vpc_config` | `peaso/checks/claude_aws_b_compute.py:310` | verified | — |
| `aws.cb.sagemaker.model_vpc_subnets` | `peaso/checks/claude_aws_b_compute.py:318` | verified | — |
| `aws.cb.sagemaker.monitoring_schedule_active` | `peaso/checks/claude_aws_b_compute.py:434` | corrected | description, evaluated, pass_when, fail_when |
| `aws.cb.sagemaker.notebook_cmk` | `peaso/checks/claude_aws_b_compute.py:275` | verified | — |
| `aws.cb.sagemaker.notebook_in_vpc` | `peaso/checks/claude_aws_b_compute.py:286` | verified | — |
| `aws.cb.sagemaker.notebook_kms_key` | `peaso/checks/claude_aws_b_compute.py:267` | verified | — |
| `aws.cb.sagemaker.notebook_no_direct_internet` | `peaso/checks/claude_aws_b_common.py:564` | verified | — |
| `aws.cb.sagemaker.notebook_root_access_disabled` | `peaso/checks/claude_aws_b_common.py:564` | verified | — |
| `aws.cb.sagemaker.notebook_supported_platform` | `peaso/checks/claude_aws_b_compute.py:300` | verified | — |
| `aws.cb.sagemaker.training_intercontainer_encryption` | `peaso/checks/claude_aws_b_common.py:564` | verified | — |
| `aws.cb.sagemaker.training_network_isolation` | `peaso/checks/claude_aws_b_common.py:564` | verified | — |
| `aws.cb.sagemaker.training_output_kms` | `peaso/checks/claude_aws_b_compute.py:357` | verified | — |
| `aws.cb.sagemaker.training_volume_kms` | `peaso/checks/claude_aws_b_compute.py:367` | verified | — |
| `aws.cb.sagemaker.training_vpc_config` | `peaso/checks/claude_aws_b_compute.py:332` | verified | — |
| `aws.cb.sagemaker.training_vpc_subnets` | `peaso/checks/claude_aws_b_compute.py:340` | verified | — |
| `aws.cb.secretsmanager.accessed_within_90_calendar_days` | `peaso/checks/claude_aws_b_security.py:559` | verified | — |
| `aws.cb.secretsmanager.accessed_within_90_days` | `peaso/checks/claude_aws_b_security.py:549` | verified | — |
| `aws.cb.secretsmanager.changed_within_365_days` | `peaso/checks/claude_aws_b_security.py:486` | verified | — |
| `aws.cb.secretsmanager.changed_within_90_days` | `peaso/checks/claude_aws_b_security.py:486` | verified | — |
| `aws.cb.secretsmanager.cmk_encryption` | `peaso/checks/claude_aws_b_security.py:473` | verified | — |
| `aws.cb.secretsmanager.policy_not_public` | `peaso/checks/claude_aws_b_security.py:575` | verified | — |
| `aws.cb.secretsmanager.policy_prohibit_public_access_perimeter` | `peaso/checks/claude_aws_b_security.py:589` | verified | — |
| `aws.cb.secretsmanager.rotated_as_scheduled` | `peaso/checks/claude_aws_b_security.py:514` | verified | — |
| `aws.cb.secretsmanager.rotated_within_90_days` | `peaso/checks/claude_aws_b_security.py:538` | verified | — |
| `aws.cb.secretsmanager.rotation_lambda` | `peaso/checks/claude_aws_b_security.py:464` | verified | — |
| `aws.cb.secretsmanager.rotation_rules_present` | `peaso/checks/claude_aws_b_security.py:456` | verified | — |
| `aws.cb.secretsmanager.used_after_creation_day` | `peaso/checks/claude_aws_b_security.py:501` | verified | — |
| `aws.cb.servicecatalog.no_account_shares` | `peaso/checks/claude_aws_b_security.py:620` | verified | — |
| `aws.cb.servicecatalog.org_member_no_account_shares` | `peaso/checks/claude_aws_b_security.py:632` | verified | — |
| `aws.cb.ses.dkim_signing` | `peaso/checks/claude_aws_b_messaging.py:491` | corrected | evaluated |
| `aws.cb.ses.identity_policies_not_public` | `peaso/checks/claude_aws_b_messaging.py:500` | corrected | evaluated |
| `aws.cb.sfn.logging_not_off` | `peaso/checks/claude_aws_b_messaging.py:524` | verified | — |
| `aws.cb.shield.classic_load_balancer_protected` | `peaso/checks/claude_aws_b_security.py:668` | verified | — |
| `aws.cb.shield.cloudfront_protected` | `peaso/checks/claude_aws_b_security.py:668` | verified | — |
| `aws.cb.shield.elastic_ip_protected` | `peaso/checks/claude_aws_b_security.py:668` | verified | — |
| `aws.cb.shield.global_accelerator_protected` | `peaso/checks/claude_aws_b_security.py:668` | verified | — |
| `aws.cb.shield.internet_facing_alb_protected` | `peaso/checks/claude_aws_b_security.py:668` | verified | — |
| `aws.cb.shield.route53_zone_protected` | `peaso/checks/claude_aws_b_security.py:668` | verified | — |
| `aws.cb.sns.failure_feedback_role` | `peaso/checks/claude_aws_b_messaging.py:281` | verified | — |
| `aws.cb.sns.policy_no_public_publish` | `peaso/checks/claude_aws_b_messaging.py:335` | verified | — |
| `aws.cb.sns.policy_no_public_subscribe` | `peaso/checks/claude_aws_b_messaging.py:335` | verified | — |
| `aws.cb.sns.policy_no_unrestricted_wildcard` | `peaso/checks/claude_aws_b_messaging.py:292` | verified | — |
| `aws.cb.sns.policy_prohibit_public_access_perimeter` | `peaso/checks/claude_aws_b_messaging.py:305` | verified | — |
| `aws.cb.sns.subscription_not_http` | `peaso/checks/claude_aws_b_messaging.py:374` | verified | — |
| `aws.cb.sns.topic_not_publicly_accessible_prowler` | `peaso/checks/claude_aws_b_messaging.py:361` | verified | — |
| `aws.cb.sqs.cmk_encryption` | `peaso/checks/claude_aws_b_messaging.py:420` | verified | — |
| `aws.cb.sqs.dead_letter_queue` | `peaso/checks/claude_aws_b_messaging.py:410` | verified | — |
| `aws.cb.sqs.policy_no_wildcard_allow` | `peaso/checks/claude_aws_b_messaging.py:429` | verified | — |
| `aws.cb.sqs.policy_prohibit_public_access_perimeter` | `peaso/checks/claude_aws_b_messaging.py:441` | verified | — |
| `aws.cb.sqs.queue_not_public_prowler` | `peaso/checks/claude_aws_b_messaging.py:470` | verified | — |
| `aws.cb.ssm.automation_logs_to_cloudwatch` | `peaso/checks/claude_aws_b_security.py:748` | verified | — |
| `aws.cb.ssm.block_public_document_sharing` | `peaso/checks/claude_aws_b_security.py:737` | verified | — |
| `aws.cb.ssm.document_shared_only_with_trusted` | `peaso/checks/claude_aws_b_security.py:765` | verified | — |
| `aws.cb.ssm.instance_association_compliant` | `peaso/checks/claude_aws_b_security.py:799` | verified | — |
| `aws.cb.ssm.instance_patch_compliant` | `peaso/checks/claude_aws_b_security.py:799` | verified | — |
| `aws.cb.ssm.resource_compliance_summary_compliant` | `peaso/checks/claude_aws_b_security.py:781` | verified | — |
| `aws.cb.ssmincidents.active_with_response_plans` | `peaso/checks/claude_aws_b_security.py:831` | verified | — |
| `aws.cb.stepfunctions.cmk_encryption` | `peaso/checks/claude_aws_b_messaging.py:543` | corrected | evaluated |
| `aws.cb.stepfunctions.logging_enabled` | `peaso/checks/claude_aws_b_messaging.py:534` | verified | — |
| `aws.cb.storagegateway.fileshare_kms` | `peaso/checks/claude_aws_b_storage.py:530` | verified | — |
| `aws.cb.storagegateway.gateway_not_on_ec2` | `peaso/checks/claude_aws_b_storage.py:541` | verified | — |
| `aws.cb.transfer.connector_logging_role` | `peaso/checks/claude_aws_b_messaging.py:590` | verified | — |
| `aws.cb.transfer.fips_security_policy` | `peaso/checks/claude_aws_b_messaging.py:570` | verified | — |
| `aws.cb.transfer.no_ftp_protocol` | `peaso/checks/claude_aws_b_messaging.py:562` | verified | — |
| `aws.cb.transfer.pqc_ssh_kex_policy` | `peaso/checks/claude_aws_b_messaging.py:581` | verified | — |
| `aws.cb.trustedadvisor.check_ok` | `peaso/checks/claude_aws_b_security.py:857` | verified | — |
| `aws.cb.trustedadvisor.premium_support` | `peaso/checks/claude_aws_b_common.py:564` | verified | — |
| `aws.cb.waf.rule_group_not_empty` | `peaso/checks/claude_aws_b_security.py:886` | verified | — |
| `aws.cb.waf.rule_has_conditions` | `peaso/checks/claude_aws_b_security.py:879` | verified | — |
| `aws.cb.waf.web_acl_has_rules` | `peaso/checks/claude_aws_b_security.py:896` | verified | — |
| `aws.cb.waf.web_acl_logging` | `peaso/checks/claude_aws_b_security.py:904` | verified | — |
| `aws.cb.wafregional.rule_group_not_empty` | `peaso/checks/claude_aws_b_security.py:886` | verified | — |
| `aws.cb.wafregional.rule_has_conditions` | `peaso/checks/claude_aws_b_security.py:879` | verified | — |
| `aws.cb.wafregional.web_acl_associated` | `peaso/checks/claude_aws_b_security.py:922` | verified | — |
| `aws.cb.wafregional.web_acl_has_rules` | `peaso/checks/claude_aws_b_security.py:896` | verified | — |
| `aws.cb.wafregional.web_acl_logging` | `peaso/checks/claude_aws_b_security.py:904` | verified | — |
| `aws.cb.wafv2.rule_group_metrics` | `peaso/checks/claude_aws_b_security.py:991` | verified | — |
| `aws.cb.wafv2.web_acl_has_rules` | `peaso/checks/claude_aws_b_security.py:960` | verified | — |
| `aws.cb.wafv2.web_acl_has_rules_or_fms_groups` | `peaso/checks/claude_aws_b_security.py:952` | verified | — |
| `aws.cb.wafv2.web_acl_logging` | `peaso/checks/claude_aws_b_security.py:968` | verified | — |
| `aws.cb.wafv2.web_acl_rule_metrics` | `peaso/checks/claude_aws_b_security.py:979` | verified | — |
| `aws.cb.wellarchitected.no_high_or_medium_risks` | `peaso/checks/claude_aws_b_security.py:1002` | verified | — |
| `aws.cb.workspaces.private_subnet_with_nat_vpc` | `peaso/checks/claude_aws_b_storage.py:597` | verified | — |
| `aws.cb.workspaces.root_and_user_volume_encryption` | `peaso/checks/claude_aws_b_storage.py:562` | verified | — |
| `aws.cb.workspaces.root_volume_encryption` | `peaso/checks/claude_aws_b_storage.py:574` | verified | — |
| `aws.cb.workspaces.user_volume_encryption` | `peaso/checks/claude_aws_b_storage.py:574` | verified | — |
| `aws.claude2_a.cloudtrail.account_has_logging_trail` | `peaso/checks/claude2_aws_a_cloudtrail.py:87` | verified | — |
| `aws.claude2_a.cloudtrail.region_has_logging_trail` | `peaso/checks/claude2_aws_a_cloudtrail.py:120` | corrected | description |
| `aws.claude2_a.cloudtrail.threat_detection_enumeration` | `peaso/checks/claude2_aws_a_cloudtrail.py:187` | verified | — |
| `aws.claude2_a.cloudtrail.threat_detection_llm_jacking` | `peaso/checks/claude2_aws_a_cloudtrail.py:187` | verified | — |
| `aws.claude2_a.cloudtrail.threat_detection_privilege_escalation` | `peaso/checks/claude2_aws_a_cloudtrail.py:187` | verified | — |
| `aws.claude2_a.cloudtrail.trail_bucket_mfa_delete` | `peaso/checks/claude2_aws_a_cloudtrail.py:49` | verified | — |
| `aws.claude2_a.cloudwatch.cross_account_sharing_role_absent` | `peaso/checks/claude2_aws_a_misc.py:17` | verified | — |
| `aws.claude2_a.config.aggregation_authorization_trusted` | `peaso/checks/claude2_aws_a_misc.py:91` | verified | — |
| `aws.claude2_a.config.org_aggregator_all_regions_with_delegated_admin` | `peaso/checks/claude2_aws_a_misc.py:109` | verified | — |
| `aws.claude2_a.dlm.snapshot_sharing_trusted_accounts` | `peaso/checks/claude2_aws_a_misc.py:150` | verified | — |
| `aws.claude2_a.logs.log_group_not_public_via_resource_policy` | `peaso/checks/claude2_aws_a_misc.py:47` | verified | — |
| `aws.claude2_a.logs.resource_policy_not_public` | `peaso/checks/claude2_aws_a_misc.py:74` | verified | — |
| `aws.claude_a.accessanalyzer.active_without_findings` | `peaso/checks/claude_aws_a_iam.py:557` | corrected | description, evaluated, pass_when, fail_when |
| `aws.claude_a.cloudtrail.account_has_logging_multi_region_trail` | `peaso/checks/claude_aws_a_security.py:424` | corrected | description |
| `aws.claude_a.ebs.attached_delete_on_termination` | `peaso/checks/claude_aws_a_ec2.py:85` | verified | — |
| `aws.claude_a.ebs.attached_volume_encrypted` | `peaso/checks/claude_aws_a_ec2.py:74` | verified | — |
| `aws.claude_a.ebs.snapshot_encrypted` | `peaso/checks/claude_aws_a_ec2.py:189` | verified | — |
| `aws.claude_a.ebs.snapshot_not_public` | `peaso/checks/claude_aws_a_ec2.py:198` | verified | — |
| `aws.claude_a.ebs.volume_has_snapshot` | `peaso/checks/claude_aws_a_ec2.py:114` | verified | — |
| `aws.claude_a.ebs.volume_in_backup_plan_resources` | `peaso/checks/claude_aws_a_ec2.py:172` | verified | — |
| `aws.claude_a.ebs.volume_in_backup_selection` | `peaso/checks/claude_aws_a_ec2.py:150` | verified | — |
| `aws.claude_a.ebs.volume_in_use` | `peaso/checks/claude_aws_a_ec2.py:98` | verified | — |
| `aws.claude_a.ebs.volume_protected_by_backup` | `peaso/checks/claude_aws_a_ec2.py:136` | verified | — |
| `aws.claude_a.ec2.account_imdsv2_default` | `peaso/checks/claude_aws_a_ec2.py:275` | corrected | evaluated |
| `aws.claude_a.ec2.active_instance_ssm_managed` | `peaso/checks/claude_aws_a_ec2.py:742` | verified | — |
| `aws.claude_a.ec2.ami_block_public_access` | `peaso/checks/claude_aws_a_ec2.py:253` | verified | — |
| `aws.claude_a.ec2.ami_ebs_encrypted` | `peaso/checks/claude_aws_a_ec2.py:306` | verified | — |
| `aws.claude_a.ec2.ami_not_older_than_90_days` | `peaso/checks/claude_aws_a_ec2.py:320` | verified | — |
| `aws.claude_a.ec2.ami_not_public` | `peaso/checks/claude_aws_a_ec2.py:295` | verified | — |
| `aws.claude_a.ec2.client_vpn_connection_logging` | `peaso/checks/claude_aws_a_ec2.py:334` | corrected | evaluated |
| `aws.claude_a.ec2.ebs_encryption_by_default` | `peaso/checks/claude_aws_a_ec2.py:215` | verified | — |
| `aws.claude_a.ec2.ebs_encryption_by_default_with_volumes` | `peaso/checks/claude_aws_a_ec2.py:225` | verified | — |
| `aws.claude_a.ec2.eip_associated` | `peaso/checks/claude_aws_a_ec2.py:1111` | verified | — |
| `aws.claude_a.ec2.enclave_host_imdsv2` | `peaso/checks/claude_aws_a_ec2.py:797` | verified | — |
| `aws.claude_a.ec2.enclave_host_ingress_allowlist` | `peaso/checks/claude_aws_a_ec2.py:882` | corrected | evaluated |
| `aws.claude_a.ec2.enclave_host_not_public` | `peaso/checks/claude_aws_a_ec2.py:820` | corrected | evaluated |
| `aws.claude_a.ec2.enclave_host_running` | `peaso/checks/claude_aws_a_ec2.py:809` | verified | — |
| `aws.claude_a.ec2.enclave_host_vsock_ports_closed` | `peaso/checks/claude_aws_a_ec2.py:909` | corrected | evaluated |
| `aws.claude_a.ec2.eni_in_use` | `peaso/checks/claude_aws_a_ec2.py:1099` | verified | — |
| `aws.claude_a.ec2.eni_no_public_ip` | `peaso/checks/claude_aws_a_ec2.py:1090` | verified | — |
| `aws.claude_a.ec2.eni_source_dest_check` | `peaso/checks/claude_aws_a_ec2.py:1077` | verified | — |
| `aws.claude_a.ec2.instance_ami_not_deprecated` | `peaso/checks/claude_aws_a_ec2.py:761` | corrected | evaluated |
| `aws.claude_a.ec2.instance_detailed_monitoring` | `peaso/checks/claude_aws_a_ec2.py:404` | verified | — |
| `aws.claude_a.ec2.instance_ebs_delete_on_termination` | `peaso/checks/claude_aws_a_ec2.py:678` | corrected | evaluated |
| `aws.claude_a.ec2.instance_ebs_optimized` | `peaso/checks/claude_aws_a_ec2.py:413` | verified | — |
| `aws.claude_a.ec2.instance_imdsv2_applied` | `peaso/checks/claude_aws_a_ec2.py:520` | verified | — |
| `aws.claude_a.ec2.instance_imdsv2_or_disabled` | `peaso/checks/claude_aws_a_ec2.py:531` | verified | — |
| `aws.claude_a.ec2.instance_in_vpc` | `peaso/checks/claude_aws_a_ec2.py:448` | verified | — |
| `aws.claude_a.ec2.instance_no_launch_wizard_sg` | `peaso/checks/claude_aws_a_ec2.py:557` | corrected | evaluated |
| `aws.claude_a.ec2.instance_no_public_ip` | `peaso/checks/claude_aws_a_ec2.py:460` | verified | — |
| `aws.claude_a.ec2.instance_no_public_ip_not_terminated` | `peaso/checks/claude_aws_a_ec2.py:471` | verified | — |
| `aws.claude_a.ec2.instance_not_older_than_180_days` | `peaso/checks/claude_aws_a_ec2.py:605` | verified | — |
| `aws.claude_a.ec2.instance_not_paravirtual` | `peaso/checks/claude_aws_a_ec2.py:575` | verified | — |
| `aws.claude_a.ec2.instance_not_paravirtual_not_terminated` | `peaso/checks/claude_aws_a_ec2.py:584` | verified | — |
| `aws.claude_a.ec2.instance_port_cassandra_not_internet_exposed` | `peaso/checks/claude_aws_a_ec2.py:940` | verified | — |
| `aws.claude_a.ec2.instance_port_cifs_not_internet_exposed` | `peaso/checks/claude_aws_a_ec2.py:940` | verified | — |
| `aws.claude_a.ec2.instance_port_elasticsearch_kibana_not_internet_exposed` | `peaso/checks/claude_aws_a_ec2.py:940` | verified | — |
| `aws.claude_a.ec2.instance_port_ftp_not_internet_exposed` | `peaso/checks/claude_aws_a_ec2.py:940` | verified | — |
| `aws.claude_a.ec2.instance_port_kafka_not_internet_exposed` | `peaso/checks/claude_aws_a_ec2.py:940` | verified | — |
| `aws.claude_a.ec2.instance_port_kerberos_not_internet_exposed` | `peaso/checks/claude_aws_a_ec2.py:940` | verified | — |
| `aws.claude_a.ec2.instance_port_ldap_not_internet_exposed` | `peaso/checks/claude_aws_a_ec2.py:940` | verified | — |
| `aws.claude_a.ec2.instance_port_memcached_not_internet_exposed` | `peaso/checks/claude_aws_a_ec2.py:940` | verified | — |
| `aws.claude_a.ec2.instance_port_mongodb_not_internet_exposed` | `peaso/checks/claude_aws_a_ec2.py:940` | verified | — |
| `aws.claude_a.ec2.instance_port_mysql_not_internet_exposed` | `peaso/checks/claude_aws_a_ec2.py:940` | verified | — |
| `aws.claude_a.ec2.instance_port_oracle_not_internet_exposed` | `peaso/checks/claude_aws_a_ec2.py:940` | verified | — |
| `aws.claude_a.ec2.instance_port_postgresql_not_internet_exposed` | `peaso/checks/claude_aws_a_ec2.py:940` | verified | — |
| `aws.claude_a.ec2.instance_port_rdp_not_internet_exposed` | `peaso/checks/claude_aws_a_ec2.py:940` | verified | — |
| `aws.claude_a.ec2.instance_port_redis_not_internet_exposed` | `peaso/checks/claude_aws_a_ec2.py:940` | verified | — |
| `aws.claude_a.ec2.instance_port_sqlserver_not_internet_exposed` | `peaso/checks/claude_aws_a_ec2.py:940` | verified | — |
| `aws.claude_a.ec2.instance_port_ssh_not_internet_exposed` | `peaso/checks/claude_aws_a_ec2.py:940` | verified | — |
| `aws.claude_a.ec2.instance_port_telnet_not_internet_exposed` | `peaso/checks/claude_aws_a_ec2.py:940` | verified | — |
| `aws.claude_a.ec2.instance_profile_attached` | `peaso/checks/claude_aws_a_ec2.py:426` | verified | — |
| `aws.claude_a.ec2.instance_profile_attached_not_terminated` | `peaso/checks/claude_aws_a_ec2.py:436` | verified | — |
| `aws.claude_a.ec2.instance_protected_by_backup` | `peaso/checks/claude_aws_a_ec2.py:546` | corrected | evaluated |
| `aws.claude_a.ec2.instance_single_attachable_eni` | `peaso/checks/claude_aws_a_ec2.py:706` | corrected | evaluated |
| `aws.claude_a.ec2.instance_single_eni` | `peaso/checks/claude_aws_a_ec2.py:692` | verified | — |
| `aws.claude_a.ec2.instance_ssm_managed` | `peaso/checks/claude_aws_a_ec2.py:726` | verified | — |
| `aws.claude_a.ec2.instance_termination_protection` | `peaso/checks/claude_aws_a_ec2.py:595` | verified | — |
| `aws.claude_a.ec2.internet_facing_without_profile` | `peaso/checks/claude_aws_a_ec2.py:495` | corrected | evaluated |
| `aws.claude_a.ec2.launch_template_any_version_imdsv2` | `peaso/checks/claude_aws_a_ec2.py:1009` | verified | — |
| `aws.claude_a.ec2.launch_template_default_ebs_encrypted` | `peaso/checks/claude_aws_a_ec2.py:994` | verified | — |
| `aws.claude_a.ec2.launch_template_default_imdsv2` | `peaso/checks/claude_aws_a_ec2.py:983` | verified | — |
| `aws.claude_a.ec2.launch_template_instances_no_public_ip` | `peaso/checks/claude_aws_a_ec2.py:1051` | corrected | evaluated |
| `aws.claude_a.ec2.launch_template_no_public_ip` | `peaso/checks/claude_aws_a_ec2.py:1030` | verified | — |
| `aws.claude_a.ec2.public_instance_has_profile` | `peaso/checks/claude_aws_a_ec2.py:483` | corrected | evaluated |
| `aws.claude_a.ec2.running_instance_age_180_days` | `peaso/checks/claude_aws_a_ec2.py:614` | verified | — |
| `aws.claude_a.ec2.running_instance_no_key_pair` | `peaso/checks/claude_aws_a_ec2.py:508` | verified | — |
| `aws.claude_a.ec2.snapshot_block_public_access` | `peaso/checks/claude_aws_a_ec2.py:238` | verified | — |
| `aws.claude_a.ec2.spot_fleet_ebs_encrypted` | `peaso/checks/claude_aws_a_ec2.py:364` | verified | — |
| `aws.claude_a.ec2.stopped_instance_30_days` | `peaso/checks/claude_aws_a_ec2.py:644` | verified | — |
| `aws.claude_a.ec2.stopped_instance_90_days` | `peaso/checks/claude_aws_a_ec2.py:644` | verified | — |
| `aws.claude_a.ec2.stopped_instance_more_than_30_days` | `peaso/checks/claude_aws_a_ec2.py:665` | verified | — |
| `aws.claude_a.ec2.tgw_no_auto_accept_shared_attachments` | `peaso/checks/claude_aws_a_ec2.py:347` | verified | — |
| `aws.claude_a.guardduty.detector_no_findings` | `peaso/checks/claude_aws_a_security.py:143` | corrected | evaluated |
| `aws.claude_a.guardduty.ebs_malware_protection_feature` | `peaso/checks/claude_aws_a_security.py:91` | corrected | evaluated |
| `aws.claude_a.guardduty.ec2_runtime_agent_management` | `peaso/checks/claude_aws_a_security.py:91` | corrected | evaluated |
| `aws.claude_a.guardduty.ecs_runtime_agent_management` | `peaso/checks/claude_aws_a_security.py:91` | corrected | evaluated |
| `aws.claude_a.guardduty.eks_runtime_monitoring_feature` | `peaso/checks/claude_aws_a_security.py:91` | corrected | evaluated |
| `aws.claude_a.guardduty.finding_archived` | `peaso/checks/claude_aws_a_security.py:154` | verified | — |
| `aws.claude_a.guardduty.prowler_ai_protection` | `peaso/checks/claude_aws_a_security.py:222` | corrected | description, evaluated, pass_when, fail_when |
| `aws.claude_a.guardduty.prowler_centrally_managed` | `peaso/checks/claude_aws_a_security.py:253` | verified | — |
| `aws.claude_a.guardduty.prowler_delegated_admin_region` | `peaso/checks/claude_aws_a_security.py:276` | corrected | description, evaluated |
| `aws.claude_a.guardduty.prowler_ec2_malware_protection` | `peaso/checks/claude_aws_a_security.py:190` | corrected | description, evaluated, pass_when, fail_when |
| `aws.claude_a.guardduty.prowler_eks_audit_logs` | `peaso/checks/claude_aws_a_security.py:190` | corrected | description, evaluated, pass_when, fail_when |
| `aws.claude_a.guardduty.prowler_eks_runtime_monitoring` | `peaso/checks/claude_aws_a_security.py:190` | corrected | description, evaluated, pass_when, fail_when |
| `aws.claude_a.guardduty.prowler_lambda_protection` | `peaso/checks/claude_aws_a_security.py:190` | corrected | evaluated |
| `aws.claude_a.guardduty.prowler_no_high_severity_findings` | `peaso/checks/claude_aws_a_security.py:264` | verified | — |
| `aws.claude_a.guardduty.prowler_rds_protection` | `peaso/checks/claude_aws_a_security.py:190` | corrected | evaluated |
| `aws.claude_a.guardduty.prowler_runtime_monitoring` | `peaso/checks/claude_aws_a_security.py:235` | corrected | description, evaluated, pass_when, fail_when |
| `aws.claude_a.guardduty.prowler_s3_protection` | `peaso/checks/claude_aws_a_security.py:190` | corrected | description, evaluated, pass_when, fail_when |
| `aws.claude_a.guardduty.region_centrally_configured` | `peaso/checks/claude_aws_a_security.py:119` | corrected | description, evaluated |
| `aws.claude_a.iam.access_key_age_365` | `peaso/checks/claude_aws_a_iam.py:448` | verified | — |
| `aws.claude_a.iam.access_keys_rotated_90` | `peaso/checks/claude_aws_a_iam.py:640` | verified | — |
| `aws.claude_a.iam.access_keys_used_45` | `peaso/checks/claude_aws_a_iam.py:657` | verified | — |
| `aws.claude_a.iam.admin_user_has_mfa` | `peaso/checks/claude_aws_a_iam.py:467` | verified | — |
| `aws.claude_a.iam.attached_policy_no_star_star` | `peaso/checks/claude_aws_a_iam.py:237` | verified | — |
| `aws.claude_a.iam.aws_managed_policy_attached_to_role` | `peaso/checks/claude_aws_a_iam.py:300` | verified | — |
| `aws.claude_a.iam.cloudshell_full_access_not_attached` | `peaso/checks/claude_aws_a_iam.py:896` | corrected | description, evaluated, pass_when, fail_when |
| `aws.claude_a.iam.console_password_used_45` | `peaso/checks/claude_aws_a_iam.py:607` | verified | — |
| `aws.claude_a.iam.custom_attached_policy_no_star_star` | `peaso/checks/claude_aws_a_iam.py:214` | verified | — |
| `aws.claude_a.iam.custom_policy_attached_to_role` | `peaso/checks/claude_aws_a_iam.py:300` | verified | — |
| `aws.claude_a.iam.custom_policy_in_use` | `peaso/checks/claude_aws_a_iam.py:322` | corrected | evaluated |
| `aws.claude_a.iam.custom_policy_kms_decrypt_restricted` | `peaso/checks/claude_aws_a_iam.py:284` | verified | — |
| `aws.claude_a.iam.custom_policy_no_blocked_kms_actions` | `peaso/checks/claude_aws_a_iam.py:252` | verified | — |
| `aws.claude_a.iam.custom_policy_no_cloudtrail_star` | `peaso/checks/claude_aws_a_iam.py:252` | verified | — |
| `aws.claude_a.iam.custom_policy_no_kms_star` | `peaso/checks/claude_aws_a_iam.py:252` | verified | — |
| `aws.claude_a.iam.custom_policy_no_service_wildcard` | `peaso/checks/claude_aws_a_iam.py:252` | verified | — |
| `aws.claude_a.iam.custom_policy_no_star_star` | `peaso/checks/claude_aws_a_iam.py:197` | verified | — |
| `aws.claude_a.iam.custom_unattached_policy_no_star_star` | `peaso/checks/claude_aws_a_iam.py:227` | verified | — |
| `aws.claude_a.iam.group_inline_kms_decrypt_restricted` | `peaso/checks/claude_aws_a_iam.py:358` | corrected | not_applicable_when |
| `aws.claude_a.iam.group_inline_no_admin` | `peaso/checks/claude_aws_a_iam.py:372` | verified | — |
| `aws.claude_a.iam.group_inline_no_blocked_kms_actions` | `peaso/checks/claude_aws_a_iam.py:348` | verified | — |
| `aws.claude_a.iam.group_no_cloudshell_full_access` | `peaso/checks/claude_aws_a_iam.py:389` | verified | — |
| `aws.claude_a.iam.group_no_inline_policies` | `peaso/checks/claude_aws_a_iam.py:379` | corrected | not_applicable_when |
| `aws.claude_a.iam.group_not_empty` | `peaso/checks/claude_aws_a_iam.py:533` | verified | — |
| `aws.claude_a.iam.no_unused_initial_access_key` | `peaso/checks/claude_aws_a_iam.py:674` | verified | — |
| `aws.claude_a.iam.not_two_active_keys` | `peaso/checks/claude_aws_a_iam.py:684` | verified | — |
| `aws.claude_a.iam.policy_in_use` | `peaso/checks/claude_aws_a_iam.py:322` | corrected | evaluated |
| `aws.claude_a.iam.prowler_admin_group_members_mfa` | `peaso/checks/claude_aws_a_iam.py:792` | verified | — |
| `aws.claude_a.iam.prowler_aws_attached_policy_no_admin` | `peaso/checks/claude_aws_a_iam_prowler.py:238` | verified | — |
| `aws.claude_a.iam.prowler_console_password_used_45` | `peaso/checks/claude_aws_a_iam.py:623` | verified | — |
| `aws.claude_a.iam.prowler_customer_attached_policy_no_admin` | `peaso/checks/claude_aws_a_iam_prowler.py:238` | verified | — |
| `aws.claude_a.iam.prowler_customer_policy_no_cloudtrail_full_access` | `peaso/checks/claude_aws_a_iam_prowler.py:238` | verified | — |
| `aws.claude_a.iam.prowler_customer_policy_no_kms_full_access` | `peaso/checks/claude_aws_a_iam_prowler.py:238` | verified | — |
| `aws.claude_a.iam.prowler_customer_policy_no_marketplace_subscribe` | `peaso/checks/claude_aws_a_iam_prowler.py:238` | verified | — |
| `aws.claude_a.iam.prowler_customer_policy_no_permissive_role_assumption` | `peaso/checks/claude_aws_a_iam_prowler.py:238` | corrected | evaluated |
| `aws.claude_a.iam.prowler_customer_policy_no_privilege_escalation` | `peaso/checks/claude_aws_a_iam_prowler.py:238` | verified | — |
| `aws.claude_a.iam.prowler_customer_unattached_policy_no_admin` | `peaso/checks/claude_aws_a_iam_prowler.py:238` | verified | — |
| `aws.claude_a.iam.prowler_group_inline_no_admin` | `peaso/checks/claude_aws_a_iam_prowler.py:348` | verified | — |
| `aws.claude_a.iam.prowler_group_inline_no_cloudtrail_full_access` | `peaso/checks/claude_aws_a_iam_prowler.py:348` | verified | — |
| `aws.claude_a.iam.prowler_group_inline_no_kms_full_access` | `peaso/checks/claude_aws_a_iam_prowler.py:348` | verified | — |
| `aws.claude_a.iam.prowler_group_inline_no_marketplace_subscribe` | `peaso/checks/claude_aws_a_iam_prowler.py:348` | verified | — |
| `aws.claude_a.iam.prowler_group_inline_no_privilege_escalation` | `peaso/checks/claude_aws_a_iam_prowler.py:348` | verified | — |
| `aws.claude_a.iam.prowler_group_no_administratoraccess` | `peaso/checks/claude_aws_a_iam.py:738` | corrected | not_applicable_when |
| `aws.claude_a.iam.prowler_policy_agentcore_token_scoped` | `peaso/checks/claude_aws_a_iam_prowler.py:238` | verified | — |
| `aws.claude_a.iam.prowler_policy_passrole_agentcore_restricted` | `peaso/checks/claude_aws_a_iam_prowler.py:238` | verified | — |
| `aws.claude_a.iam.prowler_role_confused_deputy_prevented` | `peaso/checks/claude_aws_a_iam_prowler.py:387` | verified | — |
| `aws.claude_a.iam.prowler_role_inline_no_admin` | `peaso/checks/claude_aws_a_iam_prowler.py:348` | verified | — |
| `aws.claude_a.iam.prowler_role_inline_no_cloudtrail_full_access` | `peaso/checks/claude_aws_a_iam_prowler.py:348` | verified | — |
| `aws.claude_a.iam.prowler_role_inline_no_kms_full_access` | `peaso/checks/claude_aws_a_iam_prowler.py:348` | verified | — |
| `aws.claude_a.iam.prowler_role_inline_no_marketplace_subscribe` | `peaso/checks/claude_aws_a_iam_prowler.py:348` | verified | — |
| `aws.claude_a.iam.prowler_role_inline_no_privilege_escalation` | `peaso/checks/claude_aws_a_iam_prowler.py:348` | verified | — |
| `aws.claude_a.iam.prowler_role_no_administratoraccess` | `peaso/checks/claude_aws_a_iam.py:738` | verified | — |
| `aws.claude_a.iam.prowler_role_readonly_not_cross_account` | `peaso/checks/claude_aws_a_iam.py:769` | verified | — |
| `aws.claude_a.iam.prowler_role_service_trust_bound_to_account` | `peaso/checks/claude_aws_a_iam_prowler.py:402` | verified | — |
| `aws.claude_a.iam.prowler_root_hardware_mfa` | `peaso/checks/claude_aws_a_iam.py:697` | verified | — |
| `aws.claude_a.iam.prowler_user_hardware_mfa` | `peaso/checks/claude_aws_a_iam.py:812` | verified | — |
| `aws.claude_a.iam.prowler_user_inline_no_admin` | `peaso/checks/claude_aws_a_iam_prowler.py:348` | verified | — |
| `aws.claude_a.iam.prowler_user_inline_no_cloudtrail_full_access` | `peaso/checks/claude_aws_a_iam_prowler.py:348` | verified | — |
| `aws.claude_a.iam.prowler_user_inline_no_kms_full_access` | `peaso/checks/claude_aws_a_iam_prowler.py:348` | verified | — |
| `aws.claude_a.iam.prowler_user_inline_no_marketplace_subscribe` | `peaso/checks/claude_aws_a_iam_prowler.py:348` | verified | — |
| `aws.claude_a.iam.prowler_user_inline_no_privilege_escalation` | `peaso/checks/claude_aws_a_iam_prowler.py:348` | verified | — |
| `aws.claude_a.iam.prowler_user_no_administratoraccess` | `peaso/checks/claude_aws_a_iam.py:738` | corrected | not_applicable_when |
| `aws.claude_a.iam.role_bedrock_access_not_stale` | `peaso/checks/claude_aws_a_iam.py:850` | verified | — |
| `aws.claude_a.iam.role_inline_kms_decrypt_restricted` | `peaso/checks/claude_aws_a_iam.py:358` | verified | — |
| `aws.claude_a.iam.role_inline_no_admin` | `peaso/checks/claude_aws_a_iam.py:372` | verified | — |
| `aws.claude_a.iam.role_inline_no_blocked_kms_actions` | `peaso/checks/claude_aws_a_iam.py:348` | verified | — |
| `aws.claude_a.iam.role_no_administrator_access` | `peaso/checks/claude_aws_a_iam.py:480` | verified | — |
| `aws.claude_a.iam.role_no_cloudshell_full_access` | `peaso/checks/claude_aws_a_iam.py:389` | verified | — |
| `aws.claude_a.iam.role_no_inline_policies` | `peaso/checks/claude_aws_a_iam.py:379` | verified | — |
| `aws.claude_a.iam.role_readonly_not_cross_account` | `peaso/checks/claude_aws_a_iam.py:492` | verified | — |

## Correction notes

- `aws.cb.rds.sqlserver_error_log_export`: The engine test uses `startswith('sqlserver')`, covering all SQL Server editions.
- `aws.cb.rds.sqlserver_force_ssl_parameter`: The engine test covers all SQL Server editions and the parameter fails for every value other than string `1`, including an absent key.
- `aws.cb.redshift.security_group_port_restricted`: The port-range branch does not filter protocol; protocol `-1` with absent FromPort also fails.
- `aws.cb.resourceexplorer2.index_exists`: ListIndexes supplies the account index list in each regional scope.
- `aws.cb.sagemaker.clarify_job_exists`: The predicate matches `sagemaker-clarify-processing` in AppSpecification.ImageUri.
- `aws.cb.sagemaker.domain_sso`: Either SSO application identifier satisfies the linked-application condition.
- `aws.cb.sagemaker.model_registry_approved_package`: The evaluator compares ApprovedPackages numerically with zero.
- `aws.cb.sagemaker.monitoring_schedule_active`: The evaluator matches the exact `Scheduled` status.
- `aws.cb.ses.dkim_signing`: The evaluated fact kind is ses_email_identity.
- `aws.cb.ses.identity_policies_not_public`: The evaluated fact kind is ses_email_identity.
- `aws.cb.stepfunctions.cmk_encryption`: The evaluated fact kind is sfn_state_machine.
- `aws.claude2_a.cloudtrail.region_has_logging_trail`: The check is regional scope rather than an individual trail.
- `aws.claude_a.accessanalyzer.active_without_findings`: Empty analyzer inventory and any non-ACTIVE analyzer fail; any collected Findings row fails regardless of row status. The standard live collector requests ListFindingsV2 with status=ACTIVE, so archived and resolved findings outside that filter are not assessed.
- `aws.claude_a.cloudtrail.account_has_logging_multi_region_trail`: The check evaluates collected account trail inventory in scope.
- `aws.claude_a.ec2.account_imdsv2_default`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.ec2.client_vpn_connection_logging`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.ec2.enclave_host_ingress_allowlist`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.ec2.enclave_host_not_public`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.ec2.enclave_host_vsock_ports_closed`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.ec2.instance_ami_not_deprecated`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.ec2.instance_ebs_delete_on_termination`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.ec2.instance_no_launch_wizard_sg`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.ec2.instance_protected_by_backup`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.ec2.instance_single_attachable_eni`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.ec2.internet_facing_without_profile`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.ec2.launch_template_instances_no_public_ip`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.ec2.public_instance_has_profile`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.guardduty.detector_no_findings`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.guardduty.ebs_malware_protection_feature`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.guardduty.ec2_runtime_agent_management`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.guardduty.ecs_runtime_agent_management`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.guardduty.eks_runtime_monitoring_feature`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.guardduty.prowler_ai_protection`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.guardduty.prowler_delegated_admin_region`: The check is regional scope with detector, delegated administrator, and auto-enable conditions.
- `aws.claude_a.guardduty.prowler_ec2_malware_protection`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.guardduty.prowler_eks_audit_logs`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.guardduty.prowler_eks_runtime_monitoring`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.guardduty.prowler_lambda_protection`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.guardduty.prowler_rds_protection`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.guardduty.prowler_runtime_monitoring`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.guardduty.prowler_s3_protection`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.guardduty.region_centrally_configured`: The check is regional scope and accepts an enabled detector with an administrator.
- `aws.claude_a.iam.cloudshell_full_access_not_attached`: The evaluator reads IAM user, group, and role attachments in account scope, not an IAM policy resource.
- `aws.claude_a.iam.custom_policy_in_use`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.iam.group_inline_kms_decrypt_restricted`: The service-role exclusion applies only when kind is iam_role.
- `aws.claude_a.iam.group_no_inline_policies`: The service-role exclusion applies only when kind is iam_role.
- `aws.claude_a.iam.policy_in_use`: Corrected evaluated fact paths or outcome branches to match the registered evaluator.
- `aws.claude_a.iam.prowler_customer_policy_no_permissive_role_assumption`: The predicate reads managed policy version documents, not role inline policies.
- `aws.claude_a.iam.prowler_group_no_administratoraccess`: The service-role exclusion applies only when kind is iam_role.
- `aws.claude_a.iam.prowler_user_no_administratoraccess`: The service-role exclusion applies only when kind is iam_role.

Validation: 310 unique input IDs; 310 unique description keys; 310 unique decisions; 50 corrected entries.
