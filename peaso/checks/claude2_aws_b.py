"""claude2_aws_b partition (AWS-B rows taken over from stalled Codex workers): ports, merges, manual and rejected rows.

Ported predicates live in the claude2_aws_b_* service modules (one per service group); this
module loads them, merges their disposition tables and records the steampipe rows whose
pinned query_id is byte-identical to a query already reviewed and ported in an active shard
(AUTO). reviewed_claude2_aws_b*.json are generated from here.
"""
from __future__ import annotations

from . import (claude2_aws_b_compute, claude2_aws_b_edge, claude2_aws_b_data, claude2_aws_b_analytics,  # noqa: F401
               claude2_aws_b_identity, claude2_aws_b_devtools)
from .claude2_aws_b_common import ROWS, P, C, X  # noqa: F401

_GROUPS = (claude2_aws_b_compute, claude2_aws_b_edge, claude2_aws_b_data, claude2_aws_b_analytics,
           claude2_aws_b_identity, claude2_aws_b_devtools)

# Row -> (native ids, shared steampipe query_id, already-reviewed row using that same query).
# The pinned SQL is identical, so question, threshold and applicability are identical.
AUTO = {
    C + "cis_compute_service_v100_3_3": (["aws.cb.lightsail.ssh_rdp_http_world_closed"], "lightsail_instance_ssh_rdp_http_ports_disabled", "aws-compliance.control.lightsail_instance_ssh_rdp_http_ports_disabled"),
    C + "cis_compute_service_v100_3_4": (["aws.cb.lightsail.ssh_restricted"], "lightsail_instance_ssh_restricted_ip", "aws-compliance.control.lightsail_instance_ssh_restricted_ip"),
    C + "cis_compute_service_v100_3_5": (["aws.cb.lightsail.rdp_restricted"], "lightsail_instance_rdp_restricted_ip", "aws-compliance.control.lightsail_instance_rdp_restricted_ip"),
    C + "cis_compute_service_v100_3_6": (["aws.cb.lightsail.instance_ipv6_disabled"], "lightsail_instance_ipv6_networking_disabled", "aws-compliance.control.lightsail_instance_ipv6_networking_disabled"),
    C + "cis_compute_service_v100_4_12": (["aws.cb.lambda.kms_key_configured"], "lambda_function_encryption_enabled", "aws-compliance.control.lambda_function_encryption_enabled"),
    C + "cis_compute_service_v100_4_6": (["aws.cb.lambda.policy_no_wildcard_allow"], "lambda_function_restrict_public_access", "aws-compliance.control.lambda_function_restrict_public_access"),
    C + "foundational_security_apigateway_9": (["aws.cb.apigatewayv2.stage_access_logging"], "gatewayv2_stage_access_logging_enabled", "aws-compliance.control.gatewayv2_stage_access_logging_enabled"),
    C + "foundational_security_datafirehose_1": (["aws.cb.firehose.server_side_encryption"], "kinesis_firehose_delivery_stream_server_side_encryption_enabled", "aws-compliance.control.kinesis_firehose_delivery_stream_server_side_encryption_enabled"),
    C + "foundational_security_glue_3": (["aws.cb.glue.ml_transform_encryption_configured"], "glue_ml_transform_encryption_at_rest_enabled", "aws-compliance.control.glue_ml_transform_encryption_at_rest_enabled"),
    C + "foundational_security_glue_4": (["aws.cb.glue.spark_job_version_3"], "glue_spark_job_runs_on_version_3_or_higher", "aws-compliance.control.glue_spark_job_runs_on_version_3_or_higher"),
    C + "foundational_security_kinesis_1": (["aws.cb.kinesis.kms_encryption"], "kinesis_stream_server_side_encryption_enabled", "aws-compliance.control.kinesis_stream_server_side_encryption_enabled"),
    C + "foundational_security_kinesis_3": (["aws.cb.kinesis.retention_exactly_168h"], "kinesis_stream_retention_period_168_hours", "aws-compliance.control.kinesis_stream_retention_period_168_hours"),
    C + "foundational_security_lambda_1": (["aws.cb.lambda.policy_no_wildcard_allow"], "lambda_function_restrict_public_access", "aws-compliance.control.lambda_function_restrict_public_access"),
    C + "foundational_security_lambda_2": (["aws.cb.lambda.runtime_not_deprecated_list"], "lambda_function_use_latest_runtime", "aws-compliance.control.lambda_function_use_latest_runtime"),
    C + "foundational_security_lambda_5": (["aws.cb.lambda.vpc_multiple_az"], "lambda_function_multiple_az_configured", "aws-compliance.control.lambda_function_multiple_az_configured"),
    C + "foundational_security_mq_2": (["aws.cb.mq.activemq_audit_logs"], "mq_broker_audit_log_enabled", "aws-compliance.control.mq_broker_audit_log_enabled"),
    C + "foundational_security_msk_1": (["aws.cb.msk.client_broker_tls"], "msk_cluster_encryption_in_transit_with_tls_enabled", "aws-compliance.control.msk_cluster_encryption_in_transit_with_tls_enabled"),
    C + "foundational_security_msk_3": (["aws.cb.mskconnect.tls_to_cluster"], "mskconnect_connector_encryption_in_transit_with_tls_enabled", "aws-compliance.control.mskconnect_connector_encryption_in_transit_with_tls_enabled"),
    C + "foundational_security_msk_4": (["aws.cb.kafka.public_access_disabled"], "msk_cluster_not_publicly_accessible", "aws-compliance.control.msk_cluster_not_publicly_accessible"),
    C + "foundational_security_msk_5": (["aws.cb.mskconnect.log_delivery"], "mskconnect_connector_logging_enabled", "aws-compliance.control.mskconnect_connector_logging_enabled"),
    C + "foundational_security_msk_6": (["aws.cb.kafka.unauthenticated_access_disabled"], "msk_cluster_unauthenticated_access_disabled", "aws-compliance.control.msk_cluster_unauthenticated_access_disabled"),
    C + "foundational_security_neptune_3": (["aws.cb.neptune.snapshot_restore_not_all_exact"], "neptune_db_cluster_snapshot_prohibit_public_access", "aws-compliance.control.neptune_db_cluster_snapshot_prohibit_public_access"),
    C + "foundational_security_neptune_6": (["aws.cb.neptune.snapshot_encrypted"], "neptune_db_cluster_snapshot_encryption_at_rest_enabled", "aws-compliance.control.neptune_db_cluster_snapshot_encryption_at_rest_enabled"),
    C + "foundational_security_opensearch_1": (["aws.cb.opensearch.encryption_at_rest"], "opensearch_domain_encryption_at_rest_enabled", "aws-compliance.control.opensearch_domain_encryption_at_rest_enabled"),
    C + "foundational_security_opensearch_10": (["aws.cb.opensearch.service_software_current"], "opensearch_domain_updated_with_latest_service_software_version", "aws-compliance.control.opensearch_domain_updated_with_latest_service_software_version"),
    C + "foundational_security_opensearch_2": (["aws.cb.opensearch.in_vpc_private_subnets"], "opensearch_domain_in_vpc", "aws-compliance.control.opensearch_domain_in_vpc"),
    C + "foundational_security_opensearch_3": (["aws.cb.opensearch.node_to_node_encryption_region_skip"], "opensearch_domain_node_to_node_encryption_enabled", "aws-compliance.control.opensearch_domain_node_to_node_encryption_enabled"),
    C + "foundational_security_opensearch_4": (["aws.cb.opensearch.enabled_logs_have_log_group"], "opensearch_domain_logs_to_cloudwatch", "aws-compliance.control.opensearch_domain_logs_to_cloudwatch"),
    C + "foundational_security_opensearch_6": (["aws.cb.opensearch.data_node_fault_tolerance"], "opensearch_domain_data_node_fault_tolerance", "aws-compliance.control.opensearch_domain_data_node_fault_tolerance"),
    C + "foundational_security_opensearch_7": (["aws.cb.opensearch.fine_grained_access_control"], "opensearch_domain_fine_grained_access_enabled", "aws-compliance.control.opensearch_domain_fine_grained_access_enabled"),
    C + "foundational_security_rds_1": (["aws.cb.rds.cluster_snapshot_restore_not_all_exact", "aws.cb.rds.instance_snapshot_restore_not_all_exact"], "rds_db_snapshot_prohibit_public_access", "aws-compliance.control.rds_db_snapshot_prohibit_public_access"),
    C + "foundational_security_rds_11": (["aws.cb.rds.instance_backup_retention_nonzero_all"], "rds_db_instance_backup_enabled", "aws-compliance.control.rds_db_instance_backup_enabled"),
    C + "foundational_security_rds_14": (["aws.cb.rds.aurora_backtracking_configured"], "rds_db_cluster_aurora_backtracking_enabled", "aws-compliance.control.rds_db_cluster_aurora_backtracking_enabled"),
    C + "foundational_security_rds_16": (["aws.rds.cluster_copy_snapshot_tags"], "rds_db_cluster_copy_tags_to_snapshot_enabled", "aws-compliance.control.rds_db_cluster_copy_tags_to_snapshot_enabled"),
    C + "foundational_security_rds_18": (["aws.rds.vpc_configuration"], "rds_db_instance_in_vpc", "aws-compliance.control.rds_db_instance_in_vpc"),
    C + "foundational_security_rds_36": (["aws.cb.rds.postgres_log_exports"], "rds_db_instance_postgres_logging_enabled", "aws-compliance.control.rds_db_instance_postgres_logging_enabled"),
    C + "foundational_security_rds_37": (["aws.cb.rds.aurora_postgres_postgresql_log_export"], "rds_db_cluster_aurora_postgres_logging_enabled", "aws-compliance.control.rds_db_cluster_aurora_postgres_logging_enabled"),
    C + "foundational_security_rds_40": (["aws.cb.rds.sqlserver_error_log_export"], "rds_db_instance_sql_server_logging_enabled", "aws-compliance.control.rds_db_instance_sql_server_logging_enabled"),
    C + "foundational_security_rds_41": (["aws.cb.rds.sqlserver_force_ssl_parameter"], "rds_db_instance_sql_server_encryption_in_transit_enabled", "aws-compliance.control.rds_db_instance_sql_server_encryption_in_transit_enabled"),
    C + "foundational_security_rds_42": (["aws.cb.rds.mariadb_log_exports"], "rds_db_instance_mariadb_logging_enabled", "aws-compliance.control.rds_db_instance_mariadb_logging_enabled"),
    C + "foundational_security_rds_44": (["aws.cb.rds.mariadb_require_secure_transport"], "rds_db_instance_mariadb_encryption_in_transit_enabled", "aws-compliance.control.rds_db_instance_mariadb_encryption_in_transit_enabled"),
    C + "foundational_security_rds_45": (["aws.cb.rds.aurora_mysql_server_audit_logging"], "rds_db_cluster_aurora_mysql_audit_logging_enabled", "aws-compliance.control.rds_db_cluster_aurora_mysql_audit_logging_enabled"),
    C + "foundational_security_rds_6": (["aws.cb.rds.cluster_log_exports_declared", "aws.cb.rds.instance_enhanced_monitoring_except_m1_small"], "rds_db_instance_and_cluster_enhanced_monitoring_enabled", "aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled"),
    C + "foundational_security_redshift_15": (["aws.cb.redshift.security_group_port_restricted"], "redshift_cluster_security_group_restrict_ingress_redshift_port", "aws-compliance.control.redshift_cluster_security_group_restrict_ingress_redshift_port"),
    C + "foundational_security_redshift_18": (["aws.cb.redshift.multi_az"], "redshift_cluster_multiple_az_enabled", "aws-compliance.control.redshift_cluster_multiple_az_enabled"),
    C + "foundational_security_redshift_2": (["aws.cb.redshift.require_ssl"], "redshift_cluster_encryption_in_transit_enabled", "aws-compliance.control.redshift_cluster_encryption_in_transit_enabled"),
    C + "foundational_security_redshiftserverless_1": (["aws.cb.redshiftserverless.enhanced_vpc_routing"], "redshiftserverless_workgroup_enhanced_vpc_routing_enabled", "aws-compliance.control.redshiftserverless_workgroup_enhanced_vpc_routing_enabled"),
    C + "foundational_security_redshiftserverless_2": (["aws.cb.redshiftserverless.require_ssl"], "redshiftserverless_workgroup_encryption_in_transit_enabled", "aws-compliance.control.redshiftserverless_workgroup_encryption_in_transit_enabled"),
    C + "foundational_security_redshiftserverless_3": (["aws.cb.redshiftserverless.not_publicly_accessible"], "redshiftserverless_workgroup_restrict_public_access", "aws-compliance.control.redshiftserverless_workgroup_restrict_public_access"),
    C + "foundational_security_redshiftserverless_5": (["aws.cb.redshiftserverless.non_default_admin_username"], "redshiftserverless_namespace_no_default_admin_username", "aws-compliance.control.redshiftserverless_namespace_no_default_admin_username"),
    C + "foundational_security_redshiftserverless_6": (["aws.cb.redshiftserverless.connection_user_log_exports"], "redshiftserverless_namespace_export_connection_and_user_log_to_cloudwatch", "aws-compliance.control.redshiftserverless_namespace_export_connection_and_user_log_to_cloudwatch"),
    C + "foundational_security_redshiftserverless_7": (["aws.cb.redshiftserverless.non_default_database_name"], "redshiftserverless_namespace_no_default_database_username", "aws-compliance.control.redshiftserverless_namespace_no_default_database_username"),
    C + "foundational_security_route53_2": (["aws.cb.route53.public_zone_query_logging"], "route53_zone_query_logging_enabled", "aws-compliance.control.route53_zone_query_logging_enabled"),
    C + "foundational_security_sagemaker_1": (["aws.cb.sagemaker.notebook_no_direct_internet"], "sagemaker_notebook_instance_direct_internet_access_disabled", "aws-compliance.control.sagemaker_notebook_instance_direct_internet_access_disabled"),
    C + "foundational_security_sagemaker_2": (["aws.cb.sagemaker.notebook_in_vpc"], "sagemaker_notebook_instance_in_vpc", "aws-compliance.control.sagemaker_notebook_instance_in_vpc"),
    C + "foundational_security_sagemaker_3": (["aws.cb.sagemaker.notebook_root_access_disabled"], "sagemaker_notebook_instance_root_access_disabled", "aws-compliance.control.sagemaker_notebook_instance_root_access_disabled"),
    C + "foundational_security_sagemaker_4": (["aws.cb.sagemaker.endpoint_variants_not_exactly_one"], "sagemaker_endpoint_configuration_prod_instance_count_greater_than_one", "aws-compliance.control.sagemaker_endpoint_configuration_prod_instance_count_greater_than_one"),
    C + "foundational_security_sagemaker_5": (["aws.cb.sagemaker.model_network_isolation"], "sagemaker_model_network_isolation_enabled", "aws-compliance.control.sagemaker_model_network_isolation_enabled"),
    C + "foundational_security_sagemaker_8": (["aws.cb.sagemaker.notebook_supported_platform"], "sagemaker_notebook_instance_supported_platform_version", "aws-compliance.control.sagemaker_notebook_instance_supported_platform_version"),
    C + "foundational_security_secretsmanager_1": (["aws.cb.secretsmanager.rotation_rules_present"], "secretsmanager_secret_automatic_rotation_enabled", "aws-compliance.control.secretsmanager_secret_automatic_rotation_enabled"),
    C + "foundational_security_secretsmanager_2": (["aws.cb.secretsmanager.rotated_as_scheduled"], "secretsmanager_secret_rotated_as_scheduled", "aws-compliance.control.secretsmanager_secret_rotated_as_scheduled"),
    C + "foundational_security_secretsmanager_3": (["aws.cb.secretsmanager.accessed_within_90_calendar_days"], "secretsmanager_secret_unused_90_day", "aws-compliance.control.secretsmanager_secret_unused_90_day"),
    C + "foundational_security_secretsmanager_4": (["aws.cb.secretsmanager.rotation_lambda"], "secretsmanager_secret_automatic_rotation_lambda_enabled", "aws-compliance.control.secretsmanager_secret_automatic_rotation_lambda_enabled"),
    C + "foundational_security_servicecatalog_1": (["aws.cb.servicecatalog.no_account_shares"], "servicecatalog_portfolio_shared_only_with_aws_organization", "aws-compliance.control.servicecatalog_portfolio_shared_only_with_aws_organization"),
    C + "foundational_security_sfn_1": (["aws.cb.sfn.logging_not_off"], "sfn_state_machine_logging_enabled", "aws-compliance.control.sfn_state_machine_logging_enabled"),
    C + "foundational_security_sns_1": (["aws.sns.kms_encryption"], "sns_topic_encrypted_at_rest", "aws-compliance.control.sns_topic_encrypted_at_rest"),
    C + "foundational_security_sns_2": (["aws.cb.sns.failure_feedback_role"], "sns_topic_notification_delivery_status_enabled", "aws-compliance.control.sns_topic_notification_delivery_status_enabled"),
    C + "foundational_security_sns_4": (["aws.cb.sns.policy_no_unrestricted_wildcard"], "sns_topic_policy_prohibit_public_access", "aws-compliance.control.sns_topic_policy_prohibit_public_access"),
    C + "foundational_security_sqs_1": (["aws.sqs.encryption"], "sqs_queue_encrypted_at_rest", "aws-compliance.control.sqs_queue_encrypted_at_rest"),
    C + "foundational_security_sqs_3": (["aws.cb.sqs.policy_no_wildcard_allow"], "sqs_queue_policy_prohibit_public_access", "aws-compliance.control.sqs_queue_policy_prohibit_public_access"),
    C + "foundational_security_ssm_2": (["aws.cb.ssm.instance_patch_compliant"], "ssm_managed_instance_compliance_patch_compliant", "aws-compliance.control.ssm_managed_instance_compliance_patch_compliant"),
    C + "foundational_security_ssm_3": (["aws.cb.ssm.instance_association_compliant"], "ssm_managed_instance_compliance_association_compliant", "aws-compliance.control.ssm_managed_instance_compliance_association_compliant"),
    C + "foundational_security_ssm_6": (["aws.cb.ssm.automation_logs_to_cloudwatch"], "ssm_automation_cloudwatch_logging_enabled", "aws-compliance.control.ssm_automation_cloudwatch_logging_enabled"),
    C + "foundational_security_ssm_7": (["aws.cb.ssm.block_public_document_sharing"], "ssm_document_block_public_sharing_setting_enabled", "aws-compliance.control.ssm_document_block_public_sharing_setting_enabled"),
    C + "foundational_security_transfer_2": (["aws.cb.transfer.no_ftp_protocol"], "transfer_server_no_ftp_protocol", "aws-compliance.control.transfer_server_no_ftp_protocol"),
    C + "foundational_security_transfer_3": (["aws.cb.transfer.connector_logging_role"], "transfer_connector_logging_enabled", "aws-compliance.control.transfer_connector_logging_enabled"),
    C + "foundational_security_waf_1": (["aws.cb.waf.web_acl_logging"], "waf_web_acl_logging_enabled", "aws-compliance.control.waf_web_acl_logging_enabled"),
    C + "foundational_security_waf_10": (["aws.cb.wafv2.web_acl_has_rules"], "wafv2_web_acl_rule_attached", "aws-compliance.control.wafv2_web_acl_rule_attached"),
    C + "foundational_security_waf_12": (["aws.cb.wafv2.rule_group_metrics"], "wafv2_rule_group_logging_enabled", "aws-compliance.control.wafv2_rule_group_logging_enabled"),
    C + "foundational_security_waf_2": (["aws.cb.wafregional.rule_has_conditions"], "waf_regional_rule_condition_attached", "aws-compliance.control.waf_regional_rule_condition_attached"),
    C + "foundational_security_waf_3": (["aws.cb.wafregional.rule_group_not_empty"], "waf_regional_rule_group_rule_attached", "aws-compliance.control.waf_regional_rule_group_rule_attached"),
    C + "foundational_security_waf_4": (["aws.cb.wafregional.web_acl_has_rules"], "waf_regional_web_acl_rule_attached", "aws-compliance.control.waf_regional_web_acl_rule_attached"),
    C + "foundational_security_waf_6": (["aws.cb.waf.rule_has_conditions"], "waf_rule_condition_attached", "aws-compliance.control.waf_rule_condition_attached"),
    C + "foundational_security_waf_7": (["aws.cb.waf.rule_group_not_empty"], "waf_rule_group_rule_attached", "aws-compliance.control.waf_rule_group_rule_attached"),
    C + "foundational_security_waf_8": (["aws.cb.waf.web_acl_has_rules"], "waf_web_acl_rule_attached", "aws-compliance.control.waf_web_acl_rule_attached"),
    C + "foundational_security_workspaces_1": (["aws.cb.workspaces.user_volume_encryption"], "workspaces_workspace_user_volume_encryption_enabled", "aws-compliance.control.workspaces_workspace_user_volume_encryption_enabled"),
    C + "foundational_security_workspaces_2": (["aws.cb.workspaces.root_volume_encryption"], "workspaces_workspace_root_volume_encryption_enabled", "aws-compliance.control.workspaces_workspace_root_volume_encryption_enabled"),
}

# Rows held as ported by other ACTIVE shards (addendum: drop them from this shard).
HELD_ELSEWHERE = {
    "reviewed_aws_b_cognito.json": [P + "cognito_user_pool_" + s for s in (
        "password_policy_lowercase", "password_policy_uppercase", "password_policy_number", "password_policy_symbol",
        "deletion_protection_enabled", "mfa_enabled", "advanced_security_enabled", "self_registration_disabled",
        "password_policy_minimum_length_14", "temporary_password_expiration", "blocks_compromised_credentials_sign_in_attempts",
        "blocks_potential_malicious_sign_in_attempts")],
    "reviewed_aws_b_redshift.json": [C + "foundational_security_redshift_" + n for n in ("1", "3", "4", "6", "7", "8", "9", "10")],
}

MERGED = {row: (natives, "Pinned query " + query + " is identical to the one behind " + twin + ", already ported natively.")
          for row, (natives, query, twin) in AUTO.items()}
MERGED[C + "elasticache_cluster_no_public_subnet"] = (
    ["aws.c2b.elasticache.cluster_public_subnet_prowler"],
    "The reviewed Steampipe NAT-route false positive is corrected to require an internet-gateway default route; the surviving Prowler predicate applies that same public-subnet criterion.",
)
MANUAL = {}
REJECTED = {
    C + "foundational_security_opensearch_5": {"classification": "invalid_predicate",
        "reason": "Uses the same pinned query as opensearch_domain_audit_logging_enabled: both CASE branches return 'ok', so the control can never alarm. AWS documents audit logs as LogPublishingOptions.AUDIT_LOGS (Enabled + CloudWatch log group); the corrected native predicate is aws.cb.opensearch.audit_logs_enabled.",
        "replacement": ["aws.cb.opensearch.audit_logs_enabled"],
        "docs": ["https://docs.aws.amazon.com/opensearch-service/latest/developerguide/audit-logs.html"]},
    C + "foundational_security_opensearch_8": {"classification": "invalid_predicate",
        "reason": "Uses the same pinned query as opensearch_domain_https_required, which compares DomainEndpointOptions.TLSSecurityPolicy with the literal 'tlsPolicies' (not a valid value: Policy-Min-TLS-1-0-2019-07, Policy-Min-TLS-1-2-2019-07, Policy-Min-TLS-1-2-PFS-2023-10), so it alarms on every EnforceHTTPS domain. Corrected native predicate: aws.cb.opensearch.enforce_https.",
        "replacement": ["aws.cb.opensearch.enforce_https"],
        "docs": ["https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_DomainEndpointOptions.html"]},
}

for _group in _GROUPS:
    for _name, _table in (("MERGED", MERGED), ("MANUAL", MANUAL), ("REJECTED", REJECTED)):
        _dup = set(_table) & set(getattr(_group, _name))
        if _dup:
            raise ValueError("row handled twice in claude2_aws_b: " + ", ".join(sorted(_dup)))
        _table.update(getattr(_group, _name))


def ported():
    """Row -> list of native ids ported in this partition."""
    out = {}
    for cid, rows in ROWS.items():
        for row in rows:
            out.setdefault(row, []).append(cid)
    return out


def dispositions():
    """Row -> (disposition, natives or detail) for every row handled by this partition."""
    out = {row: ("ported", natives) for row, natives in ported().items()}
    for kind, table in (("merged", MERGED), ("manual", MANUAL), ("rejected", REJECTED)):
        for row, entry in table.items():
            if row in out:
                raise ValueError("row has two dispositions in claude2_aws_b: " + row)
            out[row] = (kind, entry[0] if kind == "merged" else entry)
    return out
