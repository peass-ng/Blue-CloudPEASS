"""Evaluate a deliberately small, portable subset of Sigma against canonical events.

The checked-in YAML follows Sigma's logsource/detection/condition format. This
module supports only exact field equality, OR lists, AND within one selection,
and ``condition: selection``. Unsupported constructs fail closed at load time.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
import os
import re
from pathlib import Path
from typing import Any

import yaml

from .aws import normalize_aws_cloudtrail
from .aws_raw_cloudtrail import normalize as normalize_aws_raw_cloudtrail
from .aws_login_profile_next import normalize_aws_other_user_login_profile, normalize_aws_other_user_login_profile_update
from .aws_security_controls import normalize_aws_security_control
from .aws_trail_update import normalize_aws_trail_update
from .aws_cloudtrail_selectors_next import normalize_aws_cloudtrail_selectors
from .aws_cloudtrail_log_dest_next import correlate as correlate_aws_cloudtrail_log_dest
from .aws_cloudtrail_log_objects_next import correlate as correlate_aws_cloudtrail_log_objects
from .aws_role_boundary_next import normalize_aws_role_boundary_delete
from .aws_user_boundary_self_next import normalize_aws_self_user_boundary_delete
from .aws_wildcard_trust_next import normalize_aws_wildcard_role_trust
from .aws_keyspaces_next import normalize_keyspaces_other_user_credential
from .aws_keyspaces_timestamps_next import normalize as normalize_keyspaces_timestamps
from .aws_codebuild_next import normalize_aws_codebuild_change
from .aws_codebuild_execution_next import normalize_codebuild_execution
from .aws_codebuild_sandbox_read_next import normalize as normalize_codebuild_sandbox_read
from .aws_codepipeline_five_next import normalize as normalize_aws_codepipeline_five
from .aws_codepipeline_remaining_next import normalize as normalize_aws_codepipeline_remaining, correlate as correlate_aws_codepipeline_remaining
from .aws_codepipeline_reads_next import normalize as normalize_aws_codepipeline_reads
from .aws_lightsail_six_next import normalize as normalize_aws_lightsail_six
from .aws_lightsail_snapshot_dns_next import normalize as normalize_aws_lightsail_snapshot_dns
from .aws_lightsail_db_next import normalize as normalize_aws_lightsail_db
from .aws_ecr_lightsail_batch_next import normalize as normalize_aws_ecr_lightsail_batch, correlate_tag_overwrite as correlate_aws_ecr_tag_overwrite
from .aws_ecr_public_push_next import normalize_public as normalize_aws_ecr_public_push, correlate_new_layer_push as correlate_aws_ecr_new_layer_push
from .aws_cloudwatch_logs_data_next import normalize as normalize_aws_cloudwatch_logs_data
from .aws_cloudwatch_dashboard_insight_next import normalize as normalize_aws_cloudwatch_dashboard_insight
from .aws_codecommit_source_next import normalize as normalize_aws_codecommit_source
from .aws_codecommit_consumer_next import correlate as correlate_aws_codecommit_consumers
from .aws_appconfig_hosted_next import correlate as correlate_aws_appconfig_hosted
from .aws_codebuild_gap_correlations_next import correlate as correlate_aws_codebuild_gaps
from .aws_appsync_five_next import normalize as normalize_aws_appsync_five
from .aws_appsync_read_function_next import normalize as normalize_aws_appsync_read_function
from .aws_appsync_signed_role_next import normalize as normalize_aws_appsync_signed_role
from .aws_apigateway_rest_next import correlate as correlate_aws_apigateway_rest
from .aws_sagemaker_control_next import normalize_aws_sagemaker_control
from .aws_rolesanywhere_next import normalize as normalize_aws_rolesanywhere
from .aws_customer_profiles_next import normalize as normalize_aws_customer_profiles
from .aws_customer_profiles_read_next import normalize as normalize_aws_customer_profiles_read
from .aws_customer_profiles_write_next import normalize as normalize_aws_customer_profiles_write
from .aws_customer_profiles_disruption_next import normalize as normalize_aws_customer_profiles_disruption
from .aws_customer_profiles_paths_next import normalize as normalize_aws_customer_profiles_paths
from .aws_customer_profiles_segments_next import normalize as normalize_aws_customer_profiles_segments
from .aws_customer_profiles_export_next import normalize as normalize_aws_customer_profiles_export
from .aws_servicecatalog_next import normalize as normalize_aws_servicecatalog, correlate as correlate_aws_servicecatalog
from .aws_s3_retention_next import normalize_aws_s3_retention
from .aws_s3_ssec_next import normalize as normalize_aws_s3_ssec, correlate as correlate_aws_s3_ssec
from .aws_s3_acl_grants_next import normalize as normalize_aws_s3_acl_grants
from .aws_s3_access_point_lock_next import normalize as normalize_aws_s3_access_point_lock, correlate as correlate_aws_s3_access_point_lock
from .aws_iot_core_batch_next import normalize as normalize_aws_iot_core_batch
from .aws_iot_provision_jobs_next import normalize as normalize_aws_iot_provision_jobs, correlate_external_cert_policy as correlate_aws_iot_external_cert_policy
from .aws_lambda_access_mapping_next import normalize as normalize_aws_lambda_access_mapping, correlate_repoint as correlate_aws_lambda_mapping_repoint
from .aws_s3_notification_next import normalize_aws_s3_template_notification
from .aws_s3_replication_next import normalize_aws_s3_replication
from .aws_ecr_replication_next import normalize_aws_ecr_replication
from .aws_ecr_registry_policy_next import normalize_aws_ecr_registry_policy
from .aws_efs_access_next import normalize_aws_efs_access, normalize_aws_efs_deletion
from .aws_waf_logging_next import normalize_aws_waf_logging, normalize_aws_waf_deletion, normalize_aws_waf_disassociation
from .aws_waf_web_acl_next import normalize_aws_waf_web_acl
from .aws_codeartifact_policy_next import normalize_aws_codeartifact_policy
from .aws_codeartifact_routes_next import normalize_aws_codeartifact_routes
from .aws_appconfig_extension_next import normalize_aws_appconfig_extension
from .aws_athena_workgroup_next import normalize_aws_athena_workgroup
from .aws_athena_stored_query_next import normalize as normalize_aws_athena_stored_query, correlate as correlate_aws_athena_stored_query
from .aws_athena_history_cross_actor_next import correlate as correlate_aws_athena_history_cross_actor
from .aws_athena_spark_v3_cross_actor_next import normalize_create_workgroup as normalize_aws_athena_spark_workgroup, correlate as correlate_aws_athena_spark_v3
from .aws_athena_spark35_endpoint_next import correlate as correlate_aws_athena_spark35_endpoint
from .aws_config_recorder_next import normalize_aws_config_recorder_stop, normalize_aws_config_auto_remediation
from .aws_eventbridge_archive_next import normalize_aws_eventbridge_archive
from .aws_eventbridge_rule_targets_next import normalize_aws_eventbridge_rule_targets
from .aws_scheduler_controls_next import normalize_aws_scheduler_controls
from .aws_pipes_controls_next import normalize_aws_pipes_controls
from .aws_eventsv2_controls_next import normalize_aws_eventsv2_controls
from .aws_eventsv2_policy_next import normalize_aws_eventsv2_policy
from .aws_ecr_policy_next import normalize_aws_ecr_policy
from .aws_backup_vault_next import normalize_aws_backup_self_grant
from .aws_ecr_template_next import normalize_aws_ecr_template
from .aws_secretsmanager_self_policy_next import normalize_aws_secret_self_read_grant
from .aws_secretsmanager_tamper_next import normalize_aws_secret_tamper
from .aws_secretsmanager_followup_next import normalize_aws_secretsmanager_followup
from .aws_guardduty_controls_next import normalize_aws_guardduty_controls
from .aws_ecr_retention_next import normalize_aws_ecr_retention
from .aws_dynamodb_controls_next import normalize_aws_dynamodb_controls
from .aws_dynamodb_backup_stream_next import normalize_aws_dynamodb_backup_stream
from .aws_sns_sqs_controls_next import normalize_aws_sns_sqs_controls
from .aws_sqs_followup_next import normalize_aws_sqs_followup, correlate_aws_sqs_tagged_receive
from .aws_sqs_data_next import normalize_aws_sqs_data, correlate_aws_sqs_fifo_dedup_collision
from .aws_sqs_redrive_next import normalize_aws_sqs_redrive
from .aws_sns_controls_next import normalize_aws_sns_topic_controls
from .aws_chime_admin_next import normalize_aws_chime_admin
from .aws_chime_attendee_messaging_next import normalize_aws_chime_attendee_messaging
from .aws_chime_capability_flow_next import normalize_aws_chime_capability_flow
from .aws_chime_voice_connector_next import normalize_aws_chime_voice_connector
from .aws_chime_voice_sip_next import normalize_aws_chime_voice_sip
from .aws_chime_media_pipelines_next import (
    normalize_aws_chime_media_pipeline, correlate_aws_chime_live_pipeline_read,
)
from .aws_chime_media_insights_next import (
    normalize_aws_chime_media_insights, correlate_aws_chime_media_insights,
)
from .aws_glue_controls_next import normalize_aws_glue_controls
from .aws_cloudfront_controls_next import normalize_aws_cloudfront_controls
from .aws_glue_session_correlations_next import correlate_aws_glue_cross_actor_statements
from .aws_glue_job_correlations_next import correlate_aws_glue_job_script_runs
from .aws_cognito_controls_next import normalize_aws_cognito_controls
from .aws_cognito_directory_next import normalize_aws_cognito_directory
from .aws_cognito_m2m_next import normalize_aws_cognito_m2m
from .aws_cognito_identity_next import normalize_aws_cognito_identity
from .aws_cognito_federation_next import normalize_aws_cognito_federation
from .aws_cognito_mfa_next import normalize_aws_cognito_mfa
from .aws_cognito_import_next import normalize_aws_cognito_import
from .aws_cognito_pool_client_next import normalize_aws_cognito_pool_client
from .aws_cognito_group_correlations_next import correlate_aws_cognito_role_group_membership
from .aws_sts_correlations_next import correlate_aws_sts_role_cycle
from .aws_rolesanywhere_controls_next import normalize_aws_rolesanywhere_controls
from .aws_sts_web_token_next import normalize_aws_sts_web_token
from .aws_supportauthz_next import normalize_aws_support_permit
from .aws_iam_saml_provider_next import normalize_aws_iam_saml_provider_update
from .aws_iam_federation_providers_next import normalize_aws_iam_federation_provider
from .aws_iam_federation_deletion_next import normalize_aws_iam_federation_deletion
from .aws_resource_explorer_next import normalize_aws_resource_explorer_view
from .aws_ses_receipt_next import normalize_aws_ses_receipt
from .aws_kinesis_controls_next import normalize_aws_kinesis_controls
from .aws_kinesis_data_write_next import normalize as normalize_aws_kinesis_data_write
from .aws_kinesis_data_read_next import normalize as normalize_aws_kinesis_data_read
from .aws_kinesis_controls_extended_next import normalize_aws_kinesis_controls_extended
from .aws_kinesis_channel_next import normalize_aws_kinesis_channel
from .aws_kinesis_video_controls_next import normalize_aws_kinesis_video_controls
from .aws_kinesis_video_endpoint_next import normalize_aws_kinesis_video_endpoint
from .aws_ecs_controls_next import normalize_aws_ecs_controls
from .aws_ecs_correlations_next import correlate_aws_ecs_dormant_sidecar
from .aws_emr_serverless_next import normalize_aws_emr_serverless_runtime
from .aws_emr_serverless_session_next import correlate_aws_emr_session_endpoint_cross_actor
from .aws_cloudwatch_controls_next import normalize_aws_cloudwatch_controls
from .aws_lambda_controls_next import normalize_aws_lambda_controls
from .aws_lambda_alias_grant_next import normalize_aws_lambda_qualified_grant
from .aws_lambda_config_next import normalize_aws_lambda_config
from .aws_lambda_privesc_next import normalize_aws_lambda_role_assignment, correlate_aws_lambda_privesc
from .aws_ec2_controls_next import normalize_aws_ec2_controls
from .aws_vpc_network_next import normalize_aws_vpc_network, correlate_aws_vpc_custom_dns
from .aws_apigateway_controls_next import normalize_aws_apigateway_controls
from .aws_apigateway_http_keys_next import normalize as normalize_aws_apigateway_http_keys
from .aws_apigateway_portal_next import correlate as correlate_aws_apigateway_portal
from .aws_apigateway_private_vpce_next import normalize as normalize_aws_apigateway_private_vpce
from .aws_cloudformation_reads_next import normalize as normalize_aws_cloudformation_reads
from .aws_cloudformation_triggers_next import normalize as normalize_aws_cloudformation_triggers, correlate as correlate_aws_cloudformation_triggers
from .aws_cloudformation_inputs_stacksets_next import normalize_stackset as normalize_aws_cloudformation_stackset, correlate_inputs as correlate_aws_cloudformation_inputs
from .aws_eventbridge_controls_next import normalize_aws_eventbridge_controls
from .aws_eventbridge_connections_next import normalize_aws_eventbridge_connections
from .aws_ssm_controls_next import normalize_aws_ssm_controls
from .aws_ssm_parameter_read_next import normalize_aws_ssm_parameter_read
from .aws_ssm_association_next import normalize_aws_ssm_association_start
from .aws_ssm_command_history_next import correlate_aws_ssm_command_output_read
from .aws_ssm_session_next import normalize_aws_ssm_session_start
from .aws_ssm_automation_window_next import normalize_aws_ssm_automation_window, correlate_aws_ssm_document_window
from .aws_stepfunctions_controls_next import normalize_aws_stepfunctions_controls, normalize_aws_stepfunctions_activity_alias, normalize_aws_stepfunctions_redrive
from .aws_rds_controls_next import normalize_aws_rds_controls
from .aws_rds_restore_next import normalize_aws_rds_restore_controls, correlate_aws_rds_public_clone_password_reset
from .aws_rds_parameters_next import normalize_aws_rds_parameters, correlate_aws_rds_sql_log_capture_path
from .aws_rds_replica_next import normalize_aws_rds_public_replica, correlate_aws_rds_public_replica_controls
from .aws_rds_secret_read_next import normalize_aws_rds_managed_secret_read, correlate_aws_rds_proxy_auth_secret_read
from .aws_rds_pending_signals_next import normalize_aws_rds_pending_signals
from .aws_service_credentials_next import normalize_aws_service_credentials
from .aws_cloudformation_controls_next import normalize_aws_cloudformation_controls
from .aws_cloudformation_policy_next import normalize_aws_cloudformation_stack_policy
from .aws_kms_grants_next import normalize_aws_kms_standing_access, normalize_aws_kms_key_deletion, normalize_aws_kms_key_disabled
from .aws_kms_alias_rotation_next import normalize_aws_kms_alias_rotation
from .aws_kms_imported_material_next import normalize_aws_kms_imported_material
from .aws_kms_cancel_deletion_next import normalize_aws_kms_cancel_deletion
from .aws_kms_replicate_next import normalize_aws_kms_replication
from .aws_kms_rotation_complete_next import normalize_aws_kms_on_demand_rotation
from .aws_iam_group_role_next import normalize_aws_iam_group_role
from .aws_iam_mfa_controls_next import normalize_aws_iam_mfa_controls
from .aws_iam_policy_removal_next import normalize as normalize_aws_iam_policy_removal
from .aws_iam_credential_boundary_next import normalize as normalize_aws_iam_credential_boundary
from .aws_iam_identity_deletion_next import normalize as normalize_aws_iam_identity_deletion
from .aws_iam_remaining_credential_deletion_next import normalize as normalize_aws_iam_credential_deletion
from .aws_iam_cert_key_controls_next import normalize as normalize_aws_iam_cert_key_controls
from .gcp import normalize_gcp_audit
from .gcp_next import normalize_gcp_project_self_iam_bindings
from .gcp_iam_cross_project_next import normalize_gcp_cross_project_sa_grants
from .gcp_logging_next import normalize_gcp_default_sink_disabled
from .gcp_logging_tamper_next import normalize_gcp_data_access_exclusion_created, normalize_gcp_data_access_log_delete
from .gcp_hmac_next import normalize_gcp_hmac_key_created
from .gcp_secret_versions_next import (
    normalize_gcp_secret_delete,
    normalize_gcp_secret_version_destroy,
    normalize_gcp_secret_version_disable,
)
from .kubernetes import normalize_kubernetes_audit_candidates
from .kubernetes_next import normalize_kubernetes_cluster_admin_grant
from .kubernetes_pod_next import normalize_kubernetes_privileged_host_pod
from .kubernetes_ephemeral_next import normalize_kubernetes_privileged_ephemeral_update
from .kubernetes_runtime_socket_next import normalize_kubernetes_runtime_socket_pod
from .kubernetes_aggregate_view_next import normalize_aggregate_view_secret_read
from .kubernetes_daemonset_next import normalize_kubernetes_privileged_daemonset


DEFAULT_RULE_REPO = "peass-ng/peasso-cspm-detections"
DEFAULT_RULE_REF = "08725c62951dc198b13e03d98879bbf2dd2cf167"
DEFAULT_RULE_PACK_SHA256 = "d4819d8924be714a41fe29230fcb44ae9866ed364d80b187db04359e9c4c1217"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    level: str
    description: str
    technique_id: str
    product: str
    selection: Mapping[str, Any]
    falsepositives: tuple[str, ...] = ()
    raw_cloudtrail: bool = False
    resource_path_prefix: str | None = None


@dataclass(frozen=True)
class Detection:
    rule_id: str
    title: str
    severity: str
    technique_id: str
    event_id: str | None
    event_time: str | None
    account_id: str | None
    actor_id: str | None
    target_id: str | None
    evidence: Mapping[str, Any]
    description: str
    legitimate_context: tuple[str, ...]


class RuleSourceError(ValueError):
    """A stable error that never contains the GitHub credential or response."""


@lru_cache(maxsize=4)
def _github_rule_texts(repo: str, ref: str) -> tuple[tuple[str, str], ...]:
    if not repo or not ref:
        raise RuleSourceError("rule_source_not_configured")
    try:
        from .github_source import fetch_rules
        digest = (DEFAULT_RULE_PACK_SHA256 if (repo, ref) == (DEFAULT_RULE_REPO, DEFAULT_RULE_REF)
                  else os.getenv("HACKTRICKS_CSPM_RULES_PACK_SHA256") or None)
        return tuple(sorted(fetch_rules(repo, ref, digest).items()))
    except Exception:
        raise RuleSourceError("rule_source_unavailable") from None


def _rule_texts(directory: Path | None) -> tuple[tuple[str, str], ...]:
    if directory is not None:
        return tuple((path.relative_to(directory).as_posix(), path.read_text(encoding="utf-8"))
                     for path in sorted(directory.rglob("*.yml")))
    repo_override = os.getenv("HACKTRICKS_CSPM_RULES_GITHUB_REPO", "")
    ref_override = os.getenv("HACKTRICKS_CSPM_RULES_GITHUB_REF", "")
    local = os.getenv("HACKTRICKS_CSPM_RULES_DIR", "")
    if local and os.getenv("PEASO_AUTH_MODE") != "cognito" and not repo_override and not ref_override:
        return _rule_texts(Path(local))
    if repo_override and not ref_override:
        raise RuleSourceError("rule_source_ref_required")
    return _github_rule_texts(repo_override or DEFAULT_RULE_REPO, ref_override or DEFAULT_RULE_REF)


def load_rules(directory: Path | None = None, *, product: str | None = None) -> tuple[Rule, ...]:
    loaded: list[Rule] = []
    for name, text in _rule_texts(directory):
        source = yaml.safe_load(text)
        if not isinstance(source, Mapping):
            raise ValueError(f"Invalid detection rule: {name}")
        logsource = source.get("logsource")
        detection = source.get("detection")
        if not isinstance(logsource, Mapping) or (logsource.get("product"), logsource.get("service")) not in {
            ("aws", "cloudtrail"), ("gcp", "audit"), ("kubernetes", "audit"),
            ("azure", "activity"), ("azure", "entra"),
        } or set(logsource) != {"product", "service"}:
            raise ValueError(f"Unsupported log source: {name}")
        if not isinstance(detection, Mapping) or set(detection) != {"selection", "condition"} or detection["condition"] != "selection":
            raise ValueError(f"Unsupported detection grammar: {name}")
        selection = detection["selection"]
        if not isinstance(selection, Mapping) or not selection or any(not isinstance(k, str) or "|" in k for k in selection):
            raise ValueError(f"Unsupported detection selection: {name}")
        if any(not isinstance(v, (str, bool, int, list)) or isinstance(v, list) and (not v or any(not isinstance(x, (str, bool, int)) for x in v)) for v in selection.values()):
            raise ValueError(f"Unsupported detection values: {name}")
        raw_cloudtrail = source.get("x_cloudtrail_raw", False)
        if raw_cloudtrail is not False:
            allowed = {"event.source", "event.name", "event.category", "event.outcome",
                       "event.read_only", "resource.type", "resource.path_scope_checked"}
            if (raw_cloudtrail is not True or logsource.get("product") != "aws"
                    or not set(selection).issubset(allowed)
                    or not {"event.source", "event.name", "event.category",
                            "event.outcome", "resource.type"}.issubset(selection)
                    or not isinstance(selection["event.source"], str)
                    or not isinstance(selection["event.name"], str)
                    or selection["event.category"] not in {"Management", "Data"}
                    or selection["event.outcome"] != "success"
                    or not isinstance(selection["resource.type"], str)):
                raise ValueError(f"Unsupported raw CloudTrail rule: {name}")
        resource_path_prefix = source.get("x_cloudtrail_resource_path_prefix")
        if resource_path_prefix is not None and (
                raw_cloudtrail is not True
                or not isinstance(resource_path_prefix, str)
                or not re.fullmatch(r"/?[A-Za-z0-9][A-Za-z0-9/_:.-]{0,127}", resource_path_prefix)):
            raise ValueError(f"Unsupported raw CloudTrail resource prefix: {name}")
        if ((resource_path_prefix is not None and selection.get("resource.path_scope_checked") is not True)
                or ("resource.path_scope_checked" in selection and resource_path_prefix is None)):
            raise ValueError(f"Unsupported raw CloudTrail resource prefix: {name}")
        if product is not None and logsource["product"] != product:
            continue
        falsepositives = source.get("falsepositives", [])
        if (not isinstance(falsepositives, list) or len(falsepositives) > 10
                or any(not isinstance(item, str) or not item or len(item) > 500 for item in falsepositives)):
            raise ValueError(f"Invalid legitimate context: {name}")
        loaded.append(Rule(
            id=str(source["id"]), title=str(source["title"]),
            level=str(source["level"]), description=str(source["description"]),
            technique_id=str(source["x_hacktricks_technique_id"]),
            product=logsource["product"],
            selection=dict(selection),
            falsepositives=tuple(falsepositives),
            raw_cloudtrail=raw_cloudtrail,
            resource_path_prefix=resource_path_prefix,
        ))
    if not loaded:
        raise ValueError("No detection rules found")
    if len({rule.id for rule in loaded}) != len(loaded):
        raise ValueError("Duplicate detection rule ID")
    return tuple(loaded)


def detect_aws_events(
    records: Iterable[Mapping[str, Any]], rules: Sequence[Rule] | None = None,
) -> list[Detection]:
    """Return evidence for matching records; no compromise verdict is implied."""
    def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
        base = (normalize_aws_cloudtrail(record) or normalize_aws_security_control(record)
                or normalize_aws_trail_update(record))
        cloudtrail_selectors = normalize_aws_cloudtrail_selectors(record)
        profile = normalize_aws_other_user_login_profile(record)
        updated_profile = normalize_aws_other_user_login_profile_update(record)
        boundary = normalize_aws_role_boundary_delete(record)
        self_user_boundary = normalize_aws_self_user_boundary_delete(record)
        trust = normalize_aws_wildcard_role_trust(record)
        keyspaces_credential = normalize_keyspaces_other_user_credential(record)
        keyspaces_timestamps = normalize_keyspaces_timestamps(record)
        codebuild_change = normalize_aws_codebuild_change(record)
        codebuild_execution = normalize_codebuild_execution(record)
        codebuild_sandbox_read = normalize_codebuild_sandbox_read(record)
        codepipeline_five = normalize_aws_codepipeline_five(record)
        codepipeline_remaining = normalize_aws_codepipeline_remaining(record)
        codepipeline_reads = normalize_aws_codepipeline_reads(record)
        lightsail_six = normalize_aws_lightsail_six(record)
        lightsail_snapshot_dns = normalize_aws_lightsail_snapshot_dns(record)
        lightsail_db = normalize_aws_lightsail_db(record)
        ecr_lightsail_batch = normalize_aws_ecr_lightsail_batch(record)
        ecr_public_push = normalize_aws_ecr_public_push(record)
        cloudwatch_logs_data = normalize_aws_cloudwatch_logs_data(record)
        cloudwatch_dashboard_insight = normalize_aws_cloudwatch_dashboard_insight(record)
        codecommit_source = normalize_aws_codecommit_source(record)
        appsync_five = normalize_aws_appsync_five(record)
        appsync_read_function = normalize_aws_appsync_read_function(record)
        appsync_signed_role = normalize_aws_appsync_signed_role(record)
        sagemaker_control = normalize_aws_sagemaker_control(record)
        rolesanywhere = normalize_aws_rolesanywhere(record)
        customer_profiles = normalize_aws_customer_profiles(record)
        customer_profiles_read = normalize_aws_customer_profiles_read(record)
        customer_profiles_write = normalize_aws_customer_profiles_write(record)
        customer_profiles_disruption = normalize_aws_customer_profiles_disruption(record)
        customer_profiles_paths = normalize_aws_customer_profiles_paths(record)
        customer_profiles_segments = normalize_aws_customer_profiles_segments(record)
        customer_profiles_export = normalize_aws_customer_profiles_export(record)
        servicecatalog = normalize_aws_servicecatalog(record)
        s3_retention = normalize_aws_s3_retention(record)
        s3_ssec = normalize_aws_s3_ssec(record)
        s3_acl_grants = normalize_aws_s3_acl_grants(record)
        s3_access_point_lock = normalize_aws_s3_access_point_lock(record)
        iot_core_batch = normalize_aws_iot_core_batch(record)
        iot_provision_jobs = normalize_aws_iot_provision_jobs(record)
        lambda_access_mapping = normalize_aws_lambda_access_mapping(record)
        s3_notification = normalize_aws_s3_template_notification(record)
        s3_replication = normalize_aws_s3_replication(record)
        ecr_replication = normalize_aws_ecr_replication(record)
        ecr_registry_policy = normalize_aws_ecr_registry_policy(record)
        efs_access = normalize_aws_efs_access(record)
        efs_deletion = normalize_aws_efs_deletion(record)
        waf_logging = normalize_aws_waf_logging(record)
        waf_deletion = normalize_aws_waf_deletion(record)
        waf_disassociation = normalize_aws_waf_disassociation(record)
        waf_web_acl = normalize_aws_waf_web_acl(record)
        codeartifact_policy = normalize_aws_codeartifact_policy(record)
        codeartifact_routes = normalize_aws_codeartifact_routes(record)
        appconfig_extension = normalize_aws_appconfig_extension(record)
        athena_workgroup = normalize_aws_athena_workgroup(record)
        athena_stored_query = normalize_aws_athena_stored_query(record)
        athena_spark_workgroup = normalize_aws_athena_spark_workgroup(record)
        config_recorder_stop = normalize_aws_config_recorder_stop(record)
        config_auto_remediation = normalize_aws_config_auto_remediation(record)
        eventbridge_archive = normalize_aws_eventbridge_archive(record)
        eventbridge_rule_targets = normalize_aws_eventbridge_rule_targets(record)
        scheduler_controls = normalize_aws_scheduler_controls(record)
        pipes_controls = normalize_aws_pipes_controls(record)
        eventsv2_controls = normalize_aws_eventsv2_controls(record)
        eventsv2_policy = normalize_aws_eventsv2_policy(record)
        ecr_policy = normalize_aws_ecr_policy(record)
        backup_self_grant = normalize_aws_backup_self_grant(record)
        ecr_template = normalize_aws_ecr_template(record)
        secret_self_read = normalize_aws_secret_self_read_grant(record)
        secret_tamper = normalize_aws_secret_tamper(record)
        secret_followup = normalize_aws_secretsmanager_followup(record)
        guardduty_controls = normalize_aws_guardduty_controls(record)
        ecr_retention = normalize_aws_ecr_retention(record)
        dynamodb_controls = normalize_aws_dynamodb_controls(record)
        dynamodb_backup_stream = normalize_aws_dynamodb_backup_stream(record)
        sns_sqs_controls = normalize_aws_sns_sqs_controls(record)
        sqs_followup = normalize_aws_sqs_followup(record)
        sqs_data = normalize_aws_sqs_data(record)
        sqs_redrive = normalize_aws_sqs_redrive(record)
        sns_topic_controls = normalize_aws_sns_topic_controls(record)
        chime_admin = normalize_aws_chime_admin(record)
        chime_attendee_messaging = normalize_aws_chime_attendee_messaging(record)
        chime_capability_flow = normalize_aws_chime_capability_flow(record)
        chime_voice_connector = normalize_aws_chime_voice_connector(record)
        chime_voice_sip = normalize_aws_chime_voice_sip(record)
        chime_media_pipeline = normalize_aws_chime_media_pipeline(record)
        chime_media_insights = normalize_aws_chime_media_insights(record)
        glue_controls = normalize_aws_glue_controls(record)
        cloudfront_controls = normalize_aws_cloudfront_controls(record)
        cognito_controls = normalize_aws_cognito_controls(record)
        cognito_directory = normalize_aws_cognito_directory(record)
        cognito_m2m = normalize_aws_cognito_m2m(record)
        cognito_identity = normalize_aws_cognito_identity(record)
        cognito_federation = normalize_aws_cognito_federation(record)
        cognito_mfa = normalize_aws_cognito_mfa(record)
        cognito_import = normalize_aws_cognito_import(record)
        cognito_pool_client = normalize_aws_cognito_pool_client(record)
        rolesanywhere_controls = normalize_aws_rolesanywhere_controls(record)
        sts_web_token = normalize_aws_sts_web_token(record)
        support_permit = normalize_aws_support_permit(record)
        saml_provider_update = normalize_aws_iam_saml_provider_update(record)
        federation_provider = normalize_aws_iam_federation_provider(record)
        federation_deletion = normalize_aws_iam_federation_deletion(record)
        resource_explorer_view = normalize_aws_resource_explorer_view(record)
        ses_receipt = normalize_aws_ses_receipt(record)
        kinesis_controls = normalize_aws_kinesis_controls(record)
        kinesis_data_write = normalize_aws_kinesis_data_write(record)
        kinesis_data_read = normalize_aws_kinesis_data_read(record)
        kinesis_controls_extended = normalize_aws_kinesis_controls_extended(record)
        kinesis_channel = normalize_aws_kinesis_channel(record)
        kinesis_video_controls = normalize_aws_kinesis_video_controls(record)
        kinesis_video_endpoint = normalize_aws_kinesis_video_endpoint(record)
        ecs_controls = normalize_aws_ecs_controls(record)
        emr_runtime = normalize_aws_emr_serverless_runtime(record)
        cloudwatch_controls = normalize_aws_cloudwatch_controls(record)
        lambda_controls = normalize_aws_lambda_controls(record)
        lambda_qualified_grant = normalize_aws_lambda_qualified_grant(record)
        lambda_config = normalize_aws_lambda_config(record)
        lambda_role_assignment = normalize_aws_lambda_role_assignment(record)
        ec2_controls = normalize_aws_ec2_controls(record)
        vpc_network = normalize_aws_vpc_network(record)
        apigateway_controls = normalize_aws_apigateway_controls(record)
        apigateway_http_keys = normalize_aws_apigateway_http_keys(record)
        apigateway_private_vpce = normalize_aws_apigateway_private_vpce(record)
        cloudformation_reads = normalize_aws_cloudformation_reads(record)
        cloudformation_triggers = normalize_aws_cloudformation_triggers(record)
        cloudformation_stackset = normalize_aws_cloudformation_stackset(record)
        eventbridge_controls = normalize_aws_eventbridge_controls(record)
        eventbridge_connections = normalize_aws_eventbridge_connections(record)
        ssm_controls = normalize_aws_ssm_controls(record)
        ssm_parameter_read = normalize_aws_ssm_parameter_read(record)
        ssm_association_start = normalize_aws_ssm_association_start(record)
        ssm_session_start = normalize_aws_ssm_session_start(record)
        ssm_automation_window = normalize_aws_ssm_automation_window(record)
        stepfunctions_controls = normalize_aws_stepfunctions_controls(record)
        stepfunctions_activity_alias = normalize_aws_stepfunctions_activity_alias(record)
        stepfunctions_redrive = normalize_aws_stepfunctions_redrive(record)
        rds_controls = normalize_aws_rds_controls(record)
        rds_restore_controls = normalize_aws_rds_restore_controls(record)
        rds_parameters = normalize_aws_rds_parameters(record)
        rds_public_replica = normalize_aws_rds_public_replica(record)
        rds_managed_secret_read = normalize_aws_rds_managed_secret_read(record)
        rds_pending_signals = normalize_aws_rds_pending_signals(record)
        service_credentials = normalize_aws_service_credentials(record)
        cloudformation_controls = normalize_aws_cloudformation_controls(record)
        cloudformation_policy = normalize_aws_cloudformation_stack_policy(record)
        kms_standing_access = normalize_aws_kms_standing_access(record)
        kms_key_deletion = normalize_aws_kms_key_deletion(record)
        kms_key_disabled = normalize_aws_kms_key_disabled(record)
        kms_alias_rotation = normalize_aws_kms_alias_rotation(record)
        kms_imported_material = normalize_aws_kms_imported_material(record)
        kms_cancel_deletion = normalize_aws_kms_cancel_deletion(record)
        kms_replication = normalize_aws_kms_replication(record)
        kms_rotation_complete = normalize_aws_kms_on_demand_rotation(record)
        iam_group_role = normalize_aws_iam_group_role(record)
        iam_mfa_controls = normalize_aws_iam_mfa_controls(record)
        iam_policy_removal = normalize_aws_iam_policy_removal(record)
        iam_credential_boundary = normalize_aws_iam_credential_boundary(record)
        iam_identity_deletion = normalize_aws_iam_identity_deletion(record)
        iam_credential_deletion = normalize_aws_iam_credential_deletion(record)
        iam_cert_key_controls = normalize_aws_iam_cert_key_controls(record)
        return (([base] if base is not None else [])
                + ([cloudtrail_selectors] if cloudtrail_selectors is not None else [])
                + ([profile] if profile is not None else [])
                + ([updated_profile] if updated_profile is not None else [])
                + ([boundary] if boundary is not None else [])
                + ([self_user_boundary] if self_user_boundary is not None else [])
                + ([trust] if trust is not None else [])
                + ([keyspaces_credential] if keyspaces_credential is not None else [])
                + ([keyspaces_timestamps] if keyspaces_timestamps is not None else [])
                + ([codebuild_change] if codebuild_change is not None else [])
                + ([codebuild_execution] if codebuild_execution is not None else [])
                + ([codebuild_sandbox_read] if codebuild_sandbox_read is not None else [])
                + ([codepipeline_five] if codepipeline_five is not None else [])
                + ([codepipeline_remaining] if codepipeline_remaining is not None else [])
                + ([codepipeline_reads] if codepipeline_reads is not None else [])
                + ([lightsail_six] if lightsail_six is not None else [])
                + ([lightsail_snapshot_dns] if lightsail_snapshot_dns is not None else [])
                + ([lightsail_db] if lightsail_db is not None else [])
                + ([ecr_lightsail_batch] if ecr_lightsail_batch is not None else [])
                + ([ecr_public_push] if ecr_public_push is not None else [])
                + ([cloudwatch_logs_data] if cloudwatch_logs_data is not None else [])
                + ([cloudwatch_dashboard_insight] if cloudwatch_dashboard_insight is not None else [])
                + ([codecommit_source] if codecommit_source is not None else [])
                + ([appsync_five] if appsync_five is not None else [])
                + ([appsync_read_function] if appsync_read_function is not None else [])
                + ([appsync_signed_role] if appsync_signed_role is not None else [])
                + ([sagemaker_control] if sagemaker_control is not None else [])
                + ([rolesanywhere] if rolesanywhere is not None else [])
                + ([customer_profiles] if customer_profiles is not None else [])
                + ([customer_profiles_read] if customer_profiles_read is not None else [])
                + ([customer_profiles_write] if customer_profiles_write is not None else [])
                + ([customer_profiles_disruption] if customer_profiles_disruption is not None else [])
                + ([customer_profiles_paths] if customer_profiles_paths is not None else [])
                + ([customer_profiles_segments] if customer_profiles_segments is not None else [])
                + ([customer_profiles_export] if customer_profiles_export is not None else [])
                + ([servicecatalog] if servicecatalog is not None else [])
                + ([s3_retention] if s3_retention is not None else [])
                + ([s3_ssec] if s3_ssec is not None else [])
                + ([s3_acl_grants] if s3_acl_grants is not None else [])
                + ([s3_access_point_lock] if s3_access_point_lock is not None else [])
                + ([iot_core_batch] if iot_core_batch is not None else [])
                + ([iot_provision_jobs] if iot_provision_jobs is not None else [])
                + ([lambda_access_mapping] if lambda_access_mapping is not None else [])
                + ([s3_notification] if s3_notification is not None else [])
                + ([s3_replication] if s3_replication is not None else [])
                + ([ecr_replication] if ecr_replication is not None else [])
                + ([ecr_registry_policy] if ecr_registry_policy is not None else [])
                + ([efs_access] if efs_access is not None else [])
                + ([efs_deletion] if efs_deletion is not None else [])
                + ([waf_logging] if waf_logging is not None else [])
                + ([waf_deletion] if waf_deletion is not None else [])
                + ([waf_disassociation] if waf_disassociation is not None else [])
                + ([waf_web_acl] if waf_web_acl is not None else [])
                + ([codeartifact_policy] if codeartifact_policy is not None else [])
                + ([codeartifact_routes] if codeartifact_routes is not None else [])
                + ([appconfig_extension] if appconfig_extension is not None else [])
                + ([athena_workgroup] if athena_workgroup is not None else [])
                + ([athena_stored_query] if athena_stored_query is not None else [])
                + ([athena_spark_workgroup] if athena_spark_workgroup is not None else [])
                + ([config_recorder_stop] if config_recorder_stop is not None else [])
                + ([config_auto_remediation] if config_auto_remediation is not None else [])
                + ([eventbridge_archive] if eventbridge_archive is not None else [])
                + ([eventbridge_rule_targets] if eventbridge_rule_targets is not None else [])
                + ([scheduler_controls] if scheduler_controls is not None else [])
                + ([pipes_controls] if pipes_controls is not None else [])
                + ([eventsv2_controls] if eventsv2_controls is not None else [])
                + ([eventsv2_policy] if eventsv2_policy is not None else [])
                + ([ecr_policy] if ecr_policy is not None else [])
                + ([backup_self_grant] if backup_self_grant is not None else [])
                + ([ecr_template] if ecr_template is not None else [])
                + ([secret_self_read] if secret_self_read is not None else [])
                + ([secret_tamper] if secret_tamper is not None else [])
                + ([secret_followup] if secret_followup is not None else [])
                + ([guardduty_controls] if guardduty_controls is not None else [])
                + ([ecr_retention] if ecr_retention is not None else [])
                + ([dynamodb_controls] if dynamodb_controls is not None else [])
                + ([dynamodb_backup_stream] if dynamodb_backup_stream is not None else [])
                + ([sns_sqs_controls] if sns_sqs_controls is not None else [])
                + ([sqs_followup] if sqs_followup is not None else [])
                + ([sqs_data] if sqs_data is not None else [])
                + ([sqs_redrive] if sqs_redrive is not None else [])
                + ([sns_topic_controls] if sns_topic_controls is not None else [])
                + ([chime_admin] if chime_admin is not None else [])
                + ([chime_attendee_messaging] if chime_attendee_messaging is not None else [])
                + ([chime_capability_flow] if chime_capability_flow is not None else [])
                + ([chime_voice_connector] if chime_voice_connector is not None else [])
                + ([chime_voice_sip] if chime_voice_sip is not None else [])
                + ([chime_media_pipeline] if chime_media_pipeline is not None else [])
                + ([chime_media_insights] if chime_media_insights is not None else [])
                + ([glue_controls] if glue_controls is not None else [])
                + ([cloudfront_controls] if cloudfront_controls is not None else [])
                + ([cognito_controls] if cognito_controls is not None else [])
                + ([cognito_directory] if cognito_directory is not None else [])
                + ([cognito_m2m] if cognito_m2m is not None else [])
                + ([cognito_identity] if cognito_identity is not None else [])
                + ([cognito_federation] if cognito_federation is not None else [])
                + ([cognito_mfa] if cognito_mfa is not None else [])
                + ([cognito_import] if cognito_import is not None else [])
                + ([cognito_pool_client] if cognito_pool_client is not None else [])
                + ([rolesanywhere_controls] if rolesanywhere_controls is not None else [])
                + ([sts_web_token] if sts_web_token is not None else [])
                + ([support_permit] if support_permit is not None else [])
                + ([saml_provider_update] if saml_provider_update is not None else [])
                + ([federation_provider] if federation_provider is not None else [])
                + ([federation_deletion] if federation_deletion is not None else [])
                + ([resource_explorer_view] if resource_explorer_view is not None else [])
                + ([ses_receipt] if ses_receipt is not None else [])
                + ([kinesis_controls] if kinesis_controls is not None else [])
                + ([kinesis_data_write] if kinesis_data_write is not None else [])
                + ([kinesis_data_read] if kinesis_data_read is not None else [])
                + ([kinesis_controls_extended] if kinesis_controls_extended is not None else [])
                + ([kinesis_channel] if kinesis_channel is not None else [])
                + ([kinesis_video_controls] if kinesis_video_controls is not None else [])
                + ([kinesis_video_endpoint] if kinesis_video_endpoint is not None else [])
                + ([ecs_controls] if ecs_controls is not None else [])
                + ([emr_runtime] if emr_runtime is not None else [])
                + ([cloudwatch_controls] if cloudwatch_controls is not None else [])
                + ([lambda_controls] if lambda_controls is not None else [])
                + ([lambda_qualified_grant] if lambda_qualified_grant is not None else [])
                + ([lambda_config] if lambda_config is not None else [])
                + ([lambda_role_assignment] if lambda_role_assignment is not None else [])
                + ([ec2_controls] if ec2_controls is not None else [])
                + ([vpc_network] if vpc_network is not None else [])
                + ([apigateway_controls] if apigateway_controls is not None else [])
                + ([apigateway_http_keys] if apigateway_http_keys is not None else [])
                + ([apigateway_private_vpce] if apigateway_private_vpce is not None else [])
                + ([cloudformation_reads] if cloudformation_reads is not None else [])
                + ([cloudformation_triggers] if cloudformation_triggers is not None else [])
                + ([cloudformation_stackset] if cloudformation_stackset is not None else [])
                + ([eventbridge_controls] if eventbridge_controls is not None else [])
                + ([eventbridge_connections] if eventbridge_connections is not None else [])
                + ([ssm_controls] if ssm_controls is not None else [])
                + ([ssm_parameter_read] if ssm_parameter_read is not None else [])
                + ([ssm_association_start] if ssm_association_start is not None else [])
                + ([ssm_session_start] if ssm_session_start is not None else [])
                + ([ssm_automation_window] if ssm_automation_window is not None else [])
                + ([stepfunctions_controls] if stepfunctions_controls is not None else [])
                + ([stepfunctions_activity_alias] if stepfunctions_activity_alias is not None else [])
                + ([stepfunctions_redrive] if stepfunctions_redrive is not None else [])
                + ([rds_controls] if rds_controls is not None else [])
                + ([rds_restore_controls] if rds_restore_controls is not None else [])
                + ([rds_parameters] if rds_parameters is not None else [])
                + ([rds_public_replica] if rds_public_replica is not None else [])
                + ([rds_managed_secret_read] if rds_managed_secret_read is not None else [])
                + ([rds_pending_signals] if rds_pending_signals is not None else [])
                + ([service_credentials] if service_credentials is not None else [])
                + ([cloudformation_controls] if cloudformation_controls is not None else [])
                + ([cloudformation_policy] if cloudformation_policy is not None else [])
                + ([kms_standing_access] if kms_standing_access is not None else [])
                + ([kms_key_deletion] if kms_key_deletion is not None else [])
                + ([kms_key_disabled] if kms_key_disabled is not None else [])
                + ([kms_alias_rotation] if kms_alias_rotation is not None else [])
                + ([kms_imported_material] if kms_imported_material is not None else [])
                + ([kms_cancel_deletion] if kms_cancel_deletion is not None else [])
                + ([kms_replication] if kms_replication is not None else [])
                + ([kms_rotation_complete] if kms_rotation_complete is not None else [])
                + ([iam_group_role] if iam_group_role is not None else [])
                + ([iam_mfa_controls] if iam_mfa_controls is not None else [])
                + ([iam_policy_removal] if iam_policy_removal is not None else [])
                + ([iam_credential_boundary] if iam_credential_boundary is not None else [])
                + ([iam_identity_deletion] if iam_identity_deletion is not None else [])
                + ([iam_credential_deletion] if iam_credential_deletion is not None else [])
                + ([iam_cert_key_controls] if iam_cert_key_controls is not None else [])
                + (normalize_aws_raw_cloudtrail(record) if raw_enabled else []))

    selected = rules if rules is not None else load_rules(product="aws")
    raw_enabled = any(rule.raw_cloudtrail for rule in selected)
    glue_correlation_records: list[Mapping[str, Any]] = []
    cognito_group_records: list[Mapping[str, Any]] = []
    sts_records: list[Mapping[str, Any]] = []
    ecs_records: list[Mapping[str, Any]] = []
    emr_session_records: list[Mapping[str, Any]] = []
    vpc_network_records: list[Mapping[str, Any]] = []
    sqs_tag_records: list[Mapping[str, Any]] = []
    sqs_fifo_records: list[Mapping[str, Any]] = []
    lambda_privesc_records: list[Mapping[str, Any]] = []
    ssm_command_records: list[Mapping[str, Any]] = []
    ssm_automation_window_records: list[Mapping[str, Any]] = []
    rds_restore_records: list[Mapping[str, Any]] = []
    rds_parameter_records: list[Mapping[str, Any]] = []
    rds_replica_records: list[Mapping[str, Any]] = []
    rds_proxy_secret_records: list[Mapping[str, Any]] = []
    servicecatalog_records: list[Mapping[str, Any]] = []
    athena_stored_records: list[Mapping[str, Any]] = []
    athena_history_records: list[Mapping[str, Any]] = []
    athena_spark_records: list[Mapping[str, Any]] = []
    apigateway_rest_records: list[Mapping[str, Any]] = []
    apigateway_portal_records: list[Mapping[str, Any]] = []
    cloudformation_trigger_records: list[Mapping[str, Any]] = []
    cloudformation_input_records: list[Mapping[str, Any]] = []
    codebuild_gap_records: list[Mapping[str, Any]] = []
    codepipeline_remaining_records: list[Mapping[str, Any]] = []
    codecommit_consumer_records: list[Mapping[str, Any]] = []
    appconfig_hosted_records: list[Mapping[str, Any]] = []
    cloudtrail_log_dest_records: list[Mapping[str, Any]] = []
    cloudtrail_log_object_records: list[Mapping[str, Any]] = []
    s3_ssec_records: list[Mapping[str, Any]] = []
    s3_access_point_read_records: list[Mapping[str, Any]] = []
    iot_external_cert_records: list[Mapping[str, Any]] = []
    lambda_mapping_records: list[Mapping[str, Any]] = []
    ecr_image_records: list[Mapping[str, Any]] = []
    chime_media_pipeline_records: list[Mapping[str, Any]] = []
    chime_media_insights_records: list[Mapping[str, Any]] = []
    def remembering_records() -> Iterable[Mapping[str, Any]]:
        for record in records:
            if (record.get("eventSource") == "chime-sdk-media-pipelines.amazonaws.com"
                    and record.get("eventName") in {"CreateMediaInsightsPipelineConfiguration",
                                                    "UpdateMediaInsightsPipelineConfiguration",
                                                    "CreateMediaInsightsPipeline"}):
                chime_media_insights_records.append(record)
            if (record.get("eventSource") == "chime-sdk-media-pipelines.amazonaws.com"
                    and record.get("eventName") in {"CreateMediaLiveConnectorPipeline", "GetMediaPipeline"}):
                chime_media_pipeline_records.append(record)
            if (record.get("eventSource") == "iot.amazonaws.com"
                    and isinstance(record.get("eventName"), str)
                    and record["eventName"] in {"RegisterCertificateWithoutCA", "AttachPolicy"}):
                iot_external_cert_records.append(record)
            if (record.get("eventSource") == "lambda.amazonaws.com"
                    and isinstance(record.get("eventName"), str)
                    and record["eventName"] in {"CreateEventSourceMapping20150331",
                                                "UpdateEventSourceMapping20150331",
                                                "DeleteEventSourceMapping20150331"}):
                lambda_mapping_records.append(record)
            if (isinstance(record.get("eventSource"), str)
                    and record["eventSource"] in {"ecr.amazonaws.com", "ecr-public.amazonaws.com"}
                    and isinstance(record.get("eventName"), str)
                    and record["eventName"] in {"PutImage", "CompleteLayerUpload"}):
                ecr_image_records.append(record)
            if record.get("eventSource") == "athena.amazonaws.com" and record.get("eventName") in {"StartQueryExecution", "ListQueryExecutions", "GetQueryExecution", "BatchGetQueryExecution", "GetQueryResults", "GetQueryRuntimeStatistics"}:
                athena_history_records.append(record)
            if record.get("eventSource") == "athena.amazonaws.com" and record.get("eventName") in {"CreateWorkGroup", "StartQueryExecution"}:
                athena_stored_records.append(record)
            if record.get("eventSource") == "athena.amazonaws.com" and record.get("eventName") in {"CreateWorkGroup", "CreateNotebook", "UpdateNotebook", "StartSession", "CreatePresignedNotebookUrl", "StartCalculationExecution", "GetSessionEndpoint"}:
                athena_spark_records.append(record)
            if record.get("eventSource") == "apigateway.amazonaws.com" and record.get("eventName") in ("CreateApiKey", "CreateUsagePlanKey", "GetApiKey", "PutMethodResponse", "PutIntegrationResponse", "UpdateGatewayResponse", "UpdateRestApi", "CreateDeployment"):
                apigateway_rest_records.append(record)
            if record.get("eventSource") == "apigateway.amazonaws.com" and record.get("eventName") in {"UpdatePortal", "PublishPortal", "DisablePortal", "DeletePortal"}:
                apigateway_portal_records.append(record)
            if record.get("eventSource") == "cloudformation.amazonaws.com" and record.get("eventName") in {"CreateStack", "CreateChangeSet", "ExecuteChangeSet"}:
                cloudformation_trigger_records.append(record)
            if ((record.get("eventSource") == "cloudformation.amazonaws.com" and record.get("eventName") == "UpdateStack")
                    or (record.get("eventSource") == "ssm.amazonaws.com" and record.get("eventName") == "PutParameter")
                    or (record.get("eventSource") == "s3.amazonaws.com" and record.get("eventName") == "PutObject")):
                cloudformation_input_records.append(record)
            if ((record.get("eventSource") == "codebuild.amazonaws.com" and record.get("eventName") in {"StartBuild", "UpdateProject"})
                    or (record.get("eventSource") == "ssm.amazonaws.com" and record.get("eventName") == "StartSession")
                    or (record.get("eventSource") == "secretsmanager.amazonaws.com" and record.get("eventName") == "GetSecretValue")):
                codebuild_gap_records.append(record)
            if record.get("eventSource") == "servicecatalog.amazonaws.com" and record.get("eventName") in {"CreateProvisioningArtifact", "ProvisionProduct"}:
                servicecatalog_records.append(record)
            if record.get("eventSource") == "glue.amazonaws.com" and record.get("eventName") in {"CreateSession", "RunStatement", "CreateJob", "UpdateJob", "StartJobRun"}:
                glue_correlation_records.append(record)
            if record.get("eventSource") == "cognito-idp.amazonaws.com" and record.get("eventName") in {"CreateGroup", "UpdateGroup", "AdminAddUserToGroup"}:
                cognito_group_records.append(record)
            if record.get("eventSource") == "sts.amazonaws.com" and record.get("eventName") == "AssumeRole":
                sts_records.append(record)
            if record.get("eventSource") == "ecs.amazonaws.com" and record.get("eventName") in {"RegisterTaskDefinition", "CreateService", "UpdateService"}:
                ecs_records.append(record)
            if record.get("eventSource") == "emr-serverless.amazonaws.com" and record.get("eventName") in {"StartSession", "GetSessionEndpoint"}:
                emr_session_records.append(record)
            if record.get("eventSource") == "ec2.amazonaws.com" and record.get("eventName") in {"CreateDhcpOptions", "AssociateDhcpOptions"}:
                vpc_network_records.append(record)
            if ((record.get("eventSource") == "iam.amazonaws.com" and record.get("eventName") == "PutRolePolicy")
                    or (record.get("eventSource") == "sqs.amazonaws.com" and record.get("eventName") == "TagQueue")):
                sqs_tag_records.append(record)
            if record.get("eventSource") == "sqs.amazonaws.com" and record.get("eventName") == "SendMessage":
                sqs_fifo_records.append(record)
            if ((record.get("eventSource") == "codepipeline.amazonaws.com" and record.get("eventName") in {
                    "CreatePipeline", "UpdatePipeline", "StartPipelineExecution", "AcknowledgeJob", "PutJobSuccessResult"})
                    or (record.get("eventSource") == "codebuild.amazonaws.com" and record.get("eventName") == "UpdateProject")
                    or (record.get("eventSource") == "s3.amazonaws.com" and record.get("eventName") == "PutObject")):
                codepipeline_remaining_records.append(record)
            if ((record.get("eventSource") == "codecommit.amazonaws.com" and record.get("eventName") == "GitPush")
                    or (record.get("eventSource") == "codepipeline.amazonaws.com" and record.get("eventName") in {
                        "CreatePipeline", "UpdatePipeline", "StartPipelineExecution"})
                    or (record.get("eventSource") == "codebuild.amazonaws.com" and record.get("eventName") == "StartBuild")):
                codecommit_consumer_records.append(record)
            if (record.get("eventSource") == "appconfig.amazonaws.com" and record.get("eventName") in {
                    "CreateHostedConfigurationVersion", "StartDeployment", "GetHostedConfigurationVersion",
                    "StartConfigurationSession", "GetLatestConfiguration"}):
                appconfig_hosted_records.append(record)
            if ((record.get("eventSource") == "cloudtrail.amazonaws.com"
                 and record.get("eventName") in {"CreateTrail", "UpdateTrail"})
                or (record.get("eventSource") == "s3.amazonaws.com"
                    and record.get("eventName") in {"PutBucketLifecycle", "PutBucketPolicy", "PutBucketEncryption"})
                or (record.get("eventSource") == "kms.amazonaws.com"
                    and record.get("eventName") in {"DisableKey", "ScheduleKeyDeletion"})):
                cloudtrail_log_dest_records.append(record)
            if ((record.get("eventSource") == "cloudtrail.amazonaws.com"
                 and record.get("eventName") in {"CreateTrail", "StartLogging", "StopLogging", "DeleteTrail"})
                or (record.get("eventSource") == "s3.amazonaws.com"
                    and record.get("eventName") in {"CopyObject", "DeleteObject", "DeleteBucket"})
                or (record.get("eventSource") == "kms.amazonaws.com"
                    and record.get("eventName") == "DisableKey")):
                cloudtrail_log_object_records.append(record)
            if record.get("eventSource") == "s3.amazonaws.com" and record.get("eventName") in {"PutObject", "CopyObject"}:
                s3_ssec_records.append(record)
            if record.get("eventSource") == "s3.amazonaws.com" and record.get("eventName") == "GetObject":
                s3_access_point_read_records.append(record)
            if record.get("eventSource") == "lambda.amazonaws.com" and record.get("eventName") in {
                    "CreateFunction20150331", "UpdateFunctionConfiguration20150331v2",
                    "UpdateFunctionCode20150331v2", "AddPermission20150331v2",
                    "CreateEventSourceMapping20150331"}:
                lambda_privesc_records.append(record)
            if record.get("eventSource") == "ssm.amazonaws.com" and record.get("eventName") in {
                    "ListCommands", "ListCommandInvocations", "GetCommandInvocation"}:
                ssm_command_records.append(record)
            if record.get("eventSource") == "ssm.amazonaws.com" and record.get("eventName") in {"UpdateDocument", "UpdateDocumentDefaultVersion", "RegisterTargetWithMaintenanceWindow", "RegisterTaskWithMaintenanceWindow"}:
                ssm_automation_window_records.append(record)
            if record.get("eventSource") == "rds.amazonaws.com" and record.get("eventName") in {"RestoreDBInstanceFromDBSnapshot", "ModifyDBInstance"}:
                rds_restore_records.append(record)
            if record.get("eventSource") == "rds.amazonaws.com" and record.get("eventName") in {"ModifyDBParameterGroup", "ModifyDBInstance", "RebootDBInstance", "DownloadDBLogFilePortion"}:
                rds_parameter_records.append(record)
            if record.get("eventSource") == "rds.amazonaws.com" and record.get("eventName") in {"CreateDBInstanceReadReplica", "ModifyDBInstance", "PromoteReadReplica"}:
                rds_replica_records.append(record)
            if ((record.get("eventSource") == "rds.amazonaws.com" and record.get("eventName") == "CreateDBProxy")
                    or (record.get("eventSource") == "secretsmanager.amazonaws.com" and record.get("eventName") == "GetSecretValue")):
                rds_proxy_secret_records.append(record)
            yield record
    matches = _detect_events(remembering_records(), selected, normalize, "aws")
    correlated = (correlate_aws_glue_cross_actor_statements(glue_correlation_records)
                  + correlate_aws_glue_job_script_runs(glue_correlation_records)
                  + correlate_aws_cognito_role_group_membership(cognito_group_records)
                  + correlate_aws_sts_role_cycle(sts_records)
                  + correlate_aws_ecs_dormant_sidecar(ecs_records))
    correlated += correlate_aws_emr_session_endpoint_cross_actor(emr_session_records)
    correlated += correlate_aws_vpc_custom_dns(vpc_network_records)
    correlated += correlate_aws_sqs_tagged_receive(sqs_tag_records)
    correlated += correlate_aws_sqs_fifo_dedup_collision(sqs_fifo_records)
    correlated += correlate_aws_lambda_privesc(lambda_privesc_records)
    correlated += correlate_aws_ssm_command_output_read(ssm_command_records)
    correlated += correlate_aws_ssm_document_window(ssm_automation_window_records)
    correlated += correlate_aws_rds_public_clone_password_reset(rds_restore_records)
    correlated += correlate_aws_rds_sql_log_capture_path(rds_parameter_records)
    correlated += correlate_aws_rds_public_replica_controls(rds_replica_records)
    correlated += correlate_aws_rds_proxy_auth_secret_read(rds_proxy_secret_records)
    correlated += correlate_aws_servicecatalog(servicecatalog_records)
    correlated += correlate_aws_athena_stored_query(athena_stored_records)
    correlated += correlate_aws_athena_history_cross_actor(athena_history_records)
    correlated += correlate_aws_athena_spark_v3(athena_spark_records)
    correlated += correlate_aws_athena_spark35_endpoint(athena_spark_records)
    correlated += correlate_aws_apigateway_rest(apigateway_rest_records)
    correlated += correlate_aws_apigateway_portal(apigateway_portal_records)
    correlated += correlate_aws_cloudformation_triggers(cloudformation_trigger_records)
    correlated += correlate_aws_cloudformation_inputs(cloudformation_input_records)
    correlated += correlate_aws_codebuild_gaps(codebuild_gap_records)
    correlated += correlate_aws_codepipeline_remaining(codepipeline_remaining_records)
    correlated += correlate_aws_codecommit_consumers(codecommit_consumer_records)
    correlated += correlate_aws_appconfig_hosted(appconfig_hosted_records)
    correlated += correlate_aws_cloudtrail_log_dest(cloudtrail_log_dest_records)
    correlated += correlate_aws_cloudtrail_log_objects(cloudtrail_log_object_records)
    correlated += correlate_aws_s3_ssec(s3_ssec_records)
    correlated += correlate_aws_s3_access_point_lock(s3_access_point_read_records)
    correlated += correlate_aws_iot_external_cert_policy(iot_external_cert_records)
    correlated += correlate_aws_lambda_mapping_repoint(lambda_mapping_records)
    correlated += correlate_aws_ecr_tag_overwrite(ecr_image_records)
    correlated += correlate_aws_ecr_new_layer_push(ecr_image_records)
    correlated += correlate_aws_chime_live_pipeline_read(chime_media_pipeline_records)
    correlated += correlate_aws_chime_media_insights(chime_media_insights_records)
    if correlated:
        matches.extend(_detect_events(correlated, selected, lambda event: event, "aws"))
    return matches


def detect_gcp_events(
    records: Iterable[Mapping[str, Any]], rules: Sequence[Rule] | None = None,
) -> list[Detection]:
    """Detect successful GCP audit events with concrete credential evidence."""
    def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
        base = normalize_gcp_audit(record)
        sink = normalize_gcp_default_sink_disabled(record)
        deleted = normalize_gcp_data_access_log_delete(record)
        exclusion = normalize_gcp_data_access_exclusion_created(record)
        hmac_key = normalize_gcp_hmac_key_created(record)
        destroyed = normalize_gcp_secret_version_destroy(record)
        disabled = normalize_gcp_secret_version_disable(record)
        secret_deleted = normalize_gcp_secret_delete(record)
        return (([base] if base is not None else [])
                + normalize_gcp_project_self_iam_bindings(record)
                + normalize_gcp_cross_project_sa_grants(record)
                + ([sink] if sink is not None else [])
                + ([deleted] if deleted is not None else [])
                + ([exclusion] if exclusion is not None else [])
                + ([hmac_key] if hmac_key is not None else [])
                + ([destroyed] if destroyed is not None else [])
                + ([disabled] if disabled is not None else [])
                + ([secret_deleted] if secret_deleted is not None else []))

    return _detect_events(records, rules if rules is not None else load_rules(product="gcp"), normalize, "gcp")


def detect_kubernetes_events(
    records: Iterable[Mapping[str, Any]], rules: Sequence[Rule] | None = None,
) -> list[Detection]:
    """Detect completed Kubernetes audit events with returned RBAC objects."""
    def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
        base = normalize_kubernetes_audit_candidates(record)
        next_event = normalize_kubernetes_cluster_admin_grant(record)
        pod = normalize_kubernetes_privileged_host_pod(record)
        ephemeral = normalize_kubernetes_privileged_ephemeral_update(record)
        socket = normalize_kubernetes_runtime_socket_pod(record)
        aggregate_view = normalize_aggregate_view_secret_read(record)
        daemonset = normalize_kubernetes_privileged_daemonset(record)
        return (base
                + ([next_event] if next_event is not None else [])
                + ([pod] if pod is not None else [])
                + ([ephemeral] if ephemeral is not None else [])
                + ([socket] if socket is not None else [])
                + ([aggregate_view] if aggregate_view is not None else [])
                + ([daemonset] if daemonset is not None else []))

    return _detect_events(records, rules if rules is not None else load_rules(product="kubernetes"), normalize, "kubernetes")


def detect_azure_events(
    correlated_events: Iterable[Mapping[str, Any]], rules: Sequence[Rule] | None = None,
) -> list[Detection]:
    """Match reviewed Sigma rules against bounded, joined Azure Activity evidence."""
    return _detect_events(correlated_events, rules if rules is not None else load_rules(product="azure"), lambda event: event, "azure")


def _detect_events(
    records: Iterable[Mapping[str, Any]], selected_rules: Sequence[Rule], normalizer: Any, product: str,
) -> list[Detection]:
    # Most packs contain many rules for a small set of event sources. Keep the
    # caller's rule order while considering only rules whose exact source/name
    # selectors can match this event. Rules without those selectors remain in
    # wildcard buckets and retain the same matching semantics.
    any_value = object()
    def exact(actual: Any, expected: Any) -> bool:
        # Python considers True == 1 and False == 0. Sigma scalar selectors
        # must not turn numeric telemetry into a boolean proof field.
        if isinstance(actual, bool) or isinstance(expected, bool):
            return type(actual) is type(expected) and actual == expected
        return actual == expected

    def index_value(value: Any) -> Any:
        try:
            hash(value)
        except TypeError:
            return any_value
        return value

    rules = [rule for rule in selected_rules if rule.product == product]
    buckets: dict[tuple[Any, Any], set[int]] = {}
    for index, rule in enumerate(rules):
        values = []
        for field in ("event.source", "event.name"):
            value = rule.selection.get(field, any_value)
            choices = value if isinstance(value, list) else [value]
            values.append([index_value(item) for item in choices])
        for source in values[0]:
            for name in values[1]:
                buckets.setdefault((source, name), set()).add(index)

    matches: list[Detection] = []
    for record in records:
        normalized = normalizer(record)
        events = [normalized] if isinstance(normalized, Mapping) else normalized or []
        for event in events:
            if not isinstance(event, Mapping):
                continue
            source = event.get("event.source")
            name = event.get("event.name")
            source = index_value(source)
            name = index_value(name)
            candidate_indexes: set[int] = set()
            for key in ((source, name), (source, any_value), (any_value, name), (any_value, any_value)):
                candidate_indexes.update(buckets.get(key, ()))
            for index in sorted(candidate_indexes):
                rule = rules[index]
                if product == "aws" and rule.raw_cloudtrail is not (event.get("__raw_cloudtrail") is True):
                    continue
                if (product == "aws" and rule.resource_path_prefix is not None
                        and not str(event.get("__resource_path", "")).startswith(rule.resource_path_prefix)):
                    continue
                if all(any(exact(event.get(field), choice) for choice in expected)
                       if isinstance(expected, list) else exact(event.get(field), expected)
                       for field, expected in rule.selection.items()):
                    evidence = {field: event[field] for field in rule.selection}
                    correlation = event.get("correlation_evidence")
                    if isinstance(correlation, Mapping):
                        evidence["correlation"] = dict(correlation)
                    matches.append(Detection(
                        rule_id=rule.id, title=rule.title, severity=rule.level,
                        technique_id=rule.technique_id,
                        event_id=event["event.id"], event_time=event["event.time"],
                        account_id=event["account.id"],
                        actor_id=event["actor.id"], target_id=event["target.id"],
                        evidence=evidence,
                        description=rule.description,
                        legitimate_context=rule.falsepositives,
                    ))
    return matches
