"""Explicit additive evidence contracts; original signed fixture facts stay exact."""
AWS_FIELDS = {
    'aws.pci.shield.protection_all_internet_resources': {'global_cloudfront_scope'},
    'aws.claude_a.ebs.volume_in_backup_selection': {'backup_selection_match', 'backup_selections_evaluated'},
    'aws_cis_lambda_execution_role_no_admin': {'unconditional_admin'},
    'aws.claude_a.ebs.volume_has_snapshot': {'snapshot_found'},
    'aws.claude_a.ebs.volume_protected_by_backup': {'protected_resource'},
    'aws.claude_a.ebs.volume_in_backup_plan_resources': {'backup_selection_match'},
    'aws.claude_a.ec2.instance_protected_by_backup': {'protected_resource'},
    'aws.claude_a.ec2.instance_ssm_managed': {'ssm_managed'},
    'aws.claude_a.ec2.active_instance_ssm_managed': {'ssm_managed'},
    'aws.claude_a.ec2.launch_template_no_public_ip': {'public_ip_assignment_found'},
    'aws.c2b.elbv2.http_listeners_redirect_https': {'http_listeners_without_redirect'},
    'aws_g6_api_stage_valid_client_certificate': {'evaluation_time', 'certificate_expires_at'},
    'aws_shield_protection_health_checks': {'verified_health_check_ids'},
    'aws_nist_autoscaling_use_multiple_instance_types_in_multiple_az': {'instance_types', 'availability_zones'},
    'aws.nist.ec2_instance_effective_public_reachability': {'public_paths'},
    'aws_fedramp_ec2_effective_public_exposure': {'public_paths'},
    'aws_nist_secretsmanager_secret_automatic_rotation_enabled': {'rotation_enabled'},
    'aws.c2b.backup.vault_policy_not_public': {'public_policy'},
    'aws.c2b.dynamodb.table_protected_resource': {'protected_resource'},
    'aws.c2b.efs.file_system_protected_resource': {'protected_resource'},
    'aws.c2b.dynamodb.table_in_backup_selection_prowler': {'backup_selection_match'},
    'aws.c2b.dynamodb.table_in_backup_selection_or_tag': {'backup_selection_match'},
    'aws.c2b.docdb.snapshot_not_public_prowler': {'public_attribute'},
    'aws.c2b.dynamodb.policy_not_cross_account': {'cross_account_policy'},
    'aws.pci.vpc.peering_dns_resolution': {'peering_side', 'remote_dns_resolution', 'dns_options'},
    'aws_g6_elbv2_only_https_tls_listeners': {'certificate_configured', 'listener_protocols', 'evaluated_listener_count'},
    'aws_shield_automatic_application_layer_response': {'response_status'},
    'aws_autoscaling_userdata_plaintext_aws_key': {'has_aws_key_pair'},
    'aws.pci.iam.policy_attached_to_active_principal': {'usable_attachment'},
    'aws_fedramp_cloudtrail_cloudwatch_integration': {'simulation_allowed'},
    'aws_identity_center_sso_configured': {'enabled_assignment'},
    'aws.cb.rds.instance_snapshot_not_public_prowler': {'public_attribute'},
    'aws.cb.rds.cluster_snapshot_not_public_prowler': {'public_attribute'},
}


def assert_original_evidence_preserved(check_id, actual, original):
    additions = set(actual) - set(original)
    assert additions <= (AWS_FIELDS.get(check_id, set()) | ({'matching_metric_alarm','trail_logging'} if check_id.startswith('aws.gap.cloudwatch.') else set())), (check_id, additions)
    assert {key: value for key, value in actual.items() if key not in additions} == original
