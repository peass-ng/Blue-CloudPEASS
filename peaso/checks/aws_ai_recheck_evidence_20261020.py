"""Short observations bound to exact native recheck witnesses, never a verdict."""
import re


def evidence_summary(finding):
    if finding.get('provider') != 'aws' or not isinstance(finding.get('evidence'), dict):
        return None
    cid, e = finding.get('check_id'), finding['evidence']
    if not isinstance(cid, str):
        return None
    password_requirements = {
        'expiry_at_most_90': 'password expiry within 90 days',
        'lowercase': 'lowercase characters in passwords',
        'minimum_length_14': 'at least 14 characters per password',
        'numbers': 'numbers in passwords', 'reuse_at_least_24': 'preventing reuse of the previous 24 passwords',
        'strong_min_length_14_reuse_24_age_90': '14 characters, all four character classes, 24-password reuse prevention and 90-day expiry',
        'strong_min_length_8': 'eight characters and uppercase, lowercase, numeric and symbol requirements',
        'symbols': 'symbols in passwords', 'uppercase': 'uppercase characters in passwords',
    }
    prefix = 'aws.a.iam.password_policy_'
    if cid.startswith(prefix) and e.get('password_policy') == 'absent':
        requirement = password_requirements.get(cid[len(prefix):])
        if requirement:
            return 'No custom IAM account password policy is configured. This control requires '+requirement+'.'
    absent = {
        'aws.c2b.efs.policy_not_open_to_vpc_clients': ('policy', 'No file-system policy is configured. This control requires a policy that restricts NFS access to mount targets.'),
        'aws.c2b.efs.policy_enforces_ssl': ('policy', 'No file-system policy is configured, so it has no explicit deny for unencrypted NFS requests.'),
        'aws.c2b.efs.automatic_backups_enabled': ('backup_policy_status', 'No automatic backup policy was returned for this file system. This control requires an enabled AWS Backup policy.'),
        'aws.cb.secretsmanager.rotated_as_scheduled': ('rotation_rules', 'No rotation rules are configured for this secret. This control requires a defined rotation schedule.'),
        'aws.cb.ssmincidents.active_with_response_plans': ('replication_set', 'No Incident Manager replication set is configured. This control requires an active set and at least one response plan.'),
        'aws.claude_a.ec2.account_imdsv2_default': ('http_tokens', 'No regional account default requires IMDSv2. This control requires that default, even if individual instances already enforce IMDSv2.'),
        'aws.claude_a.iam.role_used_within_60_days': ('last_used', 'No last-used timestamp was recorded for this role; this control requires use within 60 days. Missing history does not prove the role has never been used or is safe to delete.'),
    }
    # An explicit recorded null is different from a missing evidence field.
    if cid in absent and not (cid == 'aws.cb.secretsmanager.rotated_as_scheduled' and e.get('owning_service')):
        key, observation = absent[cid]
        if key in e and e[key] is None:
            return observation
    if cid == 'aws.cb.sqs.cmk_encryption' and 'kms_master_key_id' in e and e['kms_master_key_id'] in (None, ''):
        return 'A customer-managed KMS key is not configured for this queue. SQS-managed encryption alone does not satisfy this control.'
    if cid == 'aws.a.cloudtrail.home_bucket_mfa_join' and e.get('reason') == 'Pinned source LEFT JOIN found no bucket in complete account inventory':
        return 'The trail destination bucket is absent from this account’s bucket inventory, so its MFA-delete setting could not be verified. This fails the in-scope verification requirement; it does not establish that remote MFA-delete is disabled.'
    if cid == 'aws_cis_lambda_config_recorded' and e.get('reason') == 'no customer-managed recorder':
        return 'No customer-managed AWS Config recorder is configured in this region. This control requires one to record Lambda functions.'
    if cid == 'aws.claude_a.ebs.volume_in_backup_selection' and e.get('backup_selection_match') is False and type(e.get('backup_selections_evaluated')) is int and e['backup_selections_evaluated'] >= 0:
        if e['backup_selections_evaluated'] == 0:
            return 'No AWS Backup resource assignments were recorded in this region. This volume has no matching backup-plan selection.'
        return f"None of the {e['backup_selections_evaluated']} evaluated AWS Backup selections matches this volume by ARN or tag key. This control requires a matching resource assignment."
    if e.get('reason') == 'The shared database API returned a different database engine.' and isinstance(e.get('engine'), str):
        expected = {'docdb': 'DocumentDB', 'neptune': 'Neptune', None: 'RDS'}.get(e.get('expected_engine'))
        if expected:
            return f"The API returned engine {e['engine']}. This {expected} control does not apply to that database engine."
    if cid == 'aws.b.rds.engine_log_exports' and e.get('engine') == 'aurora-postgresql' and isinstance(e.get('exported_categories'), list):
        return ('Aurora PostgreSQL exports the required postgresql log category; the RDS PostgreSQL upgrade category does not apply.'
                if 'postgresql' in e['exported_categories'] else 'Aurora PostgreSQL is not exporting postgresql logs. This control requires that log category.')
    if cid == 'aws.claude_a.ec2.instance_ebs_optimized' and e.get('optimization') == 'enabled_by_instance_type_default' and e.get('ebs_optimized') is True:
        kind = e.get('instance_type')
        if isinstance(kind, str) and re.fullmatch(r'[a-z0-9]+\.[a-z0-9]+', kind):
            return f'EBS optimization is enabled by default for instance type {kind}. A false instance-level flag does not mean optimization is disabled.'
    if cid in {'aws.claude_a.iam.policy_in_use', 'aws.claude_a.iam.custom_policy_in_use',
               'aws.claude_a.iam.custom_policy_attached_to_role', 'aws.pci.iam.policy_attached_to_active_principal'}:
        count = e.get('permissions_boundary_usage_count')
        if type(count) is int and count > 0:
            return (f'This policy is used as a permissions boundary by {count} identities. '
                    + ('It has no permissions-policy attachments, so this attachment-only control does not apply.'
                       if e.get('permissions_policy_attachment_count') == 0 else 'Boundary usage counts as use; the policy is not unused.'))
    if cid == 'aws.cb.sns.failure_feedback_role' and type(e.get('subscriptions_confirmed')) is int and e['subscriptions_confirmed'] == 0 and type(e.get('subscriptions_pending')) is int and e['subscriptions_pending'] == 0:
        return 'The topic has no confirmed or pending subscriptions. There is no delivery endpoint for this feedback-logging control to assess.'
    if cid == 'aws.cb.sqs.dead_letter_queue' and e.get('dead_letter_destination') is True:
        return 'This queue is an explicitly configured dead-letter destination. This control does not require another chained DLQ on a terminal destination.'
    if cid in {'aws.cb.secretsmanager.rotation_rules_present', 'aws.cb.secretsmanager.rotated_as_scheduled'} and isinstance(e.get('owning_service'), str) and re.fullmatch(r'[a-zA-Z0-9._-]+', e['owning_service']):
        return f"AWS service {e['owning_service']} owns this secret. Its rotation is managed through that service, so customer rotation rules do not apply."
    if cid == 'aws.c2b.apigateway.rest_api_policy_not_public' and e.get('source_boundary') == 'covering_explicit_deny_outside_ip_allowlist':
        return 'A covering explicit deny blocks API calls outside the configured IP allowlist. Allowlisted clients can still connect, but unrestricted internet sources cannot.'
    if cid in {'aws.claude_a.iam.prowler_role_confused_deputy_prevented', 'aws.claude_a.iam.prowler_role_service_trust_bound_to_account'} and e.get('service') == 'firehose.amazonaws.com':
        account = e.get('enforced_external_id_account')
        if isinstance(account, str) and re.fullmatch(r'[0-9]{12}', account):
            return f'The Firehose trust requires ExternalId {account}. AWS documents this account-valued condition as Firehose confused-deputy protection.'
    if cid == 'aws.pci.shield.protection_all_internet_resources':
        canonical = e.get('global_cloudfront_scope')
        if isinstance(canonical, str) and re.fullmatch(r'[0-9]{12}/[a-z0-9-]+', canonical):
            missing = e.get('unprotected_resource_arns')
            if isinstance(missing, list):
                return (f'{len(missing)} supported internet-facing resources lack Shield Advanced protection. '
                        + f'Global CloudFront distributions are assessed only in {canonical}.')
            if e.get('reason') == 'No regional supported internet resource; global CloudFront is assessed once.':
                return f'No supported internet-facing resource is recorded in this region. Global CloudFront distributions are assessed once in {canonical}.'
    return None
