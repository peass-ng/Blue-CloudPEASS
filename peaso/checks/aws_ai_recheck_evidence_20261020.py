"""Short observations bound to exact native recheck witnesses, never a verdict."""
import re


def evidence_summary(finding):
    if finding.get('provider') != 'aws' or not isinstance(finding.get('evidence'), dict):
        return None
    cid, e = finding.get('check_id'), finding['evidence']
    if not isinstance(cid, str):
        return None
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
    if cid == 'aws.cb.sns.failure_feedback_role' and e.get('subscriptions_confirmed') == 0 and e.get('subscriptions_pending') == 0:
        return 'The topic has no confirmed or pending subscriptions. There is no delivery endpoint for this feedback-logging control to assess.'
    if cid == 'aws.cb.sqs.dead_letter_queue' and e.get('dead_letter_destination') is True:
        return 'This queue is an explicitly configured dead-letter destination. This control does not require another chained DLQ on a terminal destination.'
    if cid == 'aws.cb.secretsmanager.rotation_rules_present' and isinstance(e.get('owning_service'), str) and re.fullmatch(r'[a-zA-Z0-9._-]+', e['owning_service']):
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
