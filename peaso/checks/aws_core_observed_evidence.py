"""Specific observations for core AWS callbacks and their signed native successors."""
from math import isfinite

IDS = frozenset({
    'aws.iam.no_full_admin', 'aws.iam.restrict_public_trust', 'aws.iam.console_mfa',
    'aws.s3.public_access_block', 'aws.s3.default_encryption',
    'aws.ec2.restrict_internet_ingress', 'aws.ec2.imdsv2',
    'aws.pci.s3.bucket_backup_plan', 'aws_cis_beanstalk_persistent_logs_s3',
    'aws_cis_ec2_userdata_embedded_secrets', 'aws_cis_elasticbeanstalk_https_listener',
    'aws_cis_elasticbeanstalk_load_balancer_access_logs',
    'aws_cis_lambda_execution_role_no_admin', 'aws_cis_lightsail_ssm_patch_compliance',
    'aws_cis_s3_macie_classification_coverage', 'aws_ec2_instance_time_offset_monitored',
    'aws_g6_ecs_fargate_storage_encryption', 'aws_g6_efs_effective_backup_plan_selection',
    'aws_nist_ec2_instance_not_publicly_accessible', 'aws_nist_efs_file_system_in_backup_plan',
})


def _strings(value):
    return isinstance(value, list) and all(isinstance(x, str) and x.strip() for x in value)


def _number(value):
    return type(value) in (int, float) and isfinite(value)


def evidence_summary(finding):
    if not isinstance(finding, dict) or finding.get('provider') != 'aws':
        return None
    cid, e, status = finding.get('check_id'), finding.get('evidence'), finding.get('status')
    if cid not in IDS or not isinstance(e, dict):
        return None
    if status == 'UNKNOWN' and cid == 'aws.s3.default_encryption':
        reason = e.get('reason')
        if isinstance(reason, str) and reason.startswith('default encryption unavailable;'):
            return 'The bucket’s default-encryption configuration was unavailable; S3 encrypts new objects by default.'
    if status not in ('PASS', 'FAIL'):
        return None
    if cid == 'aws.iam.no_full_admin':
        statements = e.get('full_admin_statements')
        if isinstance(statements, list):
            if not statements:
                return 'No unconditional full-administrator statement was found in the policy.'
            if all(isinstance(s, dict) and s.get('Effect') == 'Allow' and s.get('Action') in ('*', ['*'])
                   and s.get('Resource') in ('*', ['*']) and not s.get('Condition') for s in statements):
                return 'The policy grants all actions on all resources without a condition.'
    if cid == 'aws.iam.restrict_public_trust':
        statements = e.get('unrestricted_trust_statements')
        if isinstance(statements, list) and not statements:
            return 'No unconditional wildcard-principal Allow statement was found in the role trust policy.'
        if isinstance(statements, list) and statements and all(
                isinstance(s, dict) and s.get('Effect') == 'Allow' and not s.get('Condition')
                and (s.get('Principal') == '*' or s.get('Principal') == {'AWS': '*'}) for s in statements):
            return 'The role trust policy declares an unconditional Allow for a wildcard principal.'
    if cid == 'aws.iam.console_mfa':
        login, count = e.get('console_login'), e.get('mfa_device_count')
        if login is False:
            return 'No console login is configured for this user.'
        if login is True and type(count) is int and count >= 0:
            return ('Console login is configured without an MFA device.' if count == 0 else
                    f'Console login is configured with {count} MFA device'+('s.' if count != 1 else '.'))
    if cid == 'aws.s3.public_access_block':
        settings = e.get('effective_settings', e.get('settings'))
        keys = ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')
        if isinstance(settings, dict) and all(type(settings.get(k)) is bool for k in keys):
            missing = [k for k in keys if not settings[k]]
            return ('All four effective S3 Block Public Access protections are enabled.' if not missing else
                    'S3 Block Public Access protections not enabled: '+', '.join(missing)+'.')
    if cid == 'aws.s3.default_encryption':
        algorithms = e.get('algorithms')
        labels = {'AES256': 'SSE-S3', 'aws:kms': 'SSE-KMS', 'aws:kms:dsse': 'DSSE-KMS'}
        if _strings(algorithms) and algorithms and all(v in labels for v in algorithms):
            return 'The bucket’s default encryption uses '+', '.join(labels[v] for v in algorithms)+'.'
    if cid == 'aws.ec2.restrict_internet_ingress' and e.get('internet_ingress') == []:
        return 'No Internet-wide ingress rule was found in this security group.'
    if cid == 'aws.ec2.imdsv2':
        options = e.get('metadata_options')
        if isinstance(options, dict):
            if options.get('HttpEndpoint') == 'disabled':
                return 'The instance metadata endpoint is disabled.'
            if options.get('HttpEndpoint') == 'enabled' and options.get('HttpTokens') in ('required', 'optional'):
                return ('The enabled metadata endpoint requires IMDSv2 tokens.' if options['HttpTokens'] == 'required'
                        else 'The enabled metadata endpoint permits IMDSv1 requests without a token.')
    if cid == 'aws.pci.s3.bucket_backup_plan' and type(e.get('active_selection')) is bool:
        return ('The bucket is included in an active scheduled backup selection.' if e['active_selection'] else
                'No qualifying active scheduled backup selection includes the bucket.')
    if cid == 'aws_cis_beanstalk_persistent_logs_s3':
        bucket, prefix = e.get('log_bucket'), e.get('log_prefix')
        if isinstance(bucket, str) and bucket and isinstance(prefix, str):
            return f'Beanstalk log publication targets S3 bucket {bucket}'+(f' under {prefix}.' if prefix else '.')
    empty_lists = {
        'aws_cis_ec2_userdata_embedded_secrets': ('matched_categories', 'No high-confidence embedded-secret indicator was reported in the inspected user data.'),
        'aws_cis_elasticbeanstalk_https_listener': ('noncompliant_load_balancers', 'No associated Beanstalk load balancer was flagged for missing TLS or plain forwarding.'),
        'aws_cis_elasticbeanstalk_load_balancer_access_logs': ('disabled_access_log_load_balancers', 'No associated Beanstalk load balancer was found with access logging disabled.'),
        'aws_g6_ecs_fargate_storage_encryption': ('unencrypted_volumes', 'No unencrypted managed EBS or EFS volume was found for the assessed ECS service.'),
        'aws_nist_ec2_instance_not_publicly_accessible': ('reachable_public_paths', 'No permitted public network path was found in the recorded EC2 reachability projection.'),
    }
    if cid in empty_lists:
        key, sentence = empty_lists[cid]
        if e.get(key) == []:
            return sentence
    if cid == 'aws_cis_lambda_execution_role_no_admin' and type(e.get('unconditional_admin')) is bool:
        return ('The execution-role analysis reports unconditional administrator access.' if e['unconditional_admin'] else
                'The execution-role analysis reports no unconditional administrator access.')
    if cid == 'aws_cis_lightsail_ssm_patch_compliance':
        keys = ('MissingCount', 'FailedCount', 'InstalledRejectedCount')
        if all(type(e.get(k)) is int and e[k] >= 0 for k in keys):
            if all(e[k] == 0 for k in keys):
                return 'SSM reports no missing, failed or rejected patches for the matched Lightsail instance.'
            return f'SSM reports {e[keys[0]]} missing, {e[keys[1]]} failed and {e[keys[2]]} rejected patches.'
    if cid == 'aws_cis_s3_macie_classification_coverage':
        if e.get('coverage') == 'automated_discovery':
            return 'The bucket is included in Macie’s automated-discovery configuration.'
        if e.get('coverage') == 'classification_job':
            return 'A qualifying Macie classification-job configuration includes the bucket.'
    if cid == 'aws_ec2_instance_time_offset_monitored':
        offset, age = e.get('offset_milliseconds'), e.get('sample_age_seconds')
        if _number(offset) and _number(age) and age >= 0:
            return f'The reported time offset is {offset:g} ms; the sample is {age:g} seconds old.'
    if cid in ('aws_g6_efs_effective_backup_plan_selection', 'aws_nist_efs_file_system_in_backup_plan'):
        plans = e.get('matching_plan_arns')
        if _strings(plans) and plans and all(p.startswith('arn:') for p in plans):
            return f'The filesystem matches {len(plans)} configured backup plan'+('s.' if len(plans) != 1 else '.')
    return None
