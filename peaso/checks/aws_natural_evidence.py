"""Plain sentences for recorded AWS settings, rather than field/value dumps.

These translations use collected values, never the finding's verdict. Specific
identity and policy cases precede the shared grammar for typed observations.
"""
import re


def _flag(value):
    if type(value) is bool:
        return value
    if type(value) is int and value in (0, 1):
        return bool(value)
    if value in ('true', 'false'):
        return value == 'true'
    return None


def complete_explanation(finding):
    cid, e = finding['check_id'], finding['evidence']
    if cid == 'aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis':
        enis = e.get('customer_enis')
        if e.get('world_ingress_rule_found') is True and isinstance(enis, list) and enis and all(
                isinstance(v, str) and re.fullmatch(r'eni-[a-zA-Z0-9]+', v) for v in enis):
            observed = f"This group allows ingress from everyone and is attached to {len(enis)} customer-managed network interface{'s' if len(enis) != 1 else ''}."
            for rule in e.get('internet_ingress', []):
                if not isinstance(rule, dict) or rule.get('source') not in ('0.0.0.0/0', '::/0'):
                    continue
                protocol, low, high = str(rule.get('protocol')), rule.get('from_port'), rule.get('to_port')
                traffic = None
                if protocol in ('tcp', '6', 'udp', '17') and type(low) is int and type(high) is int and 0 <= low <= high <= 65535:
                    traffic = ('TCP' if protocol in ('tcp', '6') else 'UDP') + ' ' + (str(low) if low == high else f'{low}–{high}')
                elif protocol == '-1':
                    traffic = 'all protocols and ports'
                elif protocol in ('icmp', '1', 'icmpv6', '58'):
                    traffic = 'ICMP traffic'
                if traffic:
                    observed = f'An ingress rule allows {traffic} from {rule["source"]}; the group is attached to customer-managed interface {enis[0]}.'
                    break
            return observed + ' Any internet-open port fails this control; all ports do not need to be open.'
    if cid == 'aws.a.iam.root_hardware_mfa':
        mfa, virtual = _flag(e.get('account_mfa_enabled')), _flag(e.get('virtual_root_mfa_present'))
        if mfa is False:
            return 'The root account does not have MFA enabled. Register a hardware MFA device to add a second check when signing in.'
        if mfa is True and virtual is False:
            return 'Root MFA is enabled and no virtual device is listed, which meets this check’s hardware-MFA rule. The device itself was not tested.'
        if virtual is True:
            return 'A virtual MFA device is registered for root. This check requires a hardware device instead.'
    if cid == 'aws.claude_a.iam.prowler_root_hardware_mfa' and type(e.get('virtual_root_mfa')) is bool:
        return ('A virtual MFA device is registered for root. This check requires a hardware device instead.' if e['virtual_root_mfa'] else
                'No virtual MFA device is registered for root. This check does not show whether a hardware device is present.')
    if cid in ('aws.iam.no_root_keys', 'aws.a.iam.root_summary_no_keys'):
        count = e.get('configured') if cid == 'aws.iam.no_root_keys' else e.get('account_access_keys_present')
        if type(count) is int and count >= 0:
            if count == 0:
                return 'No access keys are configured for the root account, so there are no root keys to remove.'
            return (f'The root account has {count} access '+('key.' if count == 1 else 'keys.')
                    + ' Remove unused root keys because they provide powerful account access without a console MFA prompt.')
        return 'The root access-key count was not collected, so this check cannot confirm whether root keys exist.'
    if cid in ('aws.claude_a.iam.root_console_has_mfa', 'aws.a.iam.root_console_summary_mfa'):
        password = _flag(e.get('password_present' if 'password_present' in e else 'root_console_enabled'))
        mfa = _flag(e.get('mfa_enabled' if 'mfa_enabled' in e else 'root_mfa_enabled'))
        if password is False:
            return 'The root account has no console password, so this password sign-in check does not require an MFA device.'
        if password is True and mfa is not None:
            if mfa:
                return 'The root account has a console password and MFA enabled, adding a second sign-in check beyond the password.'
            return 'The root account has a console password but MFA is not enabled. Enable MFA to add protection if the password is stolen.'
        return 'The root password or MFA setting was not collected, so protection for root password sign-in could not be checked.'
    if cid in ('aws.iam.root_mfa', 'aws.a.iam.root_summary_mfa', 'aws.a.iam.report_all_mfa',
               'aws.a.iam.report_console_mfa', 'aws.iam.console_mfa', 'aws.claude_a.iam.admin_user_has_mfa'):
        root = cid in ('aws.iam.root_mfa', 'aws.a.iam.root_summary_mfa')
        flags = e.get('credential_flags', e)
        if not isinstance(flags, dict):
            return None
        password = _flag(flags.get('password_enabled', e.get('console_login')))
        if password is False and cid != 'aws.a.iam.report_all_mfa':
            return 'This identity has no console password, so this password sign-in check does not require an MFA device.'
        count = e.get('mfa_device_count', e.get('mfa_devices'))
        mfa = _flag(flags.get('mfa_active', e.get('account_mfa_enabled')))
        if type(count) is int and count >= 0:
            mfa = count > 0
        if mfa is None:
            return None
        who = 'The root account' if root else 'This user'
        return (f'{who} has an MFA device registered. It adds a second sign-in check; the report does not show whether every sign-in requires it.' if mfa else
                f'{who} has no MFA device registered. Enable MFA to add protection if the password is stolen.')
    return None


_ACRONYMS = {'mfa':'MFA', 'kms':'KMS', 'sse':'encryption', 'acl':'access-control list',
             'vpc':'VPC', 'ip':'IP', 'tls':'TLS', 'ssl':'TLS', 'iam':'IAM', 'arn':'ARN',
             'arns':'ARNs', 'http':'HTTP', 'https':'HTTPS', 'api':'API', 'uid':'user ID', 'pids':'processes',
             'ec2':'EC2', 'eks':'EKS', 'ecs':'ECS', 'ecr':'ECR', 'ssm':'SSM', 'sns':'SNS', 'sqs':'SQS', 'dns':'DNS', 'waf':'WAF', 'ipv6':'IPv6', 'ipv4':'IPv4', 'az':'AZ', 'cmk':'customer-managed key', 'cidrs':'network ranges', 'posix':'POSIX', 'cloudwatch':'CloudWatch', 'cloudfront':'CloudFront', 'dynamodb':'DynamoDB', 'dax':'DAX', 'cognito':'Cognito', 'sagemaker':'SageMaker', 'bedrock':'Bedrock', 'redshift':'Redshift', 'aurora':'Aurora'}


def _words(value):
    words = value.replace('_', ' ').split()
    return ' '.join(_ACRONYMS.get(word.lower(), word.lower()) for word in words)


def _display(value):
    value = value.strip('“”"').replace('”, “', ', ')
    if re.fullmatch(r'RSA_\d+', value):return value.removeprefix('RSA_')+'-bit RSA'
    translations = {'not_reported': 'not reported', 'not_set': 'not set', 'NOT_APPLICABLE': 'not applicable',
        'PendingDeletion':'scheduled for deletion', 'PendingImport':'awaiting imported key material',
        'COMPLETE':'complete',
        'IN_SYNC': 'in sync', 'PENDING_VALIDATION': 'awaiting validation', 'SINGLE_AZ_1': 'one Availability Zone',
        'SINGLE_AZ_2': 'one Availability Zone', 'MULTI_AZ_1': 'multiple Availability Zones',
        'MULTI_AZ_2': 'multiple Availability Zones', 'SCAN_ON_PUSH': 'when images are pushed',
        'CONTINUOUS_SCAN': 'continuously', 'ENHANCED': 'enhanced scanning', 'BASIC': 'basic scanning',
        'DynamoDB-owned default SSE': 'DynamoDB default encryption', 'sni-only': 'Server Name Indication',
        'redirect-to-https': 'redirecting HTTP requests to HTTPS', 'https-only': 'HTTPS only',
        'allow-all': 'both HTTP and HTTPS', 'ON': 'required', 'OFF': 'disabled', 'OPTIONAL': 'optional',
        'IMMUTABLE': 'protected from changes', 'MUTABLE': 'allowed to change',
        'IMMUTABLE_WITH_EXCLUSION': 'protected from changes except for the configured exclusions',
        'SecureString': 'an encrypted string', 'DISABLED': 'disabled', 'ENABLED': 'enabled',
        'ACTIVE': 'active', 'ACTIVATED': 'active', 'ENFORCED': 'enforced', 'COMPLIANT': 'compliant',
        'NON_COMPLIANT': 'noncompliant', 'PRIVATE': 'private', 'PUBLIC': 'public', 'REGIONAL': 'regional',
        'AWS_KMS': 'AWS KMS', 'SSE_KMS': 'encryption with AWS KMS', 'SSE_S3': 'S3-managed encryption',
        'SSE-KMS': 'encryption with AWS KMS', 'SSE-S3': 'S3-managed encryption',
        'PassThrough': 'pass-through tracing', 'LINUX': 'Linux', 'WINDOWS': 'Windows',
        'AMAZON_ISSUED': 'issued by Amazon', 'PUBLIC_READ': 'readable publicly',
        'BASIC_AUTH': 'a username and password', 'API_KEY': 'an API key',
        'NOT_SIGNING': 'not signing DNS responses', 'ML_DSA_65': 'ML-DSA-65',
        'ML_DSA_44': 'ML-DSA-44', 'ML_DSA_87': 'ML-DSA-87',
        'SYMMETRIC_DEFAULT': 'the default symmetric-key type', 'EXTERNAL': 'imported key material',
        'PER_BROKER':'per-broker monitoring', 'SERVICE_PROVIDED_EIPS':'service-provided public IP addresses', 'ACTIVE_STANDBY_MULTI_AZ':'active and standby brokers across Availability Zones', 'CLUSTER_MULTI_AZ':'a broker cluster across Availability Zones', 'CUSTOMER_MANAGED_KMS_KEY':'a customer-managed KMS key', 'CONFIG_MAP': 'the legacy ConfigMap mechanism', 'API_AND_CONFIG_MAP': 'both access entries and the legacy ConfigMap mechanism', 'API': 'access entries', 'AMAZON_COGNITO_USER_POOLS': 'Cognito user-pool sign-in', 'ISSUED':'issued', 'FAILED':'failed', 'AUDIT':'audit-only monitoring', 'DRIFTED':'changed since the recorded template', 'SIGNING':'signing DNS responses', 'CURRENT_MANAGED_KMS_KEY':'the current managed KMS key', 'RootCredentialsManagement':'central root-credential management', 'public_ipv4':'a public IPv4 address', 'network_interface':'a network interface', 'classic_vpc':'a Classic load balancer in a VPC', 'all_supported':'all supported resources', 'documented_absent':'documented as absent', 'not_enabled': 'disabled', 'not_configured': 'not configured', 'lambda_code': 'Lambda code',
        'AUDIT_LOGS': 'audit logs', 'INDEX_SLOW_LOGS': 'slow indexing logs', 'SEARCH_SLOW_LOGS': 'slow search logs'}
    if value.lower() in ('enabled', 'disabled', 'active', 'inactive', 'absent', 'optional', 'required'):
        return value.lower()
    if ', ' in value:
        return ', '.join(translations.get(part, part) for part in value.split(', '))
    return translations.get(value, value)


# Ambiguous generic field names need the exact check's actual setting.
_SUBJECTS = {
    'aws.a.guardduty.region_enabled': 'GuardDuty',
    'aws.cb.macie.enabled_where_buckets': 'Macie',
    'aws.c2b.acmpca.root_ca_disabled': 'The root certificate authority',
    'aws.cb.opensearch.encryption_at_rest': 'OpenSearch storage encryption',
    'aws.cb.opensearch.fine_grained_access_control': 'OpenSearch fine-grained access control',
    'aws.cb.opensearch.node_to_node_encryption': 'Encryption between OpenSearch nodes',
    'aws.cb.opensearch.node_to_node_encryption_region_skip': 'Encryption between OpenSearch nodes',
    'aws.claude_a.guardduty.prowler_ec2_malware_protection': 'GuardDuty EC2 malware scanning',
    'aws.claude_a.guardduty.prowler_eks_audit_logs': 'GuardDuty EKS audit-log monitoring',
    'aws.claude_a.guardduty.prowler_eks_runtime_monitoring': 'GuardDuty EKS runtime monitoring',
    'aws.claude_a.guardduty.prowler_lambda_protection': 'GuardDuty Lambda monitoring',
    'aws.claude_a.guardduty.prowler_rds_protection': 'GuardDuty RDS monitoring',
    'aws.b.eks.disable_public_endpoint': 'Public access to the Kubernetes API',
    'aws.c2b.autoscaling.lc_no_public_ip': 'Automatic public IP assignment',
    'aws.c2b.backup.recovery_point_encrypted': 'Recovery-point encryption',
    'aws.c2b.dax.encryption_at_rest': 'DAX storage encryption',
    'aws.c2b.dax.encryption_in_transit': 'DAX connection encryption',
    'aws.claude_a.s3.event_notifications': 'S3 event notifications',
    'aws.cb.ssmincidents.active_with_response_plans': 'Incident Manager',
    'aws.cb.trustedadvisor.check_ok': 'The Trusted Advisor check',
    'aws.cb.rolesanywhere.trust_anchor_pqc': 'The certificate trust anchor',
    'aws.claude_a.ebs.volume_in_use': 'The EBS volume',
    'aws.claude_a.ec2.ami_block_public_access': 'Public AMI sharing',
    'aws.claude_a.ec2.enclave_host_running': 'The enclave’s host instance',
    'aws.claude_a.ec2.instance_imdsv2_applied': 'The metadata configuration',
    'aws.claude_a.ec2.snapshot_block_public_access': 'Public snapshot sharing',
    'aws.claude_a.guardduty.prowler_s3_protection': 'GuardDuty S3 monitoring',
    'aws.claude_a.kms.customer_key_enabled_or_pending_deletion': 'The KMS key',
    'aws.claude_a.vpc.peering_same_account_active': 'The VPC peering connection',
    'aws_cis_lightsail_bucket_access_logging': 'Bucket access logging',
    'aws.cb.ssm.resource_compliance_summary_compliant': 'The reported compliance result',
}


def _subject(label, cid):
    if label in ('Enabled', 'Status', 'Configured value', 'State', 'Value'):
        return _SUBJECTS.get(cid, 'The setting checked here')
    text = _words(label)
    return text[0].upper() + text[1:]


def _singular(noun):
    if noun.endswith('indexes'): return noun[:-7] + 'index'
    if noun.endswith('classes'): return noun[:-7] + 'class'
    if noun.startswith('trust statements that '): return noun.replace('trust statements that ', 'trust statement that ', 1)
    if noun.endswith('policies'): return noun[:-8] + 'policy'
    if noun.endswith('entries'): return noun[:-7] + 'entry'
    if noun.endswith('ies'): return noun[:-3] + 'y'
    if noun.endswith('statuses'): return noun[:-2]
    if noun.endswith('addresses'): return noun[:-2]
    if noun.endswith('s') and not noun.endswith(('ss', 'access')): return noun[:-1]
    return noun


def _listed(noun, count):
    if count == 0:
        return f'No {noun} were found in the collected evidence.'
    if count == 1:
        return f'One {_singular(noun)} was found.'
    return f'The collected evidence contains {count} {noun}.'


def _sentence(label, raw, cid):
    value = _display(raw.rstrip('.'))
    subject = _subject(label, cid)
    lower = _words(label)
    if label == 'Comparison':
        return None  # A SQL comparison operator is not a configuration fact.
    if label == 'Question':
        return None  # The review purpose already asks the owner to verify recipients.
    if label in ('Managed actions', 'Stream logs') and value in ('true', 'false'):
        return ('Managed platform updates' if label == 'Managed actions' else 'Streaming application logs')+' are '+('enabled.' if value == 'true' else 'disabled.')
    if label == 'KMS key manager' and value in ('AWS', 'CUSTOMER'):
        return 'AWS manages the KMS key.' if value == 'AWS' else 'Your account manages the KMS key.'
    if label == 'SSM connection status' and value in ('Online', 'ConnectionLost'):
        return 'SSM reports that the instance is connected.' if value == 'Online' else 'SSM reports a lost connection to the instance.'
    if label in ('Days remaining', 'Days to expiry', 'Expiration days') and re.fullmatch(r'-?\d+', value) and int(value) <= 0:
        subject = 'The API key' if label == 'Days remaining' else 'The domain registration' if label == 'Days to expiry' else 'The certificate'
        return subject+(' expires today.' if int(value) == 0 else f' expired {abs(int(value))} days ago.')
    templates = {
        'Days since': 'The secret was last rotated {value} days ago.',
        'Days since change': 'The secret was last changed {value} days ago.',
        'Days since last build': 'The last build ran {value} days ago.',
        'Days since latest build': 'The latest build ran {value} days ago.',
        'Days since launch': 'The instance was launched {value} days ago.',
        'Days stopped': 'The instance has been stopped for {value} days.',
        'Days since reported access': 'The last reported access was {value} days ago.',
        'Days since rotation': 'The access key was last rotated {value} days ago.',
        'Days since use': 'The credential was last used {value} days ago.',
        'Days remaining': 'The API key expires in {value} days.',
        'Days to expiry': 'The domain registration expires in {value} days.',
        'Expiration days': 'The certificate expires in {value} days.',
        'Threshold days': 'This check requires at least {value} days before expiry.',
        'Automatically after days': 'Automatic rotation is scheduled every {value} days.',
        'Rotation period days': 'Key rotation is scheduled every {value} days.',
        'Max age days': 'Findings must be no older than {value} days.',
        'Minimum days': 'This check requires at least {value} days.',
        'Required frequency hours': 'This check requires a run at least every {value} hours.',
        'Window days': 'The check covers the last {value} days.',
        'Window start': 'The period assessed starts on {value}.',
        'Certificate expires at': 'The certificate expires on {value}.',
        'Certificate expiration timestamp': 'The certificate expires on {value}.',
        'Expires': 'The credential expires on {value}.',
        'Expiration date': 'The credential expires on {value}.',
        'Valid till': 'The certificate expires on {value}.',
        'Last scanned at': 'The most recent scan was on {value}.',
        'Launch time': 'The instance was launched on {value}.',
        'Stopped since': 'The instance has been stopped since {value}.',
        'Evaluated at': 'The assessment was made on {value}.',
        'Evaluation time': 'The assessment was made on {value}.',
        'Last used': 'The credential was last used on {value}.',
        'Shared with': 'The resource is shared with account {value}.',
        'Accepter account': 'The connection recipient is account {value}.',
        'Requester account': 'The connection requester is account {value}.',
        'Runtime': 'The function uses runtime {value}.',
        'Approved': 'The approved runtime is {value}.',
        'Key origin': 'The key material comes from {value}.',
        'Algorithm': 'The configured encryption algorithm is {value}.',
        'Serve signature': 'The hosted zone is {value}.',
        'User': 'This credential report entry belongs to {value}.',
        'Accepted': 'Approved deployment types include {value}.',
        'Used by': 'The resource is used by {value}.',
    }
    if label in templates and value not in ('none', 'empty', 'not recorded', 'not reported'):
        return templates[label].format(value=value)
    if value in ('not recorded', 'not reported', 'null', 'None'):
        return f'{subject} was not recorded.'
    if value in ('yes', 'no', 'enabled', 'disabled'):
        enabled = value in ('yes', 'enabled')
        interpretations = {
            'Archived': ('The finding is archived.', 'The finding is not archived.'),
            'Readonly': ('The attached policy is classified as read-only.', 'The attached policy is not classified as read-only.'),
            'Full access': ('The policy matches the checked full-access pattern.', 'The policy does not match the checked full-access pattern.'),
            'Admin access': ('The policy matches the administrator-access pattern.', 'The policy does not match the administrator-access pattern.'),
            'Administrator access': ('An AdministratorAccess policy attachment was found.', 'No AdministratorAccess policy attachment was found.'),
            'Subscribe on all': ('The policy allows Marketplace subscriptions without a resource restriction.', 'No unrestricted Marketplace subscription grant was found.'),
            'Cross account': ('The stored policy contains a cross-account grant.', 'No cross-account grant was found in the stored policy.'),
            'Cross account policy': ('The bus policy contains a cross-account grant.', 'No cross-account grant was found in the bus policy.'),
            'Public write': ('The stored policy contains a public write grant.', 'No public write grant was found in the stored policy.'),
            'Confused deputy exposed': ('The trust policy lacks the checked confused-deputy safeguards.', 'The trust policy meets the checked confused-deputy safeguards.'),
            'Public attribute value detected': ('A public-sharing value was found in the snapshot attributes.', 'No public-sharing value was found in the snapshot attributes.'),
            'Public restore attribute': ('The snapshot permits public restore access.', 'The snapshot does not declare public restore access.'),
            'Public access-control list': ('The stored ACL includes a public grant.', 'The stored ACL has no public grant.'),
            'Specific public range match': ('An ingress rule matches the checked public network range.', 'No ingress rule matches the checked public network range.'),
            'Opt out content match': ('The policy contains the checked AI-services opt-out setting.', 'The checked AI-services opt-out setting was not found in the policy.'),
            'Direct region deny match': ('A direct deny for the checked regions was found.', 'No direct deny for the checked regions was found.'),
            'Selection or tag key match': ('The resource ARN or an exact tag key and value matches an AWS Backup selection.', 'Neither the resource ARN nor an exact tag key and value matches an AWS Backup selection.'),
            'Disable rollback': ('Automatic stack rollback is disabled.', 'Automatic stack rollback is enabled.'),
            'Disable api termination': ('Instance termination protection is enabled.', 'Instance termination protection is disabled.'),
            'Attached': ('The policy is attached to an identity.', 'The policy is not attached to an identity.'),
            'Attached to active identity': ('The policy is attached to an active identity.', 'No attachment to an active identity was found.'),
            'Attached by group name': ('The named security group is attached to an instance.', 'No instance attachment was found for the named security group.'),
            'Bootstrap cluster creator admin': ('The cluster creator receives administrator privileges at bootstrap.', 'Administrator privileges for the cluster creator are disabled at bootstrap.'),
            'Vault locked': ('The backup vault is locked.', 'The backup vault is not locked.'),
            'Offline copy evidence': ('Evidence of an offline backup copy was recorded.', 'No evidence of an offline backup copy was recorded.'),
        }
        if label in interpretations:return interpretations[label][0 if enabled else 1]
        presence = {'Protected resource match': 'A matching AWS Backup protected-resource record',
            'Protected resource': 'An AWS Backup protected-resource record', 'Snapshot found': 'A snapshot for this volume',
            'Backup selection match': 'An AWS Backup selection matching this resource',
            'Destination resolved': 'The referenced log destination', 'Ssm managed': 'An SSM managed-instance record'}
        if label in presence:
            return presence[label]+(' was found.' if enabled else ' was not found in the collected evidence.')
        if lower.endswith(' found'):
            noun=lower[:-6].removeprefix('matching ')
            noun={'world all traffic rule':'rule allowing all traffic from internet sources', 'world ingress rule':'ingress rule allowing internet sources', 'eni attachment':'network-interface attachment'}.get(noun,noun)
            return ('A matching '+noun+' was found.' if enabled else 'No matching '+noun+' was found in the collected evidence.')
        if lower.endswith((' attached', ' attachment found')):
            return subject+(' is attached.' if enabled else ' is not attached.')
        if label in ('Approved classification', 'Approved priority', 'Approved TLS policy'):
            return subject+(' matches the approved criteria.' if enabled else ' does not match the approved criteria.')
        if label in ('Storage encrypted', 'Export encryption disabled', 'Logs encryption disabled'):
            if 'disabled' in lower:enabled = not enabled
            return ('The exported data' if label == 'Export encryption disabled' else 'The logs' if label == 'Logs encryption disabled' else 'Storage')+(' is encrypted.' if enabled else ' is not encrypted.')
        if label == 'Organization member':
            return 'The account '+('belongs to an AWS organization.' if enabled else 'does not belong to an AWS organization.')
        if label == 'Kms key declared':
            return 'A KMS encryption key '+('is configured for the trail.' if enabled else 'is not configured for the trail.')
        if label == 'Source requires explicit retention':
            return None
        if label in ('Public grant detected', 'Public policy'):
            return 'The policy '+('includes a public access grant.' if enabled else 'contains no public access grant.')
        if label == 'Is default':
            return 'The cluster '+('uses the default VPC.' if enabled else 'does not use the default VPC.')
        if label == 'Expired':
            return 'The credential '+('has expired.' if enabled else 'has not expired.')
        if label == 'Encrypted':
            return 'Storage encryption is '+('enabled.' if enabled else 'disabled.')
        if 'password' in lower and ('requirement' in lower or 'require ' in lower):
            kind = next((name for name in ('lowercase', 'uppercase', 'numbers', 'symbols') if name in lower), None)
            if kind is None:kind = 'numbers' if 'numeric' in lower else 'symbols' if 'symbol' in lower else None
            if kind:
                return 'Passwords '+('must include ' if enabled else 'are not required to include ')+kind+(' letters.' if kind in ('lowercase', 'uppercase') else '.')
        if lower.endswith(' present'):
            return f'{subject[:-8]} '+('is configured.' if enabled else 'is not configured.')
        if lower.endswith(' enabled'):
            subject = subject[:-8]
        plural = subject.lower().endswith(('upgrades', 'exports', 'logs', 'notifications', 'rules', 'actions', 'tags', 'requests'))
        return subject + (' are ' if plural else ' is ') + ('enabled.' if enabled else 'disabled.')
    if value in ('none', 'empty', 'no recorded entries'):
        if label == 'Configured value' and cid == 'aws.claude_a.s3.event_notifications':
            return 'The bucket has no event notifications configured.'
        empty_phrases = {'Not enabled for': 'Inspector scanning is enabled for all resource types assessed here.',
            'Upstream allowed': 'No internal packages allow upstream versions.',
            'Shared with': 'No recipient accounts are listed for sharing.',
            'Overdue': 'No overdue findings were found.', 'Known exploited': 'No findings match known exploited vulnerabilities.',
            'Metrics disabled': 'Metrics are enabled for every rule checked.',
            'Coverage': 'No classification coverage was recorded.',
            'Configured value': 'The required configuration was not recorded.'}
        if label in empty_phrases:return empty_phrases[label]
        if not lower.startswith('containers ') and lower.endswith(('reference', 'configuration', 'config', 'policy', 'id', 'arn', 'key', 'file', 'name')):
            return f'No {lower} was recorded.'
        return f'No {lower} were recorded.'
    count = re.fullmatch(r'(\d+)(?: recorded entries)?', value) if not raw.startswith('“') else None
    if count:
        n = int(count[1])
        if label in ('Retention days', 'Maximum password age', 'Maximum password age in days', 'Backup retention days'):
            if n == 0 and 'password' in lower:return 'Passwords do not expire under this policy.'
            if n == 0:return 'No backup retention period is configured.' if 'backup' in lower else 'No retention period is configured.'
            return f'The '+('password lifetime' if 'password' in lower else 'backup retention period' if 'backup' in lower else 'retention period')+f' is {n} '+('day.' if n == 1 else 'days.')
        if label == 'Version':return f'The launch-template version is {n}.'
        if label == 'Clients evaluated':return f'{n} clients were assessed.'
        if label == 'Minimum password length':
            return f'Passwords must contain at least {n} characters.'
        if label == 'Number of prior passwords blocked from reuse':
            return f'The previous {n} passwords cannot be reused.'
        if label == 'Configured value' and any(word in cid for word in ('seven_day', 'retention', 'snapshots_seven')):
            return f'Backups are kept for {n} days.'
        if label == 'Encryption config':
            return _listed('envelope-encryption configurations', n)
        if label == 'Non compliant':
            return _listed('items marked noncompliant', n)
        if label.endswith(' count'):
            noun = lower[:-6]
            if noun in ('ingress','egress'):return _listed(noun+' rules',n)
            return _listed(noun + ('es' if noun.endswith('s') else 's'), n)
        numeric_phrases = {'Port': f'The service listens on port {n}.',
            'Hop limit': f'Metadata responses can cross at most {n} network hops.',
            'Monitoring interval': f'Enhanced monitoring is collected every {n} seconds.' if n else 'Enhanced monitoring is disabled.',
            'Backtrack window': f'The database can be rewound by up to {n} seconds.' if n else 'Database backtracking is disabled.',
            'Reserved concurrency': f'The function is limited to {n} simultaneous executions.' if n else 'Reserved concurrency is set to zero, which stops the function from processing events.',
            'Bootstrap version': f'The CDK bootstrap version is {n}.', 'Recommended': f'The recommended minimum version is {n}.',
            'Approved ceiling': f'The approved request-rate limit is {n}.',
            'Policy statements reviewed': f'{n} policy '+('statement was reviewed.' if n == 1 else 'statements were reviewed.'),
            'Variables evaluated': f'{n} environment variables were checked.',
            'Documented minimum': f'The required minimum capacity is {n}.',
            'Configured capacity': f'The configured capacity is {n}.',
            'Egress rules checked': f'{n} outbound rules were checked.',
            'World rules checked': f'{n} rules allowing internet sources were checked.',
            'First deploy stage index': f'The first deployment is in pipeline stage {n}.',
            'Public Allow without mount target condition': f'{n} public access grants lack a mount-target restriction.',
            'Public allow without mount target condition': f'{n} public access grants lack a mount-target restriction.'}
        if label in numeric_phrases:return numeric_phrases[label]
        if 'days' in lower or 'hours' in lower or 'minutes' in lower or 'seconds' in lower:
            return f'{subject} is {n}.'
        noun = re.sub(r'^(?:number of |recorded )| count$', '', lower)
        if noun == 'wildcard statement': noun = 'statements allowing all actions on all resources'
        if noun == 'matching attachment': noun = 'matching policy attachments'
        if noun in ('authorizers', 'methods', 'rules', 'policies', 'findings', 'members', 'backup plans', 'backup report plans') or noun.endswith(('s', 'instances', 'statements')):
            return _listed(noun, n)
        return f'{subject} is set to {n}.'
    if label in ('Inventory', 'Enrollment service', 'Feature'):
        return f'The check covers {_words(value)}.'
    if label in ('Bucket name', 'Project name', 'User name', 'Cluster name', 'Repository'):
        return f'The {lower.removesuffix(" name")} is named {value}.'
    if label == 'Parameter':
        return f'The database setting checked is {value}.'
    if label == 'Backup selection or checked tag-key match' and value in ('tag','arn'):
        return 'The resource matches an AWS Backup selection by '+('a checked tag key.' if value=='tag' else 'its ARN.')
    if label == 'Security configuration':
        return f'The resource uses security configuration {value}.'
    if label.endswith(('protocols', 'Protocols')):
        return f'The configured protocols are {value}.'
    if label in ('Privileged containers', 'Writable root containers', 'Root containers', 'Unencrypted volumes'):
        condition = {'Privileged containers': 'run in privileged mode', 'Writable root containers': 'have a writable root filesystem',
                     'Root containers': 'run as root', 'Unencrypted volumes': 'are not encrypted'}[label]
        return f'The following '+('volumes' if label == 'Unencrypted volumes' else 'containers')+f' {condition}: {value}.'
    if label == 'Allow origins':
        return 'Browser requests are allowed from every origin.' if value == '*' else f'Browser requests are allowed from {value}.'
    if label in ('Created at', 'Expires at', 'Observed at', 'Delivery at', 'Latest cloudwatch delivery', 'Captured cutoff'):
        descriptions = {'Created at': 'The access key was created on', 'Expires at': 'The certificate expires on',
            'Observed at': 'The evidence was collected on', 'Delivery at': 'The latest log delivery was on',
            'Latest cloudwatch delivery': 'The latest CloudWatch log delivery was on', 'Captured cutoff': 'Credential activity was checked against the cutoff'}
        return descriptions[label]+' '+value.replace('T', ' at ').replace('+00:00', ' UTC')+'.'
    plural = lower.endswith(('types', 'actions', 'accounts', 'rules', 'names', 'categories', 'ports', 'subnets', 'zones', 'destinations', 'statuses', 'roles', 'protocols', 'selectors', 'groups', 'regions', 'containers', 'levels', 'principals', 'attributes', 'indexes', 'headers', 'filters', 'clients', 'exports', 'values', 'exceptions', 'methods', 'endpoints', 'artifacts', 'requirements', 'ids', 'arns', 'policies', 'devices', 'features', 'versions'))
    prefix = subject if subject.startswith(('The ', 'This ', 'A ', 'An ')) else 'The '+(subject if subject.split()[0] in _ACRONYMS.values() else subject[0].lower()+subject[1:])
    return prefix+(' are ' if plural else ' is ')+value+'.'


def _collection_sentence(label, values, cid):
    """Explain structured deciding values rather than counting dictionary keys."""
    lower = _words(label)
    if label in ('Remaining days', 'Remaining calendar days', 'Expiring') and isinstance(values, dict) and values and all(type(n) in (int, float) for n in values.values()):
        days = min(values.values())
        return f'The nearest certificate expires in {days:g} '+('day.' if days == 1 else 'days.')
    if label == 'Configured policy' and isinstance(values, dict):
        length, age = values.get('MinimumPasswordLength'), values.get('MaxPasswordAge')
        if type(length) is int and type(age) is int:
            return f'Passwords must contain at least {length} characters and expire after {age} days.'
    if isinstance(values, list) and values and all(type(v) is bool for v in values):
        if label == 'Encrypted':
            return 'All attached storage is configured for encryption.' if all(values) else 'At least one attached storage device is not encrypted.'
        if label == 'Delete on termination':
            return 'All attached volumes are deleted with the instance.' if all(values) else 'At least one attached volume is kept after the instance is deleted.'
        if label == 'Tunnel logging':
            return 'Logging is enabled for every VPN tunnel.' if all(values) else 'Logging is disabled for at least one VPN tunnel.'
        if label == 'Managed':
            return 'All listed detectors are centrally managed.' if all(values) else 'At least one detector is not centrally managed.'
    if label == 'Recent use' and isinstance(values, dict):
        return 'Root credential activity was found within the checked period.' if values else 'No root credential activity was recorded in the checked period.'
    if label == 'Public grant detected' and isinstance(values, list):
        return 'The bucket permissions include a public access grant.' if values else 'No public access grant was found in the bucket permissions.'
    nouns = {'Encryption config': 'envelope-encryption configurations', 'Non compliant': 'noncompliant items',
        'Statements exceeding window': 'trust statements that exceed the allowed access period',
        'Missing approved criteria': 'missing approved suppression criteria',
        'Rules using count instead of block': 'rules that only count requests instead of blocking them',
        'Globally routable ipv6': 'globally routable IPv6 addresses'}
    if label.lower() in {k.lower() for k in nouns}:
        noun=next(v for k,v in nouns.items() if k.lower()==label.lower())
        return _listed(noun, len(values))
    if label == 'Ports' and isinstance(values, list) and values and all(type(v) is int for v in values):
        return 'The ports checked are '+', '.join(map(str, values))+'.'
    if label in ('Destinations', 'Log destinations') and isinstance(values, list) and all(isinstance(v, str) for v in values) and '.vpc.' in cid:
        return 'The routes target '+(', '.join(values) if values else 'no recorded network ranges')+'.'
    if isinstance(values, list) and values and all(type(v) is bool for v in values):
        if label in ('Public flags', 'Public ip assignment'):
            return 'At least one subnet assigns public IP addresses automatically.' if any(values) else 'None of the assessed subnets assigns public IP addresses automatically.'
    if isinstance(values, list):
        if label.lower() == 'unscoped agentcore token operations':
            return _listed('AgentCore token operations without workload-identity restrictions', len(values))
        if cid == 'aws_eventbridge_iam_user_change_alert' and label in ('Missing event names', 'Covered event names'):
            if label == 'Covered event names':return f'The rule covers {len(values)} required IAM-user change events.'
            return f'The rule misses {len(values)} required IAM-user change events.' if values else 'The rule covers all required IAM-user change events.'
        if cid == 'aws_securityhub_standards_control_baseline' and label.lower() == 'mismatched standard arns':
            return _listed('Security Hub standards that differ from the approved baseline', len(values))
    if isinstance(values, dict):
        if label == 'Zones' and all(isinstance(v,list) for v in values.values()):
            return 'Instance-type choices per zone are '+', '.join(str(zone)+': '+', '.join(map(str,types)) for zone,types in values.items())+'.'
        if label == 'Risks' and all(type(v) is int for v in values.values()):
            return 'The review records '+', '.join(f'{n} {str(level).lower()} risks' for level,n in values.items())+'.'
        if label == 'Components' and all(v in ('PASS','FAIL','UNKNOWN') for v in values.values()):
            failed=sum(v=='FAIL' for v in values.values()); unknown=sum(v=='UNKNOWN' for v in values.values())
            return 'The ACL and policy checks found no public write grants.' if values and not failed and not unknown else 'A component check found public write grants.' if failed else 'The ACL or policy assessment is incomplete.'
        if label.lower() == 'missing managed-rule exceptions':
            names=[str(name) for v in values.values() if isinstance(v,list) for name in v]
            return 'The required managed-rule exceptions are missing for '+', '.join(names)+'.' if names else 'No missing managed-rule exceptions were recorded.'
        if not values:return 'No '+lower+' were recorded.'
        if label == 'Rotation rules' and type(values.get('AutomaticallyAfterDays')) is int:
            return f'Secret rotation is scheduled every {values["AutomaticallyAfterDays"]} days.'
        if label == 'Metadata options':
            tokens = values.get('HttpTokens')
            if tokens in ('required', 'optional'):
                return 'The instance '+('requires IMDSv2 tokens.' if tokens == 'required' else 'allows metadata requests without IMDSv2 tokens.')
        if label == 'Logging enabled' and isinstance(values.get('TargetBucket'), str):
            return 'Access logs are configured to go to bucket '+values['TargetBucket']+'.'
        if label == 'Wildcard method settings':
            cached, encrypted = values.get('cachingEnabled'), values.get('cacheDataEncrypted')
            if type(cached) is bool and type(encrypted) is bool:
                return 'Method caching is '+('enabled' if cached else 'disabled')+' and cached-data encryption is '+('enabled.' if encrypted else 'disabled.')
        if label == 'Origin groups' and type(values.get('Quantity')) is int:
            return _listed('origin groups', values['Quantity'])
        if label == 'Configured responses':
            known=[v for v in values.values() if isinstance(v,str)]
            if known:return 'Account-takeover risk responses are '+', '.join(sorted(set(known)))+'.'
        if label == 'Dns options' and all(type(v) is bool for v in values.values()):
            return 'DNS resolution is enabled on both sides of the peering connection.' if len(values)==2 and all(values.values()) else 'DNS resolution is not enabled on both sides of the peering connection.'
        if label == 'Severity counts' and all(type(v) is int for v in values.values()):
            return 'The image scan reports '+', '.join(f'{n} {str(level).lower()}-severity findings' for level,n in values.items())+'.'
        # The number of dictionary keys is not the configured setting.
        return 'The collected '+lower+' contain structured settings; their deciding values were not retained in this summary.'
    if isinstance(values, list) and values and all(isinstance(v, str) for v in values):
        rendered = ', '.join(_display(v) for v in values)
        if len(rendered) <= 90:
            sentences = {
                'Shared with': 'The resource is shared with accounts {values}.',
                'Account shares': 'The resource is shared with accounts {values}.',
                'Policies matching the failure pattern': 'Policies {values} match the prohibited grant pattern.',
                'Matching policy sources': 'Policies {values} contain the checked grant pattern.',
                'Matching alarm arns': 'The matching alarms are {values}.',
                'Headers not redacted': 'Headers {values} are not redacted from logs.',
                'Failures': 'The check found these issues: {values}.',
                'Missing policy arns': 'Required policies {values} are missing.',
                'Not enabled for': 'Scanning is not enabled for {values}.',
                'Containers without log driver': 'Containers {values} have no log driver configured.',
                'Methods without authorization': 'API methods {values} have no authorization configured.',
                'Methods without validator': 'API methods {values} have no request validator configured.',
                'Rules without a matching alarm': 'Rules {values} have no matching alarm.',
                'Unresolved master instances': 'The scan could not resolve master instances {values}.',
                'Accounts outside the trust boundary': 'Accounts {values} fall outside the approved trust boundary.',
                'Missing values': 'Alert rules do not cover severity levels {values}.',
                'Allowed': 'This check allows the values {values}.',
                'Accepted': 'Approved deployment types include {values}.',
                'Blocked': 'The rule blocks {values}.',
                'Counted': 'The count covers network interfaces {values}.',
                'Exposed': 'Public access is declared for {values}.',
                'Insecure': 'The configuration uses insecure algorithms {values}.',
                'Overdue': 'Vulnerabilities {values} are past the allowed remediation age.',
                'Known exploited': 'Vulnerabilities {values} appear in the known-exploited catalog.',
                'Unencrypted': 'Destinations {values} lack the required encryption.',
                'Untrusted': 'The grant includes untrusted principals {values}.',
                'Upstream allowed': 'Internal packages {values} allow upstream versions.',
                'Access points without posix user': 'Access points {values} have no enforced POSIX user.',
                'Accounts without restriction': 'Accounts {values} lack the required instance-type restriction.',
                'Accounts without tamper deny': 'Accounts {values} lack the required tamper-prevention deny.',
                'Containers without log driver': 'Containers {values} have no log driver configured.',
                'Data sources without cmk': 'Data sources {values} have no customer-managed encryption key.',
                'Disabled access log load balancers': 'Load balancers {values} have access logging disabled.',
                'Disabled log types': 'Log types {values} are disabled.',
                'Disconnected instances': 'Container instances {values} are disconnected from ECS.',
                'Enabled without log group': 'Log types {values} are enabled but have no log-group destination.',
                'Failing clients': 'App clients {values} do not meet this check’s required setting.',
                'Headers not redacted': 'Headers {values} are not redacted from logs.',
                'Http listeners without redirect': 'HTTP listeners {values} have no HTTPS redirect.',
                'Listeners without acm certificate': 'Listeners {values} have no ACM certificate.',
                'Metrics disabled': 'Metrics are disabled for rules {values}.',
                'Non propagating tags': 'Tags {values} are not propagated to instances.',
                'Public mount targets': 'Mount targets {values} match the checked public-network pattern.',
                'Resources without recent restore test': 'Resources {values} lack a recent restore-test record.',
                'Root access points': 'Access points {values} permit root-user access.',
                'Unencrypted devices': 'Storage devices {values} are not encrypted.',
                'Unencrypted origins': 'Origins {values} do not use encrypted connections.',
                'Unreviewed merged targets': 'Changes were merged into targets {values} without the required review.',
                'Used by': 'The resource is used by {values}.',
                'Regions without imported findings': 'Regions {values} have no imported findings.',
                'Log groups without active central subscription': 'Log groups {values} have no active central subscription.',
                'Events from unapproved readers': 'Events {values} record reads by unapproved identities.',
            }
            if label in sentences:return sentences[label].format(values=rendered)
            # Lists name the actual affected items. Do not turn a list length
            # into a setting, or force plural nouns into "X is identifier".
            return 'The '+lower+' include '+rendered+'.'
    return None


def _typed_observation(cid, e):
    if cid == 'aws.lambda.function_url_authentication' and e.get('auth_type') in ('NONE', 'AWS_IAM'):
        return 'The function URL does not require IAM authentication.' if e['auth_type'] == 'NONE' else 'The function URL requires IAM-signed requests.'
    if cid == 'aws.c2b.dax.encryption_in_transit' and e.get('field') == 'ClusterEndpointEncryptionType' and e.get('configured') in ('NONE', 'TLS'):
        return 'DAX connections do not use TLS encryption.' if e['configured'] == 'NONE' else 'DAX connections use TLS encryption.'
    if cid == 'aws.cb.ssm.automation_logs_to_cloudwatch' and e.get('setting_value') in ('NONE', 'CloudWatch'):
        return 'Automation script logs are not sent to CloudWatch.' if e['setting_value'] == 'NONE' else 'Automation script logs are configured for CloudWatch.'
    if cid == 'aws.htbp.ecs.exec_session_logging_not_disabled' and e.get('exec_logging') in ('NONE', 'DEFAULT', 'OVERRIDE'):
        return {'NONE':'ECS command-session logging is disabled.', 'DEFAULT':'ECS command sessions use the task’s default log driver.', 'OVERRIDE':'ECS command sessions use a separate logging destination.'}[e['exec_logging']]
    if cid == 'aws.htbp.lambda.runtime_updates_not_pinned_manual' and e.get('update_runtime_on') in ('Auto', 'Manual', 'FunctionUpdate'):
        return {'Auto':'Lambda runtime updates are automatic.', 'Manual':'Lambda runtime updates require a manual version change.', 'FunctionUpdate':'Lambda updates the runtime when the function is updated.'}[e['update_runtime_on']]
    if cid == 'aws_config_recorder_all_supported_resources' and e.get('reason') == 'unrecognized Config recording strategy':
        return 'The recorder reports an unrecognized recording strategy, so its coverage could not be determined.'
    if cid == 'aws.claude_a.s3.prowler_acl_disabled' and e.get('ownership') == 'ObjectWriter':
        return 'Uploaded objects belong to the uploading account, and ACLs remain enabled.'
    if cid == 'aws.claude_a.iam.not_two_active_keys' and type(e.get('both_active')) is bool:
        return 'Both access keys are active.' if e['both_active'] else 'This identity does not have two active access keys.'
    if cid == 'aws.claude_a.ec2.eni_in_use' and e.get('status') in ('available', 'associated', 'attaching', 'in-use', 'detaching'):
        return {'available':'The network interface reports an available status.', 'in-use':'The network interface is in use.', 'associated':'The network interface is associated.', 'attaching':'The network interface is being attached.', 'detaching':'The network interface is being detached.'}[e['status']]
    if cid == 'aws.claude_a.vpc.nacl_no_world_remote_admin' and isinstance(e.get('rule_numbers'), list):
        n = len(e['rule_numbers'])
        return 'No ACL allow entry opens SSH or RDP to internet sources.' if not n else f'{n} ACL allow '+('entry opens' if n == 1 else 'entries open')+' SSH or RDP to internet sources; earlier deny rules were not assessed.'
    if cid == 'aws.claude_a.vpc.route_table_no_default_igw_route' and isinstance(e.get('destinations'), list):
        return 'The route table has a default route to an internet gateway.' if e['destinations'] else 'The route table has no default route to an internet gateway.'
    if cid in ('aws.claude_a.iam.access_keys_rotated_90', 'aws.claude_a.iam.access_keys_used_45') and isinstance(e.get('stale_keys'), list):
        n = len(e['stale_keys'])
        condition = 'have not been rotated within 90 days' if cid.endswith('rotated_90') else 'have been unused for more than 45 days'
        return ('No active access keys '+condition+'.') if not n else f'{n} active access '+('key has' if n == 1 else 'keys have')+' '+condition.removeprefix('have ')+'.'
    if cid == 'aws.claude_a.iam.no_unused_initial_access_key' and isinstance(e.get('never_used_keys'), list):
        n = len(e['never_used_keys'])
        return 'No active access keys belonging to a console user are marked as never used.' if not n else f'{n} active access '+('key belonging to a console user has' if n == 1 else 'keys belonging to a console user have')+' never been used.'
    if cid == 'aws.claude_a.iam.prowler_admin_group_members_mfa' and isinstance(e.get('members_without_mfa'), list):
        n = len(e['members_without_mfa'])
        return 'Every assessed member of this administrator group has MFA enabled.' if not n else f'{n} '+('member of this administrator group lacks' if n == 1 else 'members of this administrator group lack')+' MFA.'
    if cid == 'aws.c2b.cloudfront.s3_origin_bucket_exists' and isinstance(e.get('buckets'), list) and e.get('reason') == 'origin bucket existence not resolvable':
        return 'The scan could not confirm whether the referenced S3 origin buckets exist.'
    if cid == 'aws.htbp.eks.access_entries_authentication':
        modes = {'API': 'access entries', 'CONFIG_MAP': 'legacy ConfigMap grants', 'API_AND_CONFIG_MAP': 'access entries and legacy ConfigMap grants'}
        mode = modes.get(e.get('authentication_mode')) if isinstance(e.get('authentication_mode'), str) else None
        if mode and type(e.get('bootstrap_cluster_creator_admin')) is bool:
            return 'The cluster accepts '+mode+'. Its creator '+('receives' if e['bootstrap_cluster_creator_admin'] else 'does not receive')+' administrator access at setup.'
    if cid == 'aws_wafv2_baseline_managed_rules' and all(isinstance(e.get(k), list) for k in ('count_only', 'missing')):
        missing, counting = len(e['missing']), len(e['count_only'])
        return ('All required managed rule groups are present.' if not missing else f'{missing} required managed rule groups are missing.')+' '+('None is set to count requests without blocking them.' if not counting else f'{counting} managed rule groups count requests without blocking them.')
    if cid == 'aws.c2b.elbv2.listeners_secure_protocol' and isinstance(e.get('insecure_listeners'),list):
        listeners=e['insecure_listeners']
        if not listeners:return 'Every assessed listener uses the required encrypted protocol.'
        rendered=[re.sub(r'^(HTTP|TCP|HTTPS|TLS):(\d+)$', r'\1 on port \2',str(v)) for v in listeners]
        return 'Listeners using an unapproved protocol are '+', '.join(rendered)+'.'
    if cid == 'aws_cognito_session_expiry' and isinstance(e.get('validity_minutes'), dict):
        values = e['validity_minutes']
        if all(type(values.get(k)) in (int, float) for k in ('AccessToken', 'IdToken', 'RefreshToken')):
            return f'Access and ID tokens expire after {values["AccessToken"]} and {values["IdToken"]} minutes; refresh tokens expire after {values["RefreshToken"]} minutes.'
    if cid == 'aws_wafv2_global_allow_block_lists' and isinstance(e.get('approved_lists_matched'), dict):
        values = e['approved_lists_matched']
        if all(type(values.get(k)) is bool for k in ('Allow', 'Block')):
            return 'The allow list '+('matches' if values['Allow'] else 'does not match')+' the approved ranges; the block list '+('matches.' if values['Block'] else 'does not match.')
    if cid == 'aws_sensitive_data_rest_access_controls' and all(isinstance(e.get(k), list) for k in ('disabled_block_flags', 'unapproved_statement_indexes')):
        a,b=len(e['disabled_block_flags']),len(e['unapproved_statement_indexes'])
        return ('All four S3 public-access protections are enabled.' if a == 0 else 'All four S3 public-access protections are disabled.' if a == 4 else f'{a} S3 public-access protections are disabled.')+' '+('Reader-policy grants match the approved rules.' if b == 0 else f'{b} reader-policy statements fall outside the approved rules.')
    if cid == 'aws_vpn_tunnel_encryption_configuration' and all(isinstance(e.get(k),list) for k in ('unsafe_tunnels', 'unsafe_client_vpns')):
        a,b=len(e['unsafe_tunnels']),len(e['unsafe_client_vpns'])
        return 'No VPN configurations violate the checked encryption criteria.' if not a and not b else f'The encryption criteria are not met by {a} site-to-site '+('tunnel' if a==1 else 'tunnels')+f' and {b} Client VPN '+('endpoint.' if b==1 else 'endpoints.')
    if cid in ('aws.nist.sc_8_coverage','aws.nist.sc_8_1_coverage') and type(e.get('external_endpoint_count')) is int and isinstance(e.get('unsafe_endpoint_ids'),list):
        a,n=len(e['unsafe_endpoint_ids']),e['external_endpoint_count']
        return f'Of {n} external endpoints checked, '+('all match the approved TLS settings.' if not a else f'{a} fall outside the approved TLS settings.')
    if cid == 'aws_wafv2_monitoring_rate_rule' and isinstance(e.get('endpoints_without_rate_alert'),list):
        n=len(e['endpoints_without_rate_alert'])
        return 'Every assessed monitoring endpoint has the required rate alert.' if not n else f'{n} monitoring '+('endpoint lacks' if n==1 else 'endpoints lack')+' the required rate alert.'
    if cid == 'aws_ssm_application_inventory_fresh' and all(isinstance(e.get(k),list) for k in ('unmanaged_instance_ids','stale_inventory_instance_ids')):
        a,b=len(e['unmanaged_instance_ids']),len(e['stale_inventory_instance_ids'])
        return ('Every assessed running instance has SSM application inventory.' if not a else f'{a} running instances have no SSM application inventory.')+' '+('All recorded inventories are within 24 hours.' if not b else f'{b} '+('inventory is' if b==1 else 'inventories are')+' older than 24 hours.')
    if cid.startswith('aws.claude_a.vpc.sg_no_world_') and isinstance(e.get('matching_ingress'),list):
        matches=e['matching_ingress']
        if not matches:return 'No ingress rule allows internet sources to reach the checked service ports.'
        ports=sorted({p for r in matches if isinstance(r,dict) for p in r.get('ports',[]) if type(p) is int})
        if ports:return 'Ingress rules allow internet sources to reach '+('port ' if len(ports)==1 else 'ports ')+', '.join(map(str,ports))+'.'
    return None


def _legacy_sentence(text):
    # Older per-check formatters already retain their actual values; translate
    # their explicit labels without deriving new configuration facts.
    replacements = {
        'The CloudFront geographic restriction mode is none.': 'CloudFront geographic restrictions are not configured.',
        'The AppSync field-log level is none.': 'AppSync field logging is disabled.',
        'The DMS endpoint SSL mode is none.': 'The DMS endpoint does not use TLS encryption.',
        'The Kinesis stream encryption type is none.': 'Kinesis stream encryption at rest is disabled.',
        'No DMS source logging components not enabled were recorded.': 'Every assessed DMS source-log component is enabled.',
        'No DMS target logging components not enabled were recorded.': 'Every assessed DMS target-log component is enabled.',
        'No OpenSearch log categories not exported to CloudWatch were recorded.': 'Every assessed OpenSearch log category is configured for export to CloudWatch.',
        'Exec logging is NONE.': 'ECS command-session logging is disabled.',
        'No headers not redacted were recorded.': 'No required headers are missing from the redaction settings.',
    }
    if text in replacements:return replacements[text]
    for old, new in {
        '1 matching database event subscriptions are recorded': '1 matching database event subscription is configured',
        '1 Client VPN destinations have': '1 Client VPN destination has',
        'All 1 sensitive Allow statements require': 'The sensitive Allow statement requires',
        'All 1 sensitive Allow statements have': 'The sensitive Allow statement has',
        '1 sensitive Allow statements have': '1 sensitive Allow statement has',
        '1 trail destination buckets have': '1 trail destination bucket has',
        'All 1 assessed public ALBs use': 'The assessed public ALB uses',
    }.items():
        text = text.replace(old, new)
    m=re.fullmatch(r'Minimum password length is (\d+)\.?',text)
    if m:return f'Passwords must contain at least {m[1]} characters.'
    m=re.fullmatch(r'(.+): (none|empty)',text.rstrip('.'))
    if m:return 'No '+re.sub(r'^(?:Recorded |Declared |Configured )', '', m[1])+' were recorded.'
    m=re.fullmatch(r'(.+ declarations): (\d+) enabled, (\d+) disabled',text.rstrip('.'))
    if m:
        subject=m[1].removesuffix(' declarations')
        return f'{subject} is enabled for {m[2]} assessed items and disabled for {m[3]}.'
    m=re.fullmatch(r'Recorded Organizations delegated administrator accounts: (.+)',text.rstrip('.'))
    if m:return 'Organizations delegates policy administration to account '+m[1]+'.'
    text=re.sub(r'\b1 (declared listeners|origin groups|days|others|backup rules|active monitors|declared sharing principals|trusted principals|matching subscriptions|signature artifacts|SBOM artifacts)\b',lambda m:'1 '+_singular(m[1]),text)
    text=re.sub(r'(?<= is )([A-Z][A-Z0-9_]+)(?=[.;]|$)',lambda m:_display(m[1]),text)
    text=text.replace('1 have ', '1 has ').replace('1 are ', '1 is ')
    return text


def natural_observation(finding, row, observation):
    """Translate field-bag fragments while retaining already fluent explanations."""
    if not observation:
        return observation
    cid, e = finding['check_id'], finding['evidence']
    typed = _typed_observation(cid, e)
    if typed is not None:
        return typed
    if cid == 'aws.a.cloudtrail.joined_bucket_declared_public_grants' and isinstance(e.get('public_acl_groups'), list):
        groups = e['public_acl_groups']
        if any(str(group).endswith('/AllUsers') for group in groups):
            return 'The log bucket’s permissions include everyone, including people who are not signed in.'
        if any(str(group).endswith('/AuthenticatedUsers') for group in groups):
            return 'The log bucket’s permissions include every authenticated AWS account, rather than only this account.'
    if cid == 'aws.c2b.drs.region_has_job' and type(e.get('source_servers')) is int:
        return _listed('Disaster Recovery source servers', e['source_servers'])
    if cid.startswith('aws.claude_a.vpc.nacl_no_world_') and type(e.get('ordered_world_ingress_allowed')) is bool:
        protocol, port = e.get('protocol'), e.get('port')
        target = 'all ports' if str(protocol) == '-1' else f'TCP port {port}' if str(protocol) == '6' else f'port {port}'
        return f'The network ACL '+('allows internet sources to reach ' if e['ordered_world_ingress_allowed'] else 'does not allow internet sources to reach ')+target+'.'
    if cid.startswith('aws.b.rds.') and cid.endswith('_event_categories') and type(e.get('enabled')) is bool:
        if e['enabled'] is False:return 'Database event notifications are disabled.'
        present = e.get('present')
        if isinstance(present, list) and all(isinstance(v, str) for v in present):
            return 'Database notifications are enabled for '+', '.join(present)+'.' if present else 'Database notifications are enabled but no event categories were recorded.'
    if cid.startswith('aws.b.inspector.admin_') and type(e.get('auto_enable')) is bool:
        service = {'ec2':'EC2 instances', 'ecr':'container images', 'lambda':'Lambda functions', 'lambdaCode':'Lambda code'}.get(str(e.get('auto_enable_service')), 'new resources')
        return f'Inspector automatic scanning for {service} is '+('enabled.' if e['auto_enable'] else 'disabled.')
    if cid in ('aws.cb.ssm.instance_association_compliant', 'aws.cb.ssm.instance_patch_compliant') and type(e.get('items')) is int and type(e.get('non_compliant')) is int:
        return f'Of {e["items"]} reported compliance items, '+('none are marked noncompliant.' if not e['non_compliant'] else f'{e["non_compliant"]} are marked noncompliant.')
    if cid == 'aws.c2b.directoryservice.manual_snapshot_quota' and type(e.get('limit')) is int and type(e.get('current')) is int:
        return f'The directory uses {e["current"]} of its {e["limit"]} manual-snapshot slots.'
    if cid == 'aws.cb.rds.aurora_mysql_server_audit_logging' and str(e.get('server_audit_logging')) in ('0', '1'):
        return 'Database audit logging is '+('enabled.' if str(e['server_audit_logging']) == '1' else 'disabled.')
    if cid in ('aws.a.accessanalyzer.region_present', 'aws.a.accessanalyzer.region_active'):
        if type(e.get('analyzer_count')) is int:
            count = e['analyzer_count']
            return 'No Access Analyzer was found in this region.' if count == 0 else f'The region has {count} Access Analyzer'+('.' if count == 1 else 's.')
        statuses = e.get('analyzer_statuses')
        if isinstance(statuses, list):
            return 'An active Access Analyzer was found in this region.' if 'ACTIVE' in statuses else 'No active Access Analyzer was found in this region.'
    if cid in ('aws.b.backup_plan.regional_presence', 'aws.b.backup_vault.regional_presence') and type(e.get('observed_configurations')) is int:
        noun = 'backup plans' if 'backup_plan.' in cid else 'backup vaults'
        return _listed(noun, e['observed_configurations'])
    if 'password_policy_strong' in cid and isinstance(e.get('composition'), dict):
        names = {'RequireLowercaseCharacters': 'lowercase letters', 'RequireUppercaseCharacters': 'uppercase letters',
                 'RequireNumbers': 'numbers', 'RequireSymbols': 'symbols'}
        missing = [name for key, name in names.items() if e['composition'].get(key) is False]
        if missing:
            return 'The password policy does not require '+', '.join(missing)+'.'
        if all(e['composition'].get(key) is True for key in names):
            return 'Passwords must include uppercase and lowercase letters, numbers and symbols.'
    if cid == 'aws.a.cloudwatch.any_state_actions' and isinstance(e.get('state_actions'), dict):
        states = {'AlarmActions': 'alarm', 'OKActions': 'healthy', 'InsufficientDataActions': 'missing-data'}
        selected = [name for key, name in states.items() if e['state_actions'].get(key)]
        return 'The alarm has actions for '+', '.join(selected)+' states.' if selected else 'The alarm has no actions configured for any state.'
    for key in ('effective_settings', 'settings'):
        flags = e.get(key)
        names = {'BlockPublicAcls': 'rejecting new public ACLs', 'IgnorePublicAcls': 'ignoring existing public ACLs',
                 'BlockPublicPolicy': 'rejecting public policies', 'RestrictPublicBuckets': 'restricting public bucket access'}
        if '.s3.' in cid and isinstance(flags, dict) and set(flags) & names.keys():
            missing = [name for flag, name in names.items() if flags.get(flag) is False]
            if len(missing) == 4:return 'All four S3 Block Public Access protections are disabled.'
            if missing:return 'S3 public-access protections are missing for '+', '.join(missing)+'.'
            if all(flags.get(flag) is True for flag in names):return 'All four S3 Block Public Access protections are enabled.'
            return 'S3 public-access protection settings are incomplete, so public access could not be assessed.'
    if cid == 'aws.b.dynamodb.kms_description' and isinstance(e.get('sse_description'), dict):
        if e['sse_description'].get('SSEType') == 'KMS':return 'The table’s encryption configuration uses AWS KMS.'
    # Parameter pairs require interpretation together, not two isolated fields.
    if cid.startswith('aws.cb.rds.') and e.get('parameter') in ('rds.force_ssl', 'require_secure_transport'):
        value = str(e.get('value', '')).lower()
        if value in ('1', 'on', 'true', '0', 'off', 'false'):
            return ('Database connections are required to use TLS encryption.' if value in ('1', 'on', 'true') else
                    'Database connections are not required to use TLS encryption.')
    if '.guardduty.' in cid and type(e.get('enabled')) is bool:
        names = {'EBS_MALWARE_PROTECTION': 'EBS malware scanning', 'RUNTIME_MONITORING': 'runtime monitoring', 'EKS_RUNTIME_MONITORING': 'EKS runtime monitoring'}
        feature = names.get(str(e.get('feature')))
        if feature:
            return f'GuardDuty {feature} is '+('enabled.' if e['enabled'] else 'disabled.')
    parts = observation.split('; ')
    specs = {spec['label'].lower(): spec for spec in row.get('fields', [])}
    labels = set(specs)
    labels |= {'declared api endpoint types', 'default encryption configuration', 'rule count', 'root access key count'}
    translated, changed = [], False
    for part in parts:
        # Only translate a recorded field label; a colon inside a meaningful
        # sentence, ARN or URL is not a field/value separator.
        match = re.match(r'^([^:]+): (.*)$', part)
        if match and match[1].lower() in labels:
            changed = True
            spec = specs.get(match[1].lower())
            actual = e.get(spec['key']) if spec else None
            sentence = _collection_sentence(match[1], actual, cid) if isinstance(actual, (list, dict)) else None
            sentence = sentence or _sentence(match[1], match[2], cid)
            if sentence:
                translated.append(sentence)
        else:
            translated.append(_legacy_sentence(part))
            changed = changed or translated[-1] != part
    result = ' '.join(_legacy_sentence(text) if text.endswith('.') else _legacy_sentence(text+'.') for text in translated) if changed else _legacy_sentence(observation)
    return result
