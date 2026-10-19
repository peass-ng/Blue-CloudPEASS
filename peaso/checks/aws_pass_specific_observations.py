"""Short observations from paired/native AWS success witnesses, not PASS alone."""
import re

REVIEWED_IDS = frozenset({
    'aws.cloudtrail.management_events', 'aws.eks.secrets_encryption',
    'aws.b.eks.secret_envelope_encryption', 'aws.b.fsx.openzfs_copy_backup_and_volume_tags',
    'aws.cb.fsx.openzfs_copy_tags_backups_and_volumes',
    'aws.cb.workspaces.private_subnet_with_nat_vpc',
    'aws.cb.opensearch.cognito_or_saml_dashboards_auth', 'aws.cb.opensearch.slow_logs_enabled',
    'aws.c2b.elbv2.listener_certificate_30_days', 'aws.c2b.elbv2.listener_certificate_7_days',
    'aws.c2b.drs.region_has_job', 'aws.pci.vpc.peering_dns_resolution',
    'aws_wafv2_rate_rule_alarm', 'aws_wafv2_request_validation_rules',
    'aws.c2b.ecr.latest_image_no_medium_plus_findings', 'aws.cb.redshift.maintenance_settings',
    'aws.c2b.cloudfront.logging_any', 'aws.b.ecs.host_network_nonprivileged',
    'aws.claude_a.s3.versioning_and_lifecycle',
    *('aws.cb.glue.' + kind + '_' + suffix for kind in ('dev_endpoint', 'job')
      for suffix in ('cloudwatch_encryption', 'bookmarks_encryption', 's3_encryption_first_mode')),
})


def _text(value):
    return isinstance(value, str) and 0 < len(value) <= 320 and all(ord(c) >= 32 for c in value)


def _strings(value, nonempty=False):
    return isinstance(value, list) and (bool(value) or not nonempty) and all(_text(v) for v in value)


def _nonnegative(value):
    return type(value) is int and value >= 0


def _trail(e):
    rows = e.get('event_selectors')
    if isinstance(rows, list) and rows:
        for row in rows:
            if not isinstance(row, dict):
                return None
            exclusions = row.get('ExcludeManagementEventSources', [])
            if row.get('IncludeManagementEvents') is True and row.get('ReadWriteType') == 'All' and exclusions == []:
                return 'CloudTrail selectors include both read and write management events without excluded event sources.'
    advanced = e.get('advanced_event_selectors')
    if isinstance(advanced, list) and advanced:
        # Reuse the exact pure selector interpretation used by the evaluator;
        # a selector count or a PASS status cannot prove read/write coverage.
        from .aws import _advanced_management_coverage, _MANAGEMENT_SOURCE_DOMAINS
        from .facts import Unavailable
        covered = set()
        for row in advanced:
            if not isinstance(row, dict):
                return None
            try:
                covered.update(_advanced_management_coverage(row))
            except (Unavailable, ValueError, TypeError, KeyError):
                continue
        required = {(direction, source) for direction in ('read', 'write') for source in _MANAGEMENT_SOURCE_DOMAINS}
        if required <= covered:
            return 'Advanced CloudTrail selectors include read and write management events across the assessed event sources.'
    return None


def evidence_summary(finding):
    if not isinstance(finding, dict) or finding.get('provider') != 'aws' or finding.get('status') != 'PASS':
        return None
    cid, e = finding.get('check_id'), finding.get('evidence')
    if not isinstance(cid, str) or cid not in REVIEWED_IDS or not isinstance(e, dict):
        return None
    if cid == 'aws.cloudtrail.management_events':
        return _trail(e)
    if cid in ('aws.eks.secrets_encryption', 'aws.b.eks.secret_envelope_encryption'):
        version = e.get('version')
        if not isinstance(version, str) or not re.fullmatch(r'\d+\.\d+(?:\.\d+)?', version):
            return None
        major, minor = map(int, version.split('.')[:2])
        if (major, minor) >= (1, 28) and e.get('encryption') in ('version-default envelope encryption', 'EKS default envelope encryption'):
            return f'EKS version {version} provides default envelope encryption for Kubernetes Secrets.'
        if e.get('secret_encryption_configured') is True or _strings(e.get('declared_encrypted_resources')) and 'secrets' in e['declared_encrypted_resources']:
            return f'EKS version {version} explicitly configures encryption for Kubernetes Secrets.'
        return None
    if cid in ('aws.b.fsx.openzfs_copy_backup_and_volume_tags', 'aws.cb.fsx.openzfs_copy_tags_backups_and_volumes'):
        fields = ('copy_backup_tags', 'copy_volume_tags') if cid.startswith('aws.b.') else ('copy_tags_to_backups', 'copy_tags_to_volumes')
        if all(e.get(k) is True for k in fields):
            return 'FSx OpenZFS copies resource tags to both backups and volumes.'
        return None
    if cid.startswith('aws.cb.glue.'):
        owner = 'development endpoint' if '.dev_endpoint_' in cid else 'job'
        target = 'CloudWatch logs' if '_cloudwatch_' in cid else 'job bookmarks' if '_bookmarks_' in cid else 'the first S3 encryption entry'
        mode = e.get('mode')
        allowed = ('SSE-KMS',) if '_cloudwatch_' in cid else ('CSE-KMS',) if '_bookmarks_' in cid else ('SSE-KMS', 'SSE-S3')
        if _text(e.get('security_configuration')) and mode in allowed:
            return f'The Glue {owner} security configuration declares {mode} for {target}.'
        if cid == 'aws.cb.glue.job_s3_encryption_first_mode' and e.get('encryption_type_argument') == 'sse-s3':
            return 'The Glue job declares the SSE-S3 encryption argument without an attached security configuration.'
        return None
    if cid == 'aws.cb.workspaces.private_subnet_with_nat_vpc':
        private, public = e.get('private_subnets'), e.get('public_subnets')
        if _nonnegative(private) and private >= 2 and _nonnegative(public) and public >= 1 and e.get('workspace_subnet_public') is False and e.get('nat_gateway') is True:
            return f'The WorkSpace subnet has no default Internet-gateway route; its VPC has {private} private subnets and a NAT route for egress.'
        return None
    if cid == 'aws.cb.opensearch.cognito_or_saml_dashboards_auth':
        cognito, saml = e.get('cognito'), e.get('saml')
        if type(cognito) is bool and type(saml) is bool and (cognito or saml):
            return 'OpenSearch Dashboards authentication enables ' + ('both Cognito and SAML.' if cognito and saml else 'Cognito.' if cognito else 'SAML.')
        return None
    if cid == 'aws.cb.opensearch.slow_logs_enabled':
        if e.get('search_slow') is True and e.get('index_slow') is True:
            return 'OpenSearch publishes both search and index slow logs.'
        return None
    if cid in ('aws.c2b.elbv2.listener_certificate_30_days', 'aws.c2b.elbv2.listener_certificate_7_days'):
        days, minimum = e.get('remaining_days'), 30 if cid.endswith('_30_days') else 7
        if not isinstance(days, dict) or not days or type(e.get('minimum_days')) is not int or e['minimum_days'] != minimum:
            return None
        if any(not _text(k) or type(v) is not int or v < minimum for k, v in days.items()):
            return None
        remaining = min(days.values())
        return f'The soonest listener certificate expires in {remaining} calendar days; the check requires at least {minimum}.'
    if cid == 'aws.c2b.drs.region_has_job':
        count, states = e.get('source_servers'), e.get('replication_states')
        if type(count) is int and count > 0 and isinstance(states, dict) and states == {'CONTINUOUS': count} and e.get('impaired_source_ids') == [] and e.get('uncertain_source_ids') == []:
            return f'All {count} configured DRS source servers report continuous replication; recovery-drill readiness is not established.'
        return None
    if cid == 'aws.pci.vpc.peering_dns_resolution':
        options = e.get('dns_options')
        if isinstance(options, dict) and all(options.get(k) is True for k in ('RequesterVpcInfo', 'AccepterVpcInfo')):
            return 'Both VPC peering sides enable DNS resolution from the remote VPC.'
        return None
    if cid == 'aws_wafv2_rate_rule_alarm':
        rules = e.get('checked_rules')
        if _strings(rules, True) and e.get('rules_without_alarm') == []:
            return f'Each of the {len(rules)} assessed WAF rate-limit rules has a matching enabled alarm.'
        return None
    if cid == 'aws_wafv2_request_validation_rules':
        albs = e.get('public_albs')
        if _strings(albs, True) and e.get('unprotected_albs') == []:
            return f'All {len(albs)} assessed public ALBs use the AWS WAF Common Rule Set without a group-level override.'
        return None
    if cid == 'aws.c2b.ecr.latest_image_no_medium_plus_findings':
        counts = e.get('severity_counts')
        known = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'UNDEFINED'}
        if e.get('scan_status') != 'COMPLETE' or not isinstance(counts, dict) or any(k not in known or not _nonnegative(v) for k, v in counts.items()):
            return None
        if any(counts.get(k, 0) for k in ('MEDIUM', 'HIGH', 'CRITICAL')):
            return None
        return 'The newest assessed ECR image has a completed scan with no MEDIUM, HIGH or CRITICAL findings.'
    if cid == 'aws.cb.redshift.maintenance_settings':
        days = e.get('retention_days')
        if e.get('allow_version_upgrade') is True and type(days) is int and days >= 7:
            return f'Redshift allows version upgrades and retains automated snapshots for {days} days.'
        return None
    if cid == 'aws.c2b.cloudfront.logging_any':
        if e.get('standard_logging') is True:
            return 'CloudFront standard access logging is enabled.'
        if _text(e.get('realtime_log_config')):
            return 'CloudFront declares a real-time access-log configuration on its default cache behavior.'
        if type(e.get('v2_deliveries')) is int and e['v2_deliveries'] > 0:
            return f'CloudFront has {e["v2_deliveries"]} configured version-2 access-log deliveries.'
        return None
    if cid == 'aws.b.ecs.host_network_nonprivileged':
        if e.get('network_mode') == 'host' and e.get('operating_system_family') == 'LINUX' and e.get('privileged_containers') == [] and _strings(e.get('proven_numeric_uid_containers'), True):
            return 'The host-network Linux task declares non-root numeric users and no privileged containers.'
        return None
    if cid == 'aws.claude_a.s3.versioning_and_lifecycle':
        rules = e.get('enabled_rules')
        if e.get('versioning') is True and _strings(rules, True):
            return f'S3 versioning is enabled with {len(rules)} enabled lifecycle rules.'
    return None
