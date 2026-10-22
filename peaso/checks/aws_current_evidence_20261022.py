"""Short observed explanations for the finite current AWS successor cohort."""

import re

CURRENT_IDS = frozenset({
    'aws.iam.group_inline_policies_have_members',
    'aws.iam.identity_center.permission_set_has_consumer_all_accounts',
    'aws.iam.oidc_provider_has_role_consumer',
    'aws.iam.saml_provider_has_role_consumer',
    'aws.network.internet_gateway_attached',
    'aws.network.route_table_associated',
    'aws.network.target_group_has_load_balancer',
    'aws.network.vpn_gateway_attached',
    'aws.review.build_deployment.referenced_source_secret_indicators',
    'aws.review.ecr.selected_image_vulnerabilities',
    'aws.review.ecr_public.selected_image_high_vulnerabilities',
    'aws.review.ecr_public.selected_image_secret_indicators',
    'aws.review.ecs.selected_environment_file_secret_indicators',
    'aws.review.workload.referenced_source_secret_indicators',
    'aws.review.workload.selected_image_secret_indicators',
})


def _lines(*sentences):
    assert len(sentences) == 3 and all(sentence.endswith('.') and '\n' not in sentence for sentence in sentences)
    return '\n'.join(sentences)


def _secret_location(leaks):
    """Name recorded content locations without copying paths or secret values."""
    names = []
    count = 0
    for leak in leaks:
        if not isinstance(leak, dict):
            continue
        locations = leak.get('locations')
        if not isinstance(locations, list):
            continue
        for location in locations:
            if not isinstance(location, dict) or not isinstance(location.get('path'), str):
                continue
            count += 1
            path = location['path']
            if re.fullmatch(r's3_selected_source_content:[0-9a-f]{64}\.text', path):
                name = 'selected S3 source text'
            elif re.fullmatch(r'ecr-public-image:[0-9a-f]{64}\.layer-\d+\.file-\d+\.chunk-\d+', path):
                name = 'an image layer file'
            elif re.fullmatch(r'ecr-public-image:[0-9a-f]{64}\.manifest', path):
                name = 'the image manifest'
            elif path == 'image-config':
                name = 'image config'
            else:
                continue
            if name not in names:
                names.append(name)
    if names and len(names) == count:
        return ' and '.join(names)
    if not count:
        return 'content whose location was not recorded'
    return f'{count} recorded content location' + ('' if count == 1 else 's')


def _secret_kind(leaks):
    for leak in leaks:
        if isinstance(leak, dict):
            detectors = leak.get('detectors')
            if not isinstance(detectors, list):
                continue
            for detector in detectors:
                if isinstance(detector, dict) and detector.get('rule') in {'github-pat', 'betterleaks.github-pat'}:
                    return 'GitHub token indicator'
    return 'secret indicator'


def _cve_suffix(findings):
    ids = sorted({finding.get('vulnerability_id') for finding in findings
                  if isinstance(finding, dict) and isinstance(finding.get('vulnerability_id'), str)
                  and re.fullmatch(r'CVE-\d{4}-\d{4,}', finding['vulnerability_id'])})
    return f', including {ids[0]}' if ids else ''


def explanation(cid, evidence):
    """Describe recorded values only; incomplete input names its missing fact."""
    if cid not in CURRENT_IDS or not isinstance(evidence, dict):
        return None
    e = evidence
    if cid == 'aws.iam.group_inline_policies_have_members':
        policies, members = e.get('inline_policies'), e.get('member_identities')
        if isinstance(policies, list) and isinstance(members, list):
            return _lines(
                f'The IAM group has {len(policies)} inline policies and {len(members)} recorded user members.',
                'Those policies may grant permissions to group members.' if members else 'No current user is recorded as inheriting those group policies.',
                'The permissions could affect those users and their data.' if members else 'A future member could receive those permissions and reach related data.')
        return _lines('The IAM group policy or member list was not recorded.',
                      'Its current policy consumers are unclear.',
                      'The permissions that users may receive through the group remain unclear.')
    if cid == 'aws.iam.identity_center.permission_set_has_consumer_all_accounts':
        accounts = e.get('consumer_accounts')
        if isinstance(accounts, list):
            return _lines(
                f'The permission set has {len(accounts)} recorded consumer accounts.',
                'An assignment may make its permissions available in those accounts.' if accounts else 'No assignment or provisioned account is recorded in the complete account inventory.',
                'Those permissions could affect users and account data.' if accounts else 'A later assignment could grant users access to account data.')
        return _lines('The permission set’s all-account assignment and provisioning records are unavailable.',
                      'Its current account consumers are unclear.',
                      'The permissions that users may receive through it remain unclear.')
    if cid in {'aws.iam.oidc_provider_has_role_consumer', 'aws.iam.saml_provider_has_role_consumer'}:
        kind = 'OIDC' if '.oidc_' in cid else 'SAML'
        roles = e.get('role_consumers')
        if isinstance(roles, list):
            return _lines(
                f'The {kind} provider is named by {len(roles)} recorded IAM role trust policies.',
                'Those roles may accept federation through the provider.' if roles else 'No current role declares this provider as a trust principal.',
                'Their permissions could affect users and data.' if roles else 'A future role trust declaration could give federated users access to data.')
        return _lines(f'The {kind} provider’s complete role trust inventory is unavailable.',
                      'Its current role consumers are unclear.',
                      'The permissions that federated users may receive remain unclear.')
    network = {
        'aws.network.internet_gateway_attached': ('Internet gateway', 'VPC attachments', 'network routes'),
        'aws.network.route_table_associated': ('Route table', 'VPC associations', 'network routes'),
        'aws.network.target_group_has_load_balancer': ('Target group', 'load balancer associations', 'service traffic'),
        'aws.network.vpn_gateway_attached': ('VPN gateway', 'VPC attachments', 'private network routes'),
    }
    if cid in network:
        noun, setting, effect = network[cid]
        values = e.get('load_balancer_arns' if cid == 'aws.network.target_group_has_load_balancer' else 'associations')
        if isinstance(values, list):
            return _lines(
                f'The {noun.lower()} has {len(values)} recorded {setting}.',
                f'Those associations may carry {effect}.' if values else f'No current {effect} consumer is recorded for it.',
                'Changing this resource could affect people using connected services.' if values else 'A later association could change access to connected services and their data.')
        return _lines(f'The {noun.lower()}’s {setting} were not recorded completely.',
                      f'Its current {effect} consumers are unclear.',
                      'The effect on people using connected services remains unclear.')
    if cid == 'aws.review.ecr.selected_image_vulnerabilities':
        image, findings, coverage = e.get('Image'), e.get('Vulnerabilities'), e.get('Coverage')
        if isinstance(image, dict) and isinstance(findings, list) and coverage in {'COMPLETE', 'UNKNOWN'}:
            if findings:
                return _lines(f'The selected ECR image has {len(findings)} recorded HIGH or CRITICAL package findings{_cve_suffix(findings)}.',
                              'A workload using that image may contain vulnerable packages.',
                              'An exploitable flaw could affect service users or their data.')
            if coverage == 'COMPLETE':
                return _lines('The selected ECR image has no detected HIGH or CRITICAL package vulnerability in its complete fresh result.',
                              'A workload may use the same immutable image digest.',
                              'Other flaws or later deployments could still affect service users or data.')
        return _lines('The selected ECR image lacks complete bound package findings or coverage.',
                      'Its HIGH or CRITICAL package state is unclear.',
                      'A vulnerability that could affect service users or data may remain unrecorded.')
    if cid == 'aws.review.ecr_public.selected_image_high_vulnerabilities':
        vulnerabilities = e.get('vulnerabilities')
        if isinstance(vulnerabilities, list) and vulnerabilities:
            return _lines(f'The selected ECR Public image has {len(vulnerabilities)} recorded HIGH or CRITICAL package findings{_cve_suffix(vulnerabilities)}.',
                          'A workload using that image may include vulnerable packages.',
                          'An exploitable flaw could affect service users or their data.')
        if e.get('complete') is True and e.get('observed') == 'Trivy found no HIGH or CRITICAL package vulnerabilities in the selected ECR Public image using a fresh database.':
            return _lines('The selected ECR Public image has no detected HIGH or CRITICAL package vulnerability in its complete fresh result.',
                          'A workload may use that immutable image.',
                          'Other flaws or later deployments could still affect service users or data.')
        return _lines('The selected ECR Public image lacks complete bound package findings or coverage.',
                      'Its HIGH or CRITICAL package state is unclear.',
                      'A vulnerability that could affect service users or data may remain unrecorded.')
    secrets = {
        'aws.review.build_deployment.referenced_source_secret_indicators': ('build or deployment artifact', 'source location'),
        'aws.review.ecr_public.selected_image_secret_indicators': ('ECR Public image', 'image content'),
        'aws.review.ecs.selected_environment_file_secret_indicators': ('ECS environment file', 'task and S3 file association'),
        'aws.review.workload.referenced_source_secret_indicators': ('workload source', 'S3 source association'),
        'aws.review.workload.selected_image_secret_indicators': ('workload image', 'immutable image content'),
    }
    noun, binding = secrets[cid]
    leaks = e.get('secret_leaks')
    if isinstance(leaks, list) and leaks:
        kind = _secret_kind(leaks)
        count = len(leaks)
        return _lines(f'The selected {noun} has {count} detected {kind}{"s" if count != 1 else ""} in {_secret_location(leaks)}.',
                      'Someone who can read that content may obtain the underlying value.',
                      'That could expose related accounts or personal data.')
    clean = (isinstance(leaks, list) and not leaks and e.get('complete') is True)
    if cid == 'aws.review.ecr_public.selected_image_secret_indicators':
        clean = e.get('complete') is True and e.get('observed') == 'Both detectors found no supported secret in the selected ECR Public image.'
    if clean:
        return _lines(f'The selected {noun} has no detected supported secret indicator in its recorded content.',
                      f'Its recorded {binding} is complete for this selection.',
                      'Other content or versions could still carry values that affect people or data.')
    return _lines(f'The selected {noun} lacks a complete recorded {binding}.',
                  'Possible secret indicators in that content remain unclear.',
                  'A hidden credential there could affect accounts or personal data.')
