"""Signed AWS compliance checks over explicit, complete, scope-bound facts.

New fact shapes are documented in sw44-collector-requests.md. Missing facts never
establish absence. No evaluator makes network calls.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from ipaddress import ip_network
import math
import re

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects


SPECS = {
    'aws_g6_cloudtrail_region_logging_trail_present': ('aws_region', 'hardening', 'medium', 'Every enabled Region has a logging CloudTrail trail', '1d3c031f5e53bcefd35f95b79057b4115337dc41f9fe00a11a212ae5a0949cb7'),
    'aws_bedrock_automated_reasoning_policy_attached': ('bedrock_automated_reasoning_policy', 'compliance', 'medium', 'Automated Reasoning for Output Validation', '55c2966fc59b7e842e486721fb149be48cf6d6c19f4b35f06479e33623272aa2'),
    'aws_controltower_landing_zone_active': ('control_tower_landing_zone', 'compliance', 'medium', 'Control Tower Automated Governance', '06528501698af585fa546f7b41b93a510457fe659452833f6541c6d2aa429d75'),
    'aws_identity_center_sso_configured': ('identity_center', 'hardening', 'medium', 'IDC integration, SSO configuration', '0d7a85c264609429110fb9634a078b6e308acd11c678e2d5c33614e303f98f9b'),
    'aws_resolver_managed_domain_lists_block': ('resolver_firewall', 'hardening', 'medium', 'Resolver DNS Firewall blocks managed domain lists', 'de4fbd45c2e3d8d2d54b496528ca4da39a6a9477e8b4490ca3550cadf31365e2'),
    'aws_inspector_cvss_version': ('inspector_finding', 'hardening', 'medium', 'Vulnerability scoring records the required CVSS version', '95fe0aba9215005f2e2a43c5340538996030da86184a8e164037b8ab71140896'),
    'aws_incident_workflow_sla': ('securityhub_finding', 'hardening', 'high', 'Critical findings enter an incident workflow promptly', '8271cee8695e7568bce915d8bef561bd07a5af1ab2cd0806289442f6d06b81e0'),
    'aws.pci.vpc.antispoofing_ingress': ('network_firewall_policy', 'network', 'medium', 'Internet ingress drops spoofed internal sources', '9c82183a7ece986278857364c38a913bcf9e097c0553ea96b93c5dd6bb9a18f5'),
    'aws.pci.kms.enclave_attestation_events': ('cloudtrail_event', 'hardening', 'high', 'Enclave attestation events use approved images', '26ccb4af2310aae4959626216ccc21232e91a8ec8dbdae08b1fa5127c43e1a7b'),
    'aws.pci.iam.policy_arn_attachment': ('iam_identity', 'hardening', 'medium', 'Required IAM policy ARN is attached to identities', 'dee037052186fc293093eb04f6ba5f18282bf8467280df73dbd3c0f7092f6e55'),
    'aws_cis_backup_recovery_point_isolation': ('backup_recovery_point', 'hardening', 'high', 'Backup recovery points have isolated protected copies', 'd769efd76c7231836980c395748317abdb8ba3c8dd32b77348135cbb927c3330'),
    'aws_cis_lightsail_ssm_patch_compliance': ('lightsail_instance', 'hardening', 'high', 'Lightsail guest patch state is compliant', '9a786b9563524fffcfc9eaca1756ed166821a6ad76a9d4a06832a91fc188e01f'),
}
PROPOSED_SPEC_SHA256 = {cid: spec[4] for cid, spec in SPECS.items()}
_SCOPE = re.compile(r'^([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9])$')
_ARN = re.compile(r'^arn:aws(?:-[a-z0-9-]+)?:[^:]+:[^:]*:[0-9]{12}:.+$')


def _inventory(item, index, kind, *, global_kind=False):
    context = get(index, 'context', dict)
    if get(context, 'provider', str) != 'aws':
        raise Unavailable('AWS provider authority unavailable')
    scope = get(context, 'scope', str)
    match = (re.fullmatch(r'([0-9]{12})/(global)', scope) if global_kind and scope.endswith('/global')
             else _SCOPE.fullmatch(scope))
    if not match:
        raise Unavailable('AWS account/Region scope unavailable')
    account, region = match.groups()
    envelopes = get(index, 'collections', dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable('single collection envelope unavailable: ' + kind)
    envelope = envelopes[0]
    expected_scope = account + '/global' if global_kind else scope
    if get(envelope, 'type', str) != kind or get(envelope, 'scope', str) != expected_scope:
        raise Unavailable('foreign collection scope: ' + kind)
    rows = complete_items(index, kind)
    declared = get(envelope, 'items', list)
    wrappers = get(index, kind, list)
    if (len(rows) != len(declared) or len(rows) != len(wrappers) or
            (get(envelope, 'status', str) == 'empty') != (len(rows) == 0)):
        raise Unavailable('inconsistent scoped inventory: ' + kind)
    for row, declared_row, wrapper in zip(rows, declared, wrappers):
        if (row != declared_row or get(wrapper, 'type', str) != kind or
                get(wrapper, 'scope', str) != expected_scope or
                get(row, 'AccountId', str) != account or
                (not global_kind and get(row, 'Region', str) != region)):
            raise Unavailable('malformed or foreign scoped fact: ' + kind)
    identity = get(item, 'id', str)
    ids = [get(row, 'id', str) for row in rows]
    if not identity or len(ids) != len(set(ids)) or ids.count(identity) != 1 or rows[ids.index(identity)] != item:
        raise Unavailable('resource absent, duplicated, or changed in inventory')
    return account, region


def _rows(index, kind, scope):
    envelopes = get(index, 'collections', dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable('complete dependency collection unavailable: ' + kind)
    envelope = envelopes[0]
    if get(envelope, 'type', str) != kind or get(envelope, 'scope', str) != scope:
        raise Unavailable('foreign dependency scope: ' + kind)
    rows = complete_items(index, kind)
    declared = get(envelope, 'items', list)
    wrappers = get(index, kind, list)
    if (len(declared) != len(rows) or len(wrappers) != len(rows) or
            (get(envelope, 'status', str) == 'empty') != (len(rows) == 0)):
        raise Unavailable('dependency inventory mismatch: ' + kind)
    for row, stated, wrapper in zip(rows, declared, wrappers):
        if (row != stated or get(wrapper, 'type', str) != kind or
                get(wrapper, 'scope', str) != scope or
                get(wrapper, 'data', dict) != row):
            raise Unavailable('foreign or inconsistent dependency fact: ' + kind)
    return rows


def _nonempty(value, name):
    if not isinstance(value, str) or not value:
        raise Unavailable('missing or malformed ' + name)
    return value


def _setting(index, name, expected=str):
    context = get(index, 'context', dict)
    if 'settings' in context:
        settings = get(context, 'settings', dict)
    else:
        settings = get(get(context, 'metadata', dict), 'parameters', dict)
    return get(settings, name, expected)


def _time(value):
    if not isinstance(value, str):
        raise Unavailable('malformed timestamp')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise Unavailable('malformed timestamp') from exc
    if parsed.tzinfo is None:
        raise Unavailable('timestamp lacks timezone')
    return parsed.astimezone(timezone.utc)


def _net(value):
    try:
        return ip_network(_nonempty(value, 'CIDR'), strict=False)
    except ValueError as exc:
        raise Unavailable('malformed CIDR') from exc


def _register(cid, dependencies, evaluator):
    kind, category, severity, title, _ = SPECS[cid]
    register(cid, 'aws', category if category != 'compliance' else 'hardening', kind,
             title, severity, 'CM-6', 'Review and correct the signed AWS control.',
             dependencies=dependencies)(evaluator)
    if category == 'compliance':
        CHECKS[-1] = replace(CHECKS[-1], category=category)


def cloudtrail_region(item, index):
    account, region = _inventory(item, index, 'aws_region')
    if get(item, 'RegionName', str) != region:
        return unknown('region identity mismatch')
    if get(item, 'Enabled', bool) is False:
        return 'NOT_APPLICABLE', {'reason': 'Region is not enabled'}
    regions = _rows(index, 'aws_region', account + '/' + region)
    if any(get(row, 'RegionName', str) != region for row in regions):
        raise Unavailable('Region inventory differs from scope')
    trails = _rows(index, 'cloudtrail_account_inventory', account + '/global')
    active = []
    for trail in trails:
        arn = get(trail, 'TrailARN', str)
        if get(trail, 'AccountId', str) != account or not arn.startswith('arn:'):
            raise Unavailable('foreign trail')
        home = get(trail, 'HomeRegion', str)
        multi = get(trail, 'IsMultiRegionTrail', bool)
        logging = get(trail, 'Status.IsLogging', bool)
        if logging and (multi or home == region):
            active.append(arn)
    return result(not active, region=region, covering_trails=active)


def bedrock_policy(item, index):
    account, region = _inventory(item, index, 'bedrock_automated_reasoning_policy')
    if '_metadata_projection' in item:
        from ..collectors.aws_bedrock_reasoning_native import assess
        return assess(item, account, region)
    app = _nonempty(get(item, 'ApplicationId', str), 'application ID')
    guardrail = _nonempty(get(item, 'GuardrailIdentifier', str), 'guardrail binding')
    version = _nonempty(get(item, 'GuardrailVersion', str), 'guardrail version')
    arn = get(item, 'AutomatedReasoningPolicyArn', str)
    if not arn:
        return result(True, application_id=app, guardrail=guardrail, version=version, reason='no policy attached')
    status = get(item, 'PolicyStatus', str)
    if status not in {'ACTIVE', 'INACTIVE', 'DELETING', 'FAILED'}:
        return unknown('unrecognized automated reasoning policy status')
    return result(status != 'ACTIVE', application_id=app, policy_arn=arn, policy_status=status)


def control_tower(item, index):
    account, _ = _inventory(item, index, 'control_tower_landing_zone')
    org = _nonempty(get(item, 'OrganizationId', str), 'organization ID')
    accounts = get(item, 'InScopeAiAccountIds', list)
    if not accounts or any(not isinstance(x, str) or not re.fullmatch(r'[0-9]{12}', x) for x in accounts):
        raise Unavailable('AI account-to-organization linkage unavailable')
    if account not in accounts:
        return 'NOT_APPLICABLE', {'reason': 'audited account is outside the linked AI organization'}
    zones = list_of_objects(get(item, 'LandingZones', list))
    statuses = []
    for zone in zones:
        _nonempty(get(zone, 'Arn', str), 'landing zone ARN')
        status = get(zone, 'Status', str)
        if status not in {'ACTIVE', 'PROCESSING', 'FAILED', 'DELETING'}:
            raise Unavailable('unrecognized landing zone status')
        statuses.append(status)
    return result('ACTIVE' not in statuses, organization_id=org, landing_zone_statuses=statuses)


def identity_center(item, index):
    account, _ = _inventory(item, index, 'identity_center')
    if get(item, 'AuditedAccountId', str) != account:
        raise Unavailable('identity center account mismatch')
    instances = list_of_objects(get(item, 'Instances', list))
    enabled_assignment = False
    for instance in instances:
        _nonempty(get(instance, 'InstanceArn', str), 'InstanceArn')
        _nonempty(get(instance, 'IdentityStoreId', str), 'IdentityStoreId')
        for assignment in list_of_objects(get(instance, 'AccountAssignments', list)):
            if get(assignment, 'AccountId', str) != account:
                raise Unavailable('foreign account assignment')
            _nonempty(get(assignment, 'PrincipalId', str), 'PrincipalId')
            status = get(assignment, 'UserStatus', str)
            if status not in {'ENABLED', 'DISABLED'}:
                raise Unavailable('unknown identity-store user status')
            if status == 'ENABLED':
                enabled_assignment = True
    return result(not enabled_assignment, account_id=account, instance_count=len(instances), enabled_assignment=enabled_assignment)


def resolver_firewall(item, index):
    _inventory(item, index, 'resolver_firewall')
    vpc = _nonempty(get(item, 'VpcId', str), 'VPC ID')
    if not get(item, 'Designated', bool):
        return 'NOT_APPLICABLE', {'vpc_id': vpc, 'reason': 'VPC is not designated'}
    approved = get(item, 'ApprovedManagedDomainListIds', list)
    if not approved or any(not isinstance(x, str) or not x for x in approved):
        raise Unavailable('approved managed domain list inventory unavailable')
    associations = list_of_objects(get(item, 'Associations', list))
    covered = set()
    ambiguous_filtering = False
    restricted_filtering = False
    for assoc in associations:
        if get(assoc, 'VpcId', str) != vpc:
            raise Unavailable('foreign VPC association')
        status = get(assoc, 'Status', str)
        if status not in {'COMPLETE', 'CREATING', 'UPDATING', 'DELETING', 'FAILED'}:
            raise Unavailable('unknown DNS Firewall association status')
        for rule in list_of_objects(get(assoc, 'Rules', list)):
            list_id = _nonempty(get(rule, 'FirewallDomainListId', str), 'domain list ID')
            action = get(rule, 'Action', str)
            if action not in {'BLOCK', 'ALLOW', 'ALERT'}:
                raise Unavailable('unknown DNS Firewall action')
            # Membership alone cannot prove blocking: ALLOW and ALERT also
            # terminate evaluation, including when they shadow a later BLOCK.
            # The legacy fact shape lacks a complete ordered-domain matcher,
            # so conservatively withhold PASS for mixed actions or restricted
            # query/redirect semantics, even if their lists appear unrelated.
            if action != 'BLOCK':
                ambiguous_filtering = True
            if 'Qtype' in rule or rule.get('FirewallDomainRedirectionAction', 'INSPECT_REDIRECTION_DOMAIN') != 'INSPECT_REDIRECTION_DOMAIN':
                restricted_filtering = True
            # Asynchronous rules may not enforce yet even when their group
            # association is COMPLETE. Synchronous rules may omit Status.
            if 'Status' in rule and rule['Status'] != 'COMPLETE':
                restricted_filtering = True
            if status == 'COMPLETE' and action == 'BLOCK':
                covered.add(list_id)
    if restricted_filtering:
        return unknown('DNS query types or domain redirection require a complete native matcher')
    missing = sorted(set(approved) - covered)
    if not missing and ambiguous_filtering:
        return unknown('ordered DNS Firewall actions require a complete native matcher')
    return result(bool(missing), vpc_id=vpc, missing_managed_lists=missing)


def inspector_cvss(item, index):
    _inventory(item, index, 'inspector_finding')
    version = _nonempty(_setting(index, 'approved_cvss_version'), 'approved CVSS version')
    status = get(item, 'status', str)
    finding_type = get(item, 'type', str)
    if status not in {'ACTIVE', 'SUPPRESSED', 'CLOSED'} or finding_type not in {'PACKAGE_VULNERABILITY', 'CODE_VULNERABILITY', 'NETWORK_REACHABILITY'}:
        return unknown('unrecognized Inspector finding state or type')
    if status != 'ACTIVE' or finding_type != 'PACKAGE_VULNERABILITY':
        return 'NOT_APPLICABLE', {'reason': 'finding is not an active package vulnerability'}
    cvss = list_of_objects(get(item, 'packageVulnerabilityDetails.cvss', list))
    matching = False
    for score in cvss:
        row_version = _nonempty(get(score, 'version', str), 'CVSS version')
        base = get(score, 'baseScore')
        if isinstance(base, bool) or not isinstance(base, (int, float)) or not math.isfinite(base) or not 0 <= base <= 10:
            raise Unavailable('malformed CVSS baseScore')
        matching |= row_version == version
    return result(not matching, finding_arn=get(item, 'findingArn', str), approved_version=version)


def incident_sla(item, index):
    _inventory(item, index, 'securityhub_finding')
    hours = _setting(index, 'approved_response_hours', None)
    if isinstance(hours, bool) or not isinstance(hours, (int, float)) or not math.isfinite(hours) or hours <= 0:
        raise Unavailable('approved response window unavailable')
    capture = _time(get(get(index, 'context', dict), 'created_at', str))
    label = get(item, 'Severity.Label', str)
    if label not in {'INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
        return unknown('unrecognized Security Hub severity')
    if label not in {'HIGH', 'CRITICAL'}:
        return 'NOT_APPLICABLE', {'reason': 'finding is not HIGH or CRITICAL'}
    created = _time(get(item, 'CreatedAt', str))
    updated = _time(get(item, 'UpdatedAt', str))
    status = get(item, 'Workflow.Status', str)
    if (status not in {'NEW', 'NOTIFIED', 'RESOLVED', 'SUPPRESSED'}
            or updated < created or updated > capture or capture < created):
        return unknown('malformed finding timeline or workflow status')
    from peaso.collectors.aws_wave_semantics_native import PROFILE, workflow_sla_from_history
    scope = get(get(index, 'context', dict), 'scope', str)
    if 'securityhub_finding_history' not in get(index, 'collections', dict):
        if capture < created + timedelta(hours=hours):
            return 'NOT_APPLICABLE', {'reason': 'response window has not elapsed; no observed response timing certified'}
        return unknown('Security Hub workflow transition history is required; UpdatedAt is not a workflow timestamp')
    histories = _rows(index, 'securityhub_finding_history', scope)
    # The approved identities are operator policy, not observed cloud facts.
    actors = _setting(index, 'approved_response_identity_arns', list)
    matches = [row for row in histories if get(row, 'id', str) == get(item, 'Id', str)]
    if len(matches) != 1:
        return unknown('single scoped Security Hub finding history unavailable')
    history = matches[0]
    account, region = _inventory(item, index, 'securityhub_finding')
    if (get(item, 'AwsAccountId', str) != account
            or get(history, 'ProductArn', str) != get(item, 'ProductArn', str)
            or get(history, 'AccountId', str) != account
            or get(history, 'Region', str) != region
            or _time(get(history, 'CreatedAt', str)) != created
            or get(history, '_metadata_projection', str) != PROFILE
            or _time(get(history, 'capture_at', str)) != capture):
        return unknown('Security Hub finding history identity or capture horizon mismatch')
    assessment = workflow_sla_from_history(item, get(history, 'Records', list),
        history_complete=get(history, 'complete', bool), capture_at=history['capture_at'],
        response_hours=hours, authorized_response_identities=actors)
    if assessment['status'] == 'UNKNOWN':
        return unknown(assessment['reason'])
    if assessment['status'] == 'NOT_APPLICABLE':
        return 'NOT_APPLICABLE', {'reason': assessment['reason']}
    return result(assessment['status'] == 'FAIL', finding_id=get(item, 'Id', str),
                  response_at=assessment.get('first_response_at'),
                  response_status=assessment.get('first_response_status'),
                  semantics='Security Hub history and operator-approved actor; external incident handling unverified',
                  reason=assessment['reason'])


def antispoofing(item, index):
    _inventory(item, index, 'network_firewall_policy')
    if not get(item, 'InternetFacing', bool):
        return 'NOT_APPLICABLE', {'reason': 'policy is not internet facing'}
    protected = get(item, 'ProtectedInternalCidrs', list)
    cde = get(item, 'CdeCidrs', list)
    if not protected or not cde:
        raise Unavailable('protected CIDR or CDE inventory unavailable')
    sources, destinations = [_net(x) for x in protected], [_net(x) for x in cde]
    rules = list_of_objects(get(item, 'OrderedIngressRules', list))
    parsed = []
    priorities = set()
    for rule in rules:
        priority = get(rule, 'Priority', int)
        if priority < 0 or priority in priorities:
            raise Unavailable('malformed rule ordering')
        priorities.add(priority)
        action = get(rule, 'Action', str)
        if action not in {'DROP', 'PASS'}:
            raise Unavailable('unsupported ingress action')
        parsed.append((priority, action, _net(get(rule, 'SourceCidr', str)), _net(get(rule, 'DestinationCidr', str)), get(rule, 'FromInternet', bool)))
    parsed.sort()
    for source in sources:
        for dest in destinations:
            covering_drop = None
            partial_drop_seen = False
            uncertain_overlap = False
            for priority, action, src, dst, internet in parsed:
                if not internet or source.version != src.version or dest.version != dst.version:
                    continue
                if source.subnet_of(src) and dest.subnet_of(dst):
                    if action == 'PASS' and (covering_drop is None or priority < covering_drop):
                        if partial_drop_seen:
                            return unknown('partial prior DROP coverage prevents PASS-order proof')
                        return result(True, protected_cidr=str(source), cde_cidr=str(dest), passing_rule_priority=priority)
                    if action == 'DROP' and covering_drop is None:
                        covering_drop = priority
                elif source.overlaps(src) and dest.overlaps(dst):
                    if action == 'PASS' and covering_drop is None and not partial_drop_seen:
                        return result(True, protected_cidr=str(source), cde_cidr=str(dest), passing_rule_priority=priority)
                    if action == 'DROP' and covering_drop is None:
                        partial_drop_seen = True
                    uncertain_overlap = True
            if covering_drop is None:
                if uncertain_overlap:
                    return unknown('partial CIDR overlap prevents complete rule-order proof')
                return result(True, protected_cidr=str(source), cde_cidr=str(dest), reason='no covering DROP rule')
    return result(False, protected_cidrs=[str(x) for x in sources], cde_cidrs=[str(x) for x in destinations])


def enclave_events(item, index):
    _inventory(item, index, 'cloudtrail_event')
    source = get(item, 'EventSource', str)
    attestation = get(item, 'IsEnclaveAttestation', bool)
    if source != 'kms.amazonaws.com' and attestation:
        return unknown('attestation flag conflicts with event source')
    if source != 'kms.amazonaws.com' or not attestation:
        return 'NOT_APPLICABLE', {'reason': 'event is not a KMS enclave attestation'}
    golden = _setting(index, 'approved_golden_pcrs', dict)
    if not golden:
        raise Unavailable('approved golden PCR measurements unavailable')
    pcrs = get(item, 'AttestationPcrs', dict)
    if not pcrs:
        raise Unavailable('attestation PCR measurements unavailable')
    for key, value in pcrs.items():
        _nonempty(key, 'PCR index')
        _nonempty(value, 'PCR value')
        if not re.fullmatch(r'[0-9a-fA-F]+', value):
            raise Unavailable('malformed PCR hex measurement')
        approved = golden.get(key)
        if (not isinstance(approved, list) or not approved or
                any(not isinstance(x, str) or not re.fullmatch(r'[0-9a-fA-F]+', x) for x in approved)):
            raise Unavailable('golden PCR set incomplete')
        if set(value) == {'0'} or value.lower() not in {x.lower() for x in approved}:
            return result(True, event_id=get(item, 'EventId', str), pcr=key, observed=value)
    if set(pcrs) != set(golden):
        return unknown('approved PCR indices absent from attestation')
    return result(False, event_id=get(item, 'EventId', str), checked_pcrs=sorted(pcrs))


def iam_attachment(item, index):
    account, _ = _inventory(item, index, 'iam_identity', global_kind=True)
    kind = get(item, 'IdentityType', str)
    if kind not in {'USER', 'GROUP', 'ROLE'}:
        return unknown('unrecognized IAM identity type')
    arn = get(item, 'Arn', str)
    if not _ARN.fullmatch(arn) or arn.split(':')[4] != account:
        raise Unavailable('foreign IAM identity ARN')
    target = _nonempty(_setting(index, 'required_policy_arn'), 'required policy ARN')
    if not re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:iam::(?:aws|[0-9]{12}):policy/[A-Za-z0-9+=,.@_/-]+', target):
        raise Unavailable('malformed policy ARN parameter')
    if target.split(':')[1]!=arn.split(':')[1] or target.split(':')[4] not in ('aws',account):
        raise Unavailable('required IAM policy belongs to another account or partition')
    attached = list_of_objects(get(item, 'AttachedManagedPolicies', list))
    arns = [_nonempty(get(policy, 'PolicyArn', str), 'attached PolicyArn') for policy in attached]
    if len(arns) != len(set(arns)):
        raise Unavailable('duplicate managed policy attachments')
    return result(target not in arns, identity_arn=arn, required_policy_arn=target)


def backup_isolation(item, index):
    _inventory(item, index, 'backup_recovery_point')
    arn = get(item, 'RecoveryPointArn', str)
    if not _ARN.fullmatch(arn):
        raise Unavailable('malformed recovery point ARN')
    encrypted = get(item, 'IsEncrypted', bool)
    if not encrypted:
        return result(True, recovery_point_arn=arn, reason='unencrypted recovery point')
    lock_required = _setting(index, 'backup_policy_requires_locked_copies', bool)
    vault = get(item, 'Vault', dict)
    if get(vault, 'BackupVaultName', str) != get(item, 'BackupVaultName', str):
        raise Unavailable('vault identity mismatch')
    locked = get(vault, 'Locked', bool)
    if lock_required and not locked:
        return result(True, recovery_point_arn=arn, reason='required Vault Lock inactive')
    offline = get(item, 'IndependentOfflineCopyEvidence', bool)
    if not offline:
        return unknown('independent offline copy evidence does not prove isolation', recovery_point_arn=arn)
    return result(False, recovery_point_arn=arn, vault_locked=locked, offline_copy_evidence=True)


def lightsail_patch(item, index):
    _inventory(item, index, 'lightsail_instance')
    arn = get(item, 'arn', str)
    if not _ARN.fullmatch(arn):
        raise Unavailable('malformed Lightsail ARN')
    match = get(item, 'SsmMatch', dict)
    if get(match, 'Verified', bool) is not True or get(match, 'LightsailArn', str) != arn:
        raise Unavailable('reliable Lightsail-to-SSM match unavailable')
    instance_id = _nonempty(get(match, 'InstanceId', str), 'SSM instance ID')
    patch = get(item, 'PatchState', dict)
    if get(patch, 'InstanceId', str) != instance_id:
        raise Unavailable('SSM patch state identity mismatch')
    counts = {}
    for field in ('MissingCount', 'FailedCount', 'InstalledRejectedCount'):
        count = get(patch, field, int)
        if count < 0:
            raise Unavailable('negative patch count')
        counts[field] = count
    return result(any(counts.values()), lightsail_arn=arn, ssm_instance_id=instance_id, **counts)


_EVALUATORS = {
    'aws_g6_cloudtrail_region_logging_trail_present': (cloudtrail_region, ['aws_region', 'cloudtrail_account_inventory']),
    'aws_bedrock_automated_reasoning_policy_attached': (bedrock_policy, ['bedrock_automated_reasoning_policy']),
    'aws_controltower_landing_zone_active': (control_tower, ['control_tower_landing_zone']),
    'aws_identity_center_sso_configured': (identity_center, ['identity_center']),
    'aws_resolver_managed_domain_lists_block': (resolver_firewall, ['resolver_firewall']),
    'aws_inspector_cvss_version': (inspector_cvss, ['inspector_finding']),
    'aws_incident_workflow_sla': (incident_sla, ['securityhub_finding', 'securityhub_finding_history']),
    'aws.pci.vpc.antispoofing_ingress': (antispoofing, ['network_firewall_policy']),
    'aws.pci.kms.enclave_attestation_events': (enclave_events, ['cloudtrail_event']),
    'aws.pci.iam.policy_arn_attachment': (iam_attachment, ['iam_identity']),
    'aws_cis_backup_recovery_point_isolation': (backup_isolation, ['backup_recovery_point']),
    'aws_cis_lightsail_ssm_patch_compliance': (lightsail_patch, ['lightsail_instance']),
}
for _cid, (_evaluator, _dependencies) in _EVALUATORS.items():
    _register(_cid, _dependencies, _evaluator)
