"""Signed AWS compliance predicates over complete, scope-bound snapshot facts."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from fnmatch import fnmatchcase
import json
import re

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get

IDS = (
    'aws_ssm_application_inventory_fresh', 'aws_ssm_endpoint_device_compliance',
    'aws_ssm_removable_storage_policy_compliance', 'aws_ssm_software_allowlist_compliance',
    'aws_ssm_software_inventory_enumeration', 'aws_incident_evidence_retention',
    'aws_log_archive_immutable', 'aws_s3_delete_lifecycle',
    'aws_sensitive_data_rest_access_controls', 'aws_siem_log_immutable_archive',
    'aws_guardduty_high_finding_alert', 'aws_guardduty_siem_forwarding',
    'aws_incident_automated_containment', 'aws_inspector_findings_metric_export',
    'aws_securityhub_critical_findings_alert',
)
_ACCOUNT_REGION = re.compile(r'^[0-9]{12}/[a-z]{2}(?:-[a-z]+)+-[0-9]$')
_ARN = re.compile(r'^arn:aws(?:-[a-z0-9-]+)?:[a-z0-9-]+:[a-z0-9-]*:[0-9]{0,12}:.+$')


def _scope(index):
    context = get(index, 'context', dict)
    if get(context, 'provider', str) != 'aws':
        raise Unavailable('AWS provider authority unavailable')
    scope = get(context, 'scope', str)
    if not _ACCOUNT_REGION.fullmatch(scope):
        raise Unavailable('AWS account/Region scope unavailable')
    return scope


def _rows(index, kind):
    scope = _scope(index)
    collections = get(index, 'collections', dict)
    envelopes = collections.get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable('single scoped inventory unavailable: ' + kind)
    envelope = envelopes[0]
    if not isinstance(envelope, dict) or envelope.get('type', kind) != kind:
        raise Unavailable('inventory kind mismatch: ' + kind)
    if envelope.get('scope') != scope:
        if not (envelope.get('global') is True and envelope.get('account_id') == scope.split('/')[0]):
            raise Unavailable('foreign inventory scope: ' + kind)
    rows = complete_items(index, kind)
    wrappers = index.get(kind)
    if not isinstance(wrappers, list) or len(wrappers) != len(rows):
        raise Unavailable('projected inventory cardinality mismatch: ' + kind)
    for wrapper, row in zip(wrappers, rows):
        if (not isinstance(wrapper, dict) or wrapper.get('type', kind) != kind or
                wrapper.get('scope') != envelope.get('scope') or wrapper.get('data') != row):
            raise Unavailable('foreign or malformed projected inventory row: ' + kind)
    if envelope.get('status') == 'empty' and rows:
        raise Unavailable('nonempty inventory marked empty: ' + kind)
    if 'items' in envelope and envelope['items'] != rows:
        raise Unavailable('inventory envelope differs from projected rows: ' + kind)
    return rows


def _subject(item, index, kind, field):
    rows = _rows(index, kind)
    key = get(item, field, str)
    if not key or sum(get(row, field, str) == key for row in rows) != 1:
        raise Unavailable('resource missing or ambiguous in scoped inventory')
    match = next(row for row in rows if row[field] == key)
    if match != item:
        raise Unavailable('resource differs from collected inventory')
    return key


def _inputs(index):
    return get(get(get(index, 'context', dict), 'metadata', dict), 'compliance_inputs', dict)


def _string_set(index, field, *, allow_empty=False):
    values = get(_inputs(index), field, list)
    if (not allow_empty and not values) or any(not isinstance(x, str) or not x for x in values) or len(values) != len(set(values)):
        raise Unavailable('malformed or empty approved input: ' + field)
    return set(values)


def _arn_set(index, field, *, allow_empty=False):
    values = _string_set(index, field, allow_empty=allow_empty)
    if any(not _ARN.fullmatch(value) for value in values):
        raise Unavailable('malformed approved ARN input: ' + field)
    return values


def _text(index, field):
    value = get(_inputs(index), field, str)
    if not value:
        raise Unavailable('empty approved input: ' + field)
    return value


def _positive_int(index, field):
    value = get(_inputs(index), field, int)
    if value <= 0:
        raise Unavailable('invalid approved input: ' + field)
    return value


def _time(value):
    if not isinstance(value, str):
        raise Unavailable('timestamp unavailable')
    try:
        instant = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise Unavailable('malformed timestamp') from exc
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise Unavailable('timestamp lacks timezone')
    return instant


def _ssm(item, index):
    instance_id = _subject(item, index, 'ssm_managed_instance', 'InstanceId')
    if not re.fullmatch(r'(?:i-[0-9a-f]{8,17}|mi-[0-9a-f]{8,17})', instance_id):
        raise Unavailable('malformed SSM instance ID')
    return instance_id


def _list_fact(item, field, entries):
    fact = get(item, field, dict)
    if get(fact, 'collection_status', str) not in ('collected', 'empty'):
        raise Unavailable(field + ' read incomplete')
    rows = get(fact, entries, list)
    if fact['collection_status'] == 'empty' and rows:
        raise Unavailable(field + ' empty/read conflict')
    if any(not isinstance(x, dict) for x in rows):
        raise Unavailable('malformed ' + field + ' entries')
    return rows


def _association_items(item):
    fact = get(item, 'AssociationCompliance', dict)
    if get(fact, 'source_operation', str) != 'ssm:ListComplianceItems':
        raise Unavailable('per-association SSM source unavailable')
    rows = _list_fact(item, 'AssociationCompliance', 'items')
    seen = set()
    for row in rows:
        typ, association_id, status = get(row, 'ComplianceType', str), get(row, 'Id', str), get(row, 'Status', str)
        if not typ or not association_id or status not in ('COMPLIANT', 'NON_COMPLIANT') or (typ, association_id) in seen:
            raise Unavailable('malformed or duplicate SSM compliance item')
        seen.add((typ, association_id))
    return rows


def _application_entries(item):
    fact = get(item, 'ApplicationInventory', dict)
    if get(fact, 'source_operation', str) != 'ssm:ListInventoryEntries' or get(fact, 'TypeName', str) != 'AWS:Application':
        raise Unavailable('AWS:Application inventory source unavailable')
    rows = _list_fact(item, 'ApplicationInventory', 'Entries')
    for row in rows:
        if not get(row, 'Name', str) or not get(row, 'Version', str):
            raise Unavailable('malformed application identity')
    return rows


def _designated(item, index, field):
    bucket = _subject(item, index, 's3_bucket', 'Name')
    designated = _string_set(index, field)
    if bucket not in designated:
        return bucket, False
    return bucket, True


def _detail(item, field):
    value = get(item, field, dict)
    status = get(value, 'collection_status', str)
    if status not in ('collected', 'empty'):
        raise Unavailable(field + ' read incomplete')
    return value, status == 'empty'


def _lock_state(item):
    version, _ = _detail(item, 'Versioning')
    lock, absent = _detail(item, 'ObjectLock')
    version_status = version.get('Status')
    if version_status not in (None, 'Enabled', 'Suspended'):
        raise Unavailable('unrecognized versioning status')
    if absent:
        return False, False, None
    config = get(lock, 'ObjectLockConfiguration', dict)
    enabled = get(config, 'ObjectLockEnabled', str)
    if enabled != 'Enabled':
        raise Unavailable('unrecognized Object Lock state')
    rule = config.get('Rule')
    retention = get(rule, 'DefaultRetention', dict) if rule is not None else None
    if retention is not None:
        mode = get(retention, 'Mode', str)
        if mode not in ('GOVERNANCE', 'COMPLIANCE'):
            raise Unavailable('unrecognized retention mode')
        days = retention.get('Days')
        years = retention.get('Years')
        if (type(days) is not int or days <= 0) and (type(years) is not int or years <= 0):
            raise Unavailable('malformed retention period')
    return version_status == 'Enabled', True, retention


def _event_pattern(rule):
    if 'EventPattern' not in rule:
        schedule = rule.get('ScheduleExpression')
        if isinstance(schedule, str) and schedule:
            return {'source': ['__schedule_only__']}
        raise Unavailable('EventBridge EventPattern unavailable')
    pattern = get(rule, 'EventPattern')
    if isinstance(pattern, str):
        try:
            pattern = json.loads(pattern)
        except ValueError as exc:
            raise Unavailable('malformed EventBridge EventPattern') from exc
    if not isinstance(pattern, dict):
        raise Unavailable('malformed EventBridge EventPattern')
    return pattern


def _exact_field(pattern, field, value):
    entries = pattern.get(field)
    if entries is None:
        return True  # unconstrained EventBridge field covers the value
    if not isinstance(entries, list) or not entries:
        raise Unavailable('unsupported EventBridge pattern: ' + field)
    if any(not isinstance(x, str) for x in entries):
        raise Unavailable('unsupported EventBridge pattern: ' + field)
    return value in entries


def _rule_rows(index):
    rows = _rows(index, 'eventbridge_rule')
    names = set()
    for row in rows:
        name = get(row, 'Name', str)
        bus = get(row, 'EventBusName', str)
        state = get(row, 'State', str)
        if not name or not bus or (bus, name) in names or state not in ('ENABLED', 'DISABLED'):
            raise Unavailable('malformed EventBridge rule inventory')
        names.add((bus, name))
        _event_pattern(row)
        targets = _list_fact(row, 'Targets', 'items')
        ids = set()
        for target in targets:
            target_id, arn = get(target, 'Id', str), get(target, 'Arn', str)
            if not target_id or target_id in ids or not _ARN.fullmatch(arn):
                raise Unavailable('malformed EventBridge target')
            ids.add(target_id)
    return rows


def _matches(rule, source, detail_type):
    pattern = _event_pattern(rule)
    return _event_match(pattern, source, detail_type)


def _targets(rule):
    return [get(target, 'Arn', str) for target in _list_fact(rule, 'Targets', 'items')]


def _event_scope(item, index):
    scope = get(item, 'scope', str)
    if scope != _scope(index):
        raise Unavailable('event scope differs from snapshot context')
    return _rule_rows(index)


def _register(check_id, kind, title, severity, category, remediation, dependencies, *, target='resource'):
    def decorator(function):
        register(check_id, 'aws', category if category != 'compliance' else 'hardening', kind,
                 title, severity, 'CM-6', remediation, dependencies=dependencies, target=target)(function)
        if category == 'compliance':
            CHECKS[-1] = replace(CHECKS[-1], category=category)
        return function
    return decorator


@_register('aws_ssm_application_inventory_fresh', 'ssm_managed_instance', 'EC2 software inventory is fresh', 'medium', 'hardening', 'Enable SSM Inventory application collection for every running instance.', ['instance', 'ssm_managed_instance'], target='scope')
def application_inventory_fresh(item, index):
    if get(item, 'scope', str) != _scope(index):
        raise Unavailable('foreign SSM scope')
    instances, managed = _rows(index, 'instance'), _rows(index, 'ssm_managed_instance')
    now = _time(get(get(index, 'context', dict), 'created_at', str))
    by_id = {}
    for row in managed:
        instance_id = get(row, 'InstanceId', str)
        if instance_id in by_id or not instance_id:
            raise Unavailable('duplicate or malformed managed instance')
        by_id[instance_id] = row
    running = []
    instance_ids = set()
    for row in instances:
        instance_id = get(row, 'InstanceId', str)
        state = get(row, 'State.Name', str)
        if state not in ('pending', 'running', 'shutting-down', 'terminated', 'stopping', 'stopped') or not instance_id or instance_id in instance_ids:
            raise Unavailable('malformed EC2 instance identity or state')
        instance_ids.add(instance_id)
        if state == 'running':
            running.append(instance_id)
    if not running:
        return 'NOT_APPLICABLE', {'reason': 'no running EC2 instance in complete inventory'}
    missing, stale = [], []
    for instance_id in running:
        row = by_id.get(instance_id)
        if row is None:
            missing.append(instance_id)
            continue
        entries = _application_entries(row)
        if not entries:
            stale.append(instance_id)
            continue
        captures = [_time(get(entry, 'CaptureTime', str)) for entry in entries]
        if any(not timedelta(0) <= now - captured <= timedelta(hours=24) for captured in captures):
            stale.append(instance_id)
    return result(bool(missing or stale), unmanaged_instance_ids=sorted(missing), stale_inventory_instance_ids=sorted(stale), running_count=len(running))


@_register('aws_ssm_endpoint_device_compliance', 'ssm_managed_instance', 'Managed endpoint security baseline is compliant', 'medium', 'hardening', 'Bring each endpoint online in SSM and remediate the failed approved Association compliance items.', ['ssm_managed_instance'])
def endpoint_device_compliance(item, index):
    instance_id = _ssm(item, index)
    endpoints = _string_set(index, 'endpoint_instance_ids')
    associations = _string_set(index, 'approved_association_ids')
    if instance_id not in endpoints:
        return 'NOT_APPLICABLE', {'reason': 'outside approved endpoint inventory', 'instance_id': instance_id}
    status = get(item, 'PingStatus', str)
    if status not in ('Online', 'ConnectionLost', 'Inactive'):
        raise Unavailable('unrecognized SSM ping status')
    rows = _association_items(item)
    by_id = {row['Id']: row['Status'] for row in rows if row['ComplianceType'] == 'Association'}
    missing = associations - by_id.keys()
    noncompliant = {key for key in associations if by_id.get(key) == 'NON_COMPLIANT'}
    return result(status != 'Online' or bool(missing or noncompliant), instance_id=instance_id, ping_status=status, missing_association_ids=sorted(missing), noncompliant_association_ids=sorted(noncompliant))


@_register('aws_ssm_removable_storage_policy_compliance', 'ssm_managed_instance', 'Managed host removable-media restriction is compliant', 'medium', 'hardening', 'Run the named SSM State Manager removable-media association on each scoped managed instance and remediate failures until ComplianceItems.Status=COMPLIANT.', ['ssm_managed_instance'])
def removable_storage_compliance(item, index):
    instance_id = _ssm(item, index)
    managed = _string_set(index, 'managed_instance_ids')
    association = _text(index, 'removable_media_association_id')
    if instance_id not in managed:
        return 'NOT_APPLICABLE', {'reason': 'outside approved managed host scope', 'instance_id': instance_id}
    status = get(item, 'PingStatus', str)
    if status not in ('Online', 'ConnectionLost', 'Inactive'):
        raise Unavailable('unrecognized SSM ping status')
    rows = _association_items(item)
    matching = [row for row in rows if row['ComplianceType'] == 'Association' and row['Id'] == association]
    return result(status != 'Online' or not matching or matching[0]['Status'] != 'COMPLIANT', instance_id=instance_id, ping_status=status, association_id=association)


@_register('aws_ssm_software_allowlist_compliance', 'ssm_managed_instance', 'Managed EC2 software follows approved allowlist', 'medium', 'hardening', 'Remove or replace AWS:Application packages whose (Name, Version) pair is outside the approved allowlist.', ['ssm_managed_instance'])
def software_allowlist(item, index):
    instance_id = _ssm(item, index)
    managed = _string_set(index, 'managed_instance_ids')
    raw = get(_inputs(index), 'allowed_packages', list)
    if any(not isinstance(row, dict) or not isinstance(row.get('Name'), str) or not row['Name'] or not isinstance(row.get('Version'), str) or not row['Version'] for row in raw):
        raise Unavailable('malformed package allowlist')
    allowed = {(row['Name'], row['Version']) for row in raw}
    if len(allowed) != len(raw):
        raise Unavailable('duplicate approved package')
    if instance_id not in managed:
        return 'NOT_APPLICABLE', {'reason': 'outside approved managed host scope', 'instance_id': instance_id}
    entries = _application_entries(item)
    unauthorized = sorted({(row['Name'], row['Version']) for row in entries} - allowed)
    return result(bool(unauthorized), instance_id=instance_id, unapproved_packages=[{'Name': name, 'Version': version} for name, version in unauthorized])


@_register('aws_ssm_software_inventory_enumeration', 'ssm_managed_instance', 'Software Discovery', 'medium', 'compliance', 'Restrict ssm:GetInventory and ssm:ListInventoryEntries to approved reader principals and investigate unauthorized CloudTrail events.', ['ssm_managed_instance', 'ssm_inventory_read_event'], target='scope')
def software_inventory_enumeration(item, index):
    if get(item, 'scope', str) != _scope(index):
        raise Unavailable('foreign SSM scope')
    _rows(index, 'ssm_managed_instance')
    readers = _arn_set(index, 'approved_inventory_reader_arns')
    rows = _rows(index, 'ssm_inventory_read_event')
    bad = []
    ids = set()
    for row in rows:
        event_id = get(row, 'EventId', str)
        name = get(row, 'EventName', str)
        source = get(row, 'EventSource', str)
        actor = get(row, 'userIdentity.arn', str)
        success = get(row, 'success', bool)
        if not event_id or event_id in ids or name not in ('GetInventory', 'ListInventoryEntries') or source != 'ssm.amazonaws.com' or not _ARN.fullmatch(actor):
            raise Unavailable('malformed SSM inventory read event')
        ids.add(event_id)
        if success and actor not in readers:
            bad.append(event_id)
    return result(bool(bad), unauthorized_event_ids=sorted(bad), observed_event_count=len(rows), semantics='Complete collected management-event history only; no claim about older events')


@_register('aws_incident_evidence_retention', 's3_bucket', 'Incident evidence is retained immutably', 'medium', 'hardening', 'Enable versioning and S3 Object Lock default retention on the designated incident-evidence bucket for the approved evidence period.', ['s3_bucket'])
def incident_evidence_retention(item, index):
    bucket, applicable = _designated(item, index, 'incident_evidence_bucket_names')
    minimum = _positive_int(index, 'evidence_retention_days')
    if not applicable:
        return 'NOT_APPLICABLE', {'reason': 'not an approved incident evidence bucket', 'bucket': bucket}
    versioned, locked, retention = _lock_state(item)
    days = retention.get('Days', 0) + retention.get('Years', 0) * 365 if retention else 0
    return result(not (versioned and locked and days >= minimum), bucket=bucket, retention_days_lower_bound=days, required_days=minimum)


@_register('aws_log_archive_immutable', 's3_bucket', 'CloudTrail archives have effective immutable retention', 'high', 'hardening', 'Enable Object Lock default retention and versioning on log archive buckets.', ['s3_bucket', 'cloudtrail'])
def log_archive_immutable(item, index):
    bucket = _subject(item, index, 's3_bucket', 'Name')
    trails = _rows(index, 'cloudtrail')
    destinations = set()
    for trail in trails:
        name = get(trail, 'S3BucketName', str)
        if not name:
            raise Unavailable('CloudTrail destination unavailable')
        destinations.add(name)
    if bucket not in destinations:
        return 'NOT_APPLICABLE', {'reason': 'not a CloudTrail destination bucket', 'bucket': bucket}
    versioned, locked, retention = _lock_state(item)
    return result(not (versioned and locked and retention is not None), bucket=bucket, has_default_retention=retention is not None)


@_register('aws_s3_delete_lifecycle', 's3_bucket', 'Customer-data buckets have deletion lifecycle rules', 'high', 'hardening', 'Add Enabled S3 lifecycle rules with Expiration.Days and NoncurrentVersionExpiration.NoncurrentDays within the approved deletion period.', ['s3_bucket'])
def s3_delete_lifecycle(item, index):
    bucket, applicable = _designated(item, index, 'customer_data_bucket_names')
    maximum = _positive_int(index, 'approved_deletion_days')
    if not applicable:
        return 'NOT_APPLICABLE', {'reason': 'not an approved customer-data bucket', 'bucket': bucket}
    lifecycle, absent = _detail(item, 'Lifecycle')
    rules = [] if absent else get(lifecycle, 'Rules', list)
    if any(not isinstance(rule, dict) for rule in rules):
        raise Unavailable('malformed lifecycle rules')
    qualifying = []
    for rule in rules:
        state = get(rule, 'Status', str)
        if state not in ('Enabled', 'Disabled'):
            raise Unavailable('unrecognized lifecycle rule state')
        if state != 'Enabled':
            continue
        current = rule.get('Expiration', {}).get('Days') if isinstance(rule.get('Expiration'), dict) else None
        noncurrent = rule.get('NoncurrentVersionExpiration', {}).get('NoncurrentDays') if isinstance(rule.get('NoncurrentVersionExpiration'), dict) else None
        if current is None or noncurrent is None:
            continue
        if type(current) is not int or type(noncurrent) is not int or current <= 0 or noncurrent <= 0:
            raise Unavailable('malformed lifecycle day threshold')
        # Only an all-object filter proves all object versions are covered.
        filter_value = rule.get('Filter')
        if filter_value not in (None, {}) or rule.get('Prefix') not in (None, ''):
            continue
        if current <= maximum and noncurrent <= maximum:
            qualifying.append(rule.get('ID', 'unnamed'))
    return result(not qualifying, bucket=bucket, qualifying_rule_ids=qualifying, approved_deletion_days=maximum)


def _policy_principals(statement):
    principal = get(statement, 'Principal')
    if principal == '*':
        return {'*'}
    if isinstance(principal, str):
        return {principal}
    if not isinstance(principal, dict) or set(principal) != {'AWS'}:
        raise Unavailable('unsupported S3 policy principal')
    values = principal['AWS']
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list) or not values or any(not isinstance(x, str) or not x for x in values):
        raise Unavailable('malformed S3 policy principal')
    return set(values)


@_register('aws_sensitive_data_rest_access_controls', 's3_bucket', 'Sensitive stored data has access controls', 'medium', 'hardening', 'Enable all four S3 Public Access Block flags and remove unapproved s3:GetObject Allow principals from sensitive bucket policies.', ['s3_bucket'])
def sensitive_data_rest_access_controls(item, index):
    bucket, applicable = _designated(item, index, 'sensitive_bucket_names')
    approved = _arn_set(index, 'approved_sensitive_principal_arns', allow_empty=True)
    if not applicable:
        return 'NOT_APPLICABLE', {'reason': 'not an inventoried sensitive bucket', 'bucket': bucket}
    block, block_absent = _detail(item, 'PublicAccessBlock')
    policy, policy_absent = _detail(item, 'Policy')
    flags = ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')
    configured = {} if block_absent else get(block, 'PublicAccessBlockConfiguration', dict)
    values = {}
    for flag in flags:
        value = False if block_absent else get(configured, flag, bool)
        if type(value) is not bool:
            raise Unavailable('malformed Public Access Block flag')
        values[flag] = value
    statements = [] if policy_absent else get(get(policy, 'Policy', dict), 'Statement')
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or any(not isinstance(x, dict) for x in statements):
        raise Unavailable('malformed S3 policy statements')
    bad = []
    for number, statement in enumerate(statements):
        effect = get(statement, 'Effect', str)
        if effect not in ('Allow', 'Deny'):
            raise Unavailable('unrecognized S3 policy effect')
        if effect != 'Allow':
            continue
        actions = get(statement, 'Action')
        actions = [actions] if isinstance(actions, str) else actions
        if not isinstance(actions, list) or any(not isinstance(x, str) for x in actions):
            raise Unavailable('malformed S3 action')
        if not any(fnmatchcase('s3:getobject', action.lower()) for action in actions):
            continue
        if 'NotPrincipal' in statement or 'NotAction' in statement or 'NotResource' in statement or 'Condition' in statement:
            raise Unavailable('conditional or inverted S3 policy requires separate evaluation')
        resources = get(statement, 'Resource')
        resources = [resources] if isinstance(resources, str) else resources
        if not isinstance(resources, list) or not resources or any(not isinstance(x, str) or not x for x in resources):
            raise Unavailable('malformed S3 policy Resource')
        own_object = re.compile(r'^arn:aws(?:-us-gov|-cn)?:s3:::' + re.escape(bucket) + r'/')
        if not any(resource == '*' or own_object.match(resource) for resource in resources):
            if any('*' in resource or '?' in resource for resource in resources):
                raise Unavailable('wildcard S3 policy Resource coverage unresolved')
            continue
        if _policy_principals(statement) - approved:
            bad.append(number)
    return result(not all(values.values()) or bool(bad), bucket=bucket, disabled_block_flags=sorted(flag for flag in flags if not values[flag]), unapproved_statement_indexes=bad)


@_register('aws_siem_log_immutable_archive', 's3_bucket', 'SIEM log archive has immutable retention', 'medium', 'hardening', 'Enable S3 Object Lock and versioning on the SIEM archive bucket, with DefaultRetention.Days at least the approved minimum.', ['s3_bucket'])
def siem_log_immutable_archive(item, index):
    bucket, applicable = _designated(item, index, 'siem_archive_bucket_names')
    minimum = _positive_int(index, 'siem_archive_minimum_days')
    if not applicable:
        return 'NOT_APPLICABLE', {'reason': 'not an approved SIEM archive bucket', 'bucket': bucket}
    versioned, locked, retention = _lock_state(item)
    days = retention.get('Days') if retention else None
    return result(not (versioned and locked and type(days) is int and days >= minimum), bucket=bucket, retention_days=days, required_days=minimum)


def _event_match(pattern, source, detail_type, *, detail_path=None, detail_value=None):
    if not (_exact_field(pattern, 'source', source) and _exact_field(pattern, 'detail-type', detail_type)):
        return False
    if set(pattern) - {'source', 'detail-type', 'detail'}:
        raise Unavailable('additional EventBridge filters prevent full event-class coverage')
    if detail_path:
        detail = pattern.get('detail', {})
        if not isinstance(detail, dict):
            raise Unavailable('malformed EventBridge detail pattern')
        for part in detail_path[:-1]:
            if set(detail) - {part}:
                raise Unavailable('additional EventBridge detail filters prevent full coverage')
            detail = detail.get(part, {})
            if not isinstance(detail, dict):
                raise Unavailable('malformed EventBridge detail pattern')
        if set(detail) - {detail_path[-1]}:
            raise Unavailable('additional EventBridge detail filters prevent full coverage')
        if not _exact_field(detail, detail_path[-1], detail_value):
            return False
    elif pattern.get('detail') not in (None, {}):
        raise Unavailable('additional EventBridge detail filters prevent full coverage')
    return True


def _guardduty_high(pattern):
    if not (_exact_field(pattern, 'source', 'aws.guardduty') and _exact_field(pattern, 'detail-type', 'GuardDuty Finding')):
        return False
    if set(pattern) - {'source', 'detail-type', 'detail'}:
        raise Unavailable('additional EventBridge filters prevent high-finding coverage')
    detail = pattern.get('detail', {})
    if not isinstance(detail, dict):
        raise Unavailable('malformed GuardDuty detail pattern')
    if set(detail) - {'severity'}:
        raise Unavailable('additional GuardDuty detail filters prevent high-finding coverage')
    severity = detail.get('severity')
    if severity is None:
        return True
    if not isinstance(severity, list) or len(severity) != 1 or not isinstance(severity[0], dict):
        raise Unavailable('unsupported GuardDuty severity pattern')
    numeric = severity[0].get('numeric')
    if numeric not in (['>=', 7], ['>', 6], ['>=', 0], ['>', 0]):
        raise Unavailable('GuardDuty high severity coverage not proven')
    return True


@_register('aws_guardduty_high_finding_alert', 'eventbridge_rule', 'GuardDuty HIGH findings trigger alert', 'medium', 'hardening', 'Create an enabled EventBridge rule for GuardDuty finding severity >= 7 and attach the approved notification target.', ['eventbridge_rule'], target='scope')
def guardduty_high_finding_alert(item, index):
    rows = _event_scope(item, index)
    matched = [row for row in rows if row['State'] == 'ENABLED' and _guardduty_high(_event_pattern(row))]
    good = [row['Name'] for row in matched if _targets(row)]
    return result(not good, matching_rule_names=sorted(good), semantics='Configured EventBridge notification target only; delivery unverified')


@_register('aws_guardduty_siem_forwarding', 'eventbridge_rule', 'GuardDuty findings forwarded to SIEM', 'medium', 'hardening', 'Target the approved SIEM pipeline from the enabled EventBridge rule matching GuardDuty findings.', ['eventbridge_rule'], target='scope')
def guardduty_siem_forwarding(item, index):
    rows = _event_scope(item, index)
    approved = _arn_set(index, 'approved_siem_forwarder_arns')
    good = []
    for row in rows:
        if row['State'] != 'ENABLED':
            continue
        pattern = _event_pattern(row)
        if _event_match(pattern, 'aws.guardduty', 'GuardDuty Finding'):
            detail = pattern.get('detail', {})
            if not isinstance(detail, dict):
                raise Unavailable('malformed GuardDuty detail pattern')
            if 'severity' in detail:
                continue
            if approved.intersection(_targets(row)):
                good.append(row['Name'])
    return result(not good, matching_rule_names=sorted(good), semantics='Target declaration only; SIEM receipt unverified')


@_register('aws_incident_automated_containment', 'eventbridge_rule', 'Security incidents trigger containment automation', 'medium', 'hardening', 'Attach the approved SSM Automation document ARN as the target of each enabled incident EventBridge rule.', ['eventbridge_rule'], target='scope')
def incident_automated_containment(item, index):
    rows = _event_scope(item, index)
    classes = get(_inputs(index), 'approved_incident_event_classes', list)
    if not classes or any(not isinstance(x, dict) for x in classes):
        raise Unavailable('approved incident classes unavailable')
    uncovered = []
    seen = set()
    for event_class in classes:
        source, detail_type, arn = (get(event_class, key, str) for key in ('source', 'detail_type', 'document_arn'))
        if not source or not detail_type or not _ARN.fullmatch(arn) or (source, detail_type) in seen:
            raise Unavailable('malformed approved incident class')
        seen.add((source, detail_type))
        if not any(row['State'] == 'ENABLED' and _matches(row, source, detail_type) and arn in _targets(row) for row in rows):
            uncovered.append({'source': source, 'detail_type': detail_type})
    return result(bool(uncovered), uncovered_event_classes=uncovered, semantics='Configured automation target only; executions and containment effectiveness unverified')


@_register('aws_inspector_findings_metric_export', 'eventbridge_rule', 'Inspector findings feed central metrics', 'medium', 'hardening', 'Route Inspector2 EC2 finding events to the approved central metric ingestion target via EventBridge.', ['eventbridge_rule'], target='scope')
def inspector_findings_metric_export(item, index):
    rows = _event_scope(item, index)
    approved = _text(index, 'approved_metric_pipeline_arn')
    if not _ARN.fullmatch(approved):
        raise Unavailable('malformed approved metric pipeline ARN')
    good = [row['Name'] for row in rows if row['State'] == 'ENABLED' and _event_match(_event_pattern(row), 'aws.inspector2', 'Inspector2 Finding', detail_path=('resources', 'type'), detail_value='AWS_EC2_INSTANCE') and approved in _targets(row)]
    return result(not good, matching_rule_names=sorted(good), semantics='Configured EventBridge target only; metric arrival unverified')


@_register('aws_securityhub_critical_findings_alert', 'eventbridge_rule', 'Security Hub CRITICAL finding alert', 'medium', 'hardening', 'Create an enabled EventBridge rule matching Security Hub imported CRITICAL findings and attach an SNS or incident target.', ['eventbridge_rule'], target='scope')
def securityhub_critical_findings_alert(item, index):
    rows = _event_scope(item, index)
    good = [row['Name'] for row in rows if row['State'] == 'ENABLED' and _event_match(_event_pattern(row), 'aws.securityhub', 'Security Hub Findings - Imported', detail_path=('findings', 'Severity', 'Label'), detail_value='CRITICAL') and _targets(row)]
    return result(not good, matching_rule_names=sorted(good), semantics='Configured notification target only; delivery unverified')
