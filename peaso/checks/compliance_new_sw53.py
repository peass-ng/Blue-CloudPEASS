"""Signed GCP compliance checks over scoped, read-only snapshot evidence."""
from __future__ import annotations

META = {'gcp_c5_backup_remote_location': {'kind': 'sql_instance',
                                   'category': 'backup',
                                   'severity': 'medium',
                                   'title': 'Offsite backup location',
                                   'hint': 'Place the in-scope backup target in an approved separate '
                                           'failure region using the Cloud SQL or Storage backup '
                                           'destination setting.',
                                   'sha': '44f9ae1fcbd05d2d79d22eb2c5bbeff9ba66cb651bf15358a9787cebb3e55bf2'},
 'gcp_c5_restore_destination': {'kind': 'sql_instance',
                                'category': 'backup',
                                'severity': 'medium',
                                'title': 'Restore target access parity',
                                'hint': 'Restore Cloud SQL to an approved target, disable public IPv4 '
                                        'if absent on the source, and remove new public IAM grants.',
                                'sha': '489a05964f3f3aa345e68efacd3fd465994f1417200ed1ec278d6b47ed26c503'},
 'gcp_c5_restore_test': {'kind': 'sql_instance',
                         'category': 'backup',
                         'severity': 'medium',
                         'title': 'Cloud SQL restore test event',
                         'hint': 'Run and validate a Cloud SQL restore or clone test within 365 days; '
                                 'retain a successful operation record.',
                         'sha': 'bc278e450ceda0b95f15ce05354b73707fe39ed25921bd0dcb466c943dfc988c'},
 'gcp_c5_sql_backup_run': {'kind': 'sql_instance',
                           'category': 'backup',
                           'severity': 'medium',
                           'title': 'Recent successful Cloud SQL backup',
                           'hint': 'Enable automated Cloud SQL backups and correct backup schedules '
                                   'until a SUCCESSFUL run falls inside the approved RPO window.',
                           'sha': '64efff290cb9e0a049c36c1e21a2094dc77e8ef9eb9370c08ac9347074d27b6f'},
 'gcp.compute.os_patch_compliance': {'kind': 'instance',
                                     'category': 'hardening',
                                     'severity': 'high',
                                     'title': 'VM operating systems have current security patches',
                                     'hint': 'Apply outstanding OS Config security patches with a patch '
                                             'deployment and verify fresh VM inventory against the '
                                             'approved grace period.',
                                     'sha': '626d66df389fad108c4ff5756dab62e31e90cd05d884abbabcb6bb15dc001d54'},
 'gcp_c5_malware_telemetry': {'kind': 'instance',
                              'category': 'malware',
                              'severity': 'medium',
                              'title': 'VM malware protection inventory signal',
                              'hint': 'Install the approved VM protection agent through OS Config and '
                                      'verify its package appears in current guest inventory.',
                              'sha': 'c4574fd6dacef9c8cbe2cc53a1fcab073e6b3f65d06945122c739c3ec8ebaccc'},
 'gcp_c5_patch_deployment': {'kind': 'instance',
                             'category': 'patch_management',
                             'severity': 'medium',
                             'title': 'Compute VM patch deployment coverage',
                             'hint': 'Assign every in-scope VM an enabled recurring OS Config patch '
                                     'deployment and apply packages beyond the approved age.',
                             'sha': '33494a459016f1d7a5b0aef9b71b2a007d3749a9867205b8157006d4202e8761'},
 'gcp_c5_software_inventory': {'kind': 'instance',
                               'category': 'asset_management',
                               'severity': 'medium',
                               'title': 'Compute VM installed-software inventory',
                               'hint': 'Enable OS Config guest inventory for each in-scope VM and '
                                       'reconcile installed package names/versions with the software '
                                       'register.',
                               'sha': '5d700da584c7992e36e8fc0e029d574480ca4916e42bd6b1f555f183251d717b'},
 'gcp_compute_approved_packages': {'kind': 'instance',
                                   'category': 'vulnerability',
                                   'severity': 'medium',
                                   'title': 'VM contains unapproved installed software',
                                   'hint': 'Remove unapproved OS packages or pin them to approved '
                                           'version ranges using OS Config package management.',
                                   'sha': 'ff1af87f9f1dc0a6dc51b2568ecc11c969d28cf76bc314e599f48183b66495dc'},
 'gcp_compute_os_patch_compliance': {'kind': 'instance',
                                     'category': 'vulnerability',
                                     'severity': 'high',
                                     'title': 'VM security patches exceed approved SLA',
                                     'hint': 'Apply critical OS Config security updates within the '
                                             'approved SLA and refresh inventory and vulnerability '
                                             'reports.',
                                     'sha': '3d98981ed677d9a44cc339c524e705a5df0d6e5d9b8124d71511c4d520c4f0ce'},
 'gcp_c5_iam_change_timeliness': {'kind': 'iam_policy',
                                  'category': 'identity',
                                  'severity': 'medium',
                                  'title': 'IAM grant revocation timeliness',
                                  'hint': 'Remove IAM grants past the approved 48-hour or 14-day '
                                          'personnel-change deadline using the resource IAM policy '
                                          'editor.',
                                  'sha': '56fdc625b31d8bbc24b2f8572dd69f7cd10ab36c198c82c20f69ff468357f17b'},
 'gcp_c5_iam_conditions': {'kind': 'iam_policy',
                           'category': 'identity',
                           'severity': 'medium',
                           'title': 'Contextual IAM binding conditions',
                           'hint': 'Add a binding condition.expression covering the required time, '
                                   'resource or principal attributes to each contextual IAM grant.',
                           'sha': 'b6cd52900ea97ed2263a3181b0feeea862c23f71dccbd2dc97ee6e80b6ce2ffe'},
 'gcp_c5_iam_expiry': {'kind': 'iam_policy',
                       'category': 'identity',
                       'severity': 'medium',
                       'title': 'Privileged IAM binding expiry',
                       'hint': 'Add a request.time expiry condition to each privileged IAM binding that '
                               'requires a time limit.',
                       'sha': '017702d3c791cd415e1b1b4f16d4242ce7274dfd44a81b174f1aff1bfbc1c585'},
 'gcp.logging.access_transparency_entries': {'kind': 'project',
                                             'category': 'hardening',
                                             'severity': 'medium',
                                             'title': 'Access Transparency log signal is available',
                                             'hint': 'Enable Access Transparency for supported services '
                                                     'and retain its Cloud Logging entries; investigate '
                                                     'missing 30-day evidence manually.',
                                             'sha': 'bb2bbe32cffa23862441e31e60163ac71ed572a8de523586f0c05a9539db5cac'},
 'gcp_cloudsql_backup_failure_alert': {'kind': 'project',
                                       'category': 'backup',
                                       'severity': 'high',
                                       'title': 'Cloud SQL backup failures lack an alert',
                                       'hint': 'Create a Logging metric for failed Cloud SQL backup '
                                               'events and link it to an enabled Monitoring alert '
                                               'policy and channel.',
                                       'sha': '1b136117fa2d4fe85988f749cd7654433f701835de2c965c50f1e390b8f19c88'}}

from dataclasses import replace
from collections import Counter
import json
from datetime import datetime, timedelta, timezone
import re

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get


def _ctx(index):
    context = get(index, 'context', dict)
    if get(context, 'provider', str) != 'gcp':
        raise Unavailable('foreign provider')
    scope = get(context, 'scope', str)
    if not scope.startswith('projects/') or len(scope.split('/')) != 2:
        raise Unavailable('project scope unavailable')
    return context, scope


def _rows(index, kind):
    _, scope = _ctx(index)
    envelopes = get(get(index, 'collections', dict), kind, list)
    if not envelopes or any(get(e, 'scope', str) != scope or get(e, 'type', str) != kind for e in envelopes):
        raise Unavailable('foreign or absent collection scope')
    rows = complete_items(index, kind)
    declared = []
    for envelope in envelopes:
        payload = get(envelope, 'items', list)
        if get(envelope, 'status', str) == 'empty' and payload:
            raise Unavailable('empty collection contains resources')
        declared.extend(payload)
    if Counter(json.dumps(x, sort_keys=True, default=str) for x in declared) != Counter(
            json.dumps(x, sort_keys=True, default=str) for x in rows):
        raise Unavailable('collection items differ from resource index')
    for resource in get(index, kind, list):
        if get(resource, 'scope', str) != scope or get(resource, 'type', str) != kind:
            raise Unavailable('foreign resource scope')
    return rows


def _identity(row, kind):
    if kind == 'instance':
        return get(row, 'name', str)
    return get(row, 'name', str)


def _base(item, index, kind):
    rows = _rows(index, kind)
    ident = _identity(item, kind)
    matches = [row for row in rows if _identity(row, kind) == ident]
    if len(matches) != 1 or matches[0] != item:
        raise Unavailable('resource identity not unique in scoped inventory')
    return ident


def _policy(index):
    context, scope = _ctx(index)
    if 'policy' in context:
        return get(context, 'policy', dict)
    policy = get(get(context, 'metadata', dict), 'compliance_policy', dict)
    if get(policy, 'scope', str) != scope or get(policy, 'status', str) != 'collected':
        raise Unavailable('approved policy absent or foreign scope')
    return policy


def _time(value):
    if not isinstance(value, str):
        raise Unavailable('timestamp missing or malformed')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise Unavailable('malformed timestamp') from exc
    if parsed.tzinfo is None:
        raise Unavailable('timestamp timezone missing')
    return parsed.astimezone(timezone.utc)


def _now(index):
    context, _ = _ctx(index)
    return _time(get(context, 'created_at', str))


def _hours(policy, field):
    value = get(policy, field, int)
    if value <= 0:
        raise Unavailable('invalid approved duration')
    return value


def _scope(policy, field, ident):
    names = get(policy, field, list)
    if any(not isinstance(n, str) or not n for n in names) or len(names) != len(set(names)):
        raise Unavailable('malformed approved scope')
    return ident in names


def _joined(index, kind, key, ident):
    rows = _rows(index, kind)
    matches = [r for r in rows if get(r, key, str) == ident]
    if len(matches) > 1:
        raise Unavailable('duplicate joined fact')
    return matches[0] if matches else None


def _packages(inventory):
    packages = get(inventory, 'items.installedPackages', list)
    if any(not isinstance(p, dict) or not isinstance(p.get('name'), str) or not p['name'] or
           not isinstance(p.get('version'), str) or not p['version'] for p in packages):
        raise Unavailable('malformed installed package inventory')
    return packages


def _inventory(index, ident):
    inv = _joined(index, 'os_inventory', 'instanceName', ident)
    if inv is None:
        raise Unavailable('guest inventory absent')
    now = _now(index)
    at = _time(get(inv, 'updateTime', str))
    if at > now or now - at > timedelta(hours=24):
        raise Unavailable('guest inventory stale')
    return inv


def _na(reason):
    return 'NOT_APPLICABLE', {'reason': reason}


def _software(item, index):
    ident = _base(item, index, 'instance')
    policy = _policy(index)
    if not _scope(policy, 'vm_scope', ident):
        return _na('VM outside approved software scope')
    register = get(policy, 'approved_software_register', list)
    approved = {(get(x, 'name', str), get(x, 'version', str)) for x in register}
    inventory = _joined(index, 'os_inventory', 'instanceName', ident)
    if inventory is None:
        return result(True, instance=ident, reason='no guest inventory record in complete collection')
    now = _now(index)
    observed = _time(get(inventory, 'updateTime', str))
    if observed > now or now - observed > timedelta(hours=24):
        return result(True, instance=ident, reason='no current guest inventory record')
    packages = _packages(inventory)
    bad = sorted({(p['name'], p['version']) for p in packages} - approved)
    return result(bool(bad), instance=ident, unregistered_packages=bad)


def _allowed_version(version, rules):
    if version in rules:
        return True
    comparisons = [r for r in rules if isinstance(r, str) and r.startswith(('>=', '<=', '>', '<', '=='))]
    if any(not isinstance(r, str) or not r or '*' in r or r.startswith(('~', '^')) for r in rules):
        raise Unavailable('unrecognized approved package version rule')
    if not comparisons:
        return False
    if not re.fullmatch(r'\d+(?:\.\d+)*', version):
        raise Unavailable('package version cannot be compared to approved range')
    current = tuple(map(int, version.split('.')))
    for rule in comparisons:
        pieces = rule.split(',')
        satisfied = True
        for piece in pieces:
            match = re.fullmatch(r'(>=|<=|>|<|==)\s*(\d+(?:\.\d+)*)', piece.strip())
            if not match:
                raise Unavailable('unrecognized approved version range')
            target = tuple(map(int, match.group(2).split('.')))
            width = max(len(current), len(target))
            left, right = current + (0,) * (width - len(current)), target + (0,) * (width - len(target))
            op = match.group(1)
            satisfied = satisfied and {'>=': left >= right, '<=': left <= right,
                                        '>': left > right, '<': left < right, '==': left == right}[op]
        if satisfied:
            return True
    return False


def _approved_packages(item, index):
    ident = _base(item, index, 'instance')
    policy = _policy(index)
    if not _scope(policy, 'vm_scope', ident):
        return _na('VM outside approved package scope')
    allowed = get(policy, 'approved_packages', dict)
    for name, versions in allowed.items():
        if not isinstance(name, str) or not isinstance(versions, list) or any(not isinstance(v, str) for v in versions):
            raise Unavailable('malformed package allowlist')
    packages = _packages(_inventory(index, ident))
    bad = sorted({(p['name'], p['version']) for p in packages if not _allowed_version(p['version'], allowed.get(p['name'], []))})
    return result(bool(bad), instance=ident, unapproved_packages=bad)


def _malware(item, index):
    ident = _base(item, index, 'instance')
    policy = _policy(index)
    required = get(policy, 'approved_agent_package_by_vm', dict)
    if ident not in required:
        return _na('no protection agent required by approved VM policy')
    agent = required[ident]
    if not isinstance(agent, str) or not agent:
        raise Unavailable('malformed approved agent name')
    packages = _packages(_inventory(index, ident))
    return result(not any(p['name'] == agent for p in packages), instance=ident, required_package=agent)


def _vulnerabilities(item, index, critical_only, sla_field):
    ident = _base(item, index, 'instance')
    if get(item, 'status', str) != 'RUNNING':
        return _na('VM is not RUNNING')
    policy = _policy(index)
    if not _scope(policy, 'vm_scope', ident):
        return _na('VM outside approved patch scope')
    grace = timedelta(hours=_hours(policy, sla_field))
    _packages(_inventory(index, ident))
    report = _joined(index, 'os_vulnerability_report', 'instanceName', ident)
    if report is None:
        raise Unavailable('vulnerability report absent')
    if report.get('native_model') == 'osconfig_v1':
        at = _time(get(report, 'updateTime', str))
        if at > _now(index) or _now(index) - at > timedelta(hours=24):
            raise Unavailable('native vulnerability report stale or future dated')
    findings = get(report, 'vulnerabilities', list)
    now = _now(index)
    overdue = []
    for finding in findings:
        severity = get(finding, 'severity', str)
        if severity not in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'):
            raise Unavailable('unknown vulnerability severity')
        if critical_only and severity != 'CRITICAL':
            continue
        for package in get(finding, 'items', list):
            available = get(package, 'availableInventoryItem', dict)
            name = get(available, 'name', str)
            published = _time(get(available, 'publishedTime', str))
            if not name or published > now:
                raise Unavailable('invalid available package age')
            if now - published > grace:
                overdue.append(name)
    return result(bool(overdue), instance=ident, overdue_packages=sorted(set(overdue)))


def _native_patch_applies(deployment, vm, index):
    state = get(deployment, 'state', str)
    if state == 'PAUSED':
        return False
    if state != 'ACTIVE':
        raise Unavailable('native patch state unresolved')
    if 'oneTimeSchedule' in deployment and 'recurringSchedule' not in deployment:
        return False
    schedule = get(deployment, 'recurringSchedule', dict)
    now = _now(index)
    if 'endTime' in schedule and _time(get(schedule, 'endTime', str)) <= now:
        return False
    if 'startTime' in schedule and _time(get(schedule, 'startTime', str)) > now:
        return False
    if get(schedule, 'frequency', str) not in ('DAILY', 'WEEKLY', 'MONTHLY'):
        raise Unavailable('native patch frequency unresolved')
    # Provider-computed next execution proves a configured active recurrence;
    # it never proves that patches have been successfully installed.
    if _time(get(schedule, 'nextExecuteTime', str)) <= now:
        raise Unavailable('native next execution stale')
    filt = get(deployment, 'instanceFilter', dict)
    if set(filt) - {'all', 'instances'}:
        raise Unavailable('native patch filter unsupported')
    if filt.get('all') is True and not filt.get('instances'):
        return True
    if filt.get('all') not in (None, False):
        raise Unavailable('native patch all filter malformed')
    names = get(filt, 'instances', list)
    zone = get(vm, 'zone', str).rsplit('/', 1)[-1]
    name = get(vm, 'name', str)
    _, scope = _ctx(index)
    allowed = {'zones/' + zone + '/instances/' + name,
               scope + '/zones/' + zone + '/instances/' + name,
               'https://www.googleapis.com/compute/v1/' + scope + '/zones/' + zone + '/instances/' + name}
    pattern = r'(?:zones/[a-z0-9-]+/instances/[a-z][a-z0-9-]*|' + re.escape(scope) + r'/zones/[a-z0-9-]+/instances/[a-z][a-z0-9-]*|https://www\.googleapis\.com/compute/v1/' + re.escape(scope) + r'/zones/[a-z0-9-]+/instances/[a-z][a-z0-9-]*)'
    if any(not isinstance(n, str) or not re.fullmatch(pattern, n) for n in names):
        raise Unavailable('native explicit VM filter malformed or foreign')
    return bool(allowed.intersection(names))


def _patch_deployment(item, index):
    ident = _base(item, index, 'instance')
    policy = _policy(index)
    if not _scope(policy, 'vm_scope', ident):
        return _na('VM outside approved patch scope')
    max_age = timedelta(hours=_hours(policy, 'approved_patch_age_hours'))
    packages = _packages(_inventory(index, ident))
    deployments = _rows(index, 'os_patch_deployment')
    applicable = []
    for deployment in deployments:
        if deployment.get('native_model') == 'osconfig_v1':
            if _native_patch_applies(deployment, item, index):
                applicable.append(get(deployment, 'name', str))
            continue
        enabled = get(deployment, 'enabled', bool)
        targets = get(deployment, 'instanceFilter.instanceNames', list)
        if any(not isinstance(n, str) for n in targets):
            raise Unavailable('malformed patch filter')
        schedule = get(deployment, 'recurringSchedule', dict)
        if enabled and ident in targets and get(schedule, 'active', bool):
            applicable.append(get(deployment, 'name', str))
    if not applicable:
        return result(True, instance=ident, applicable_deployments=[], reason='no enabled recurring patch deployment covers this VM')
    now = _now(index)
    overdue = []
    for package in packages:
        installed = _time(get(package, 'installTime', str))
        if installed > now:
            raise Unavailable('future package install time')
        if now - installed > max_age:
            overdue.append(package['name'])
    return result(not applicable or bool(overdue), instance=ident, applicable_deployments=applicable,
                  packages_over_age=sorted(set(overdue)))


def _sql(item, index):
    ident = _base(item, index, 'sql_instance')
    policy = _policy(index)
    if not _scope(policy, 'sql_scope', ident):
        return ident, policy, _na('SQL instance outside approved scope')
    return ident, policy, None


def _backup_run(item, index):
    ident, policy, na = _sql(item, index)
    if na:
        return na
    if get(item, 'instanceType', str) != 'CLOUD_SQL_INSTANCE':
        return _na('SQL instance is not primary')
    enabled = get(item, 'settings.backupConfiguration.enabled', bool)
    if not enabled:
        return result(True, instance=ident, reason='automated backups disabled')
    rpo = timedelta(hours=_hours(policy, 'approved_rpo_hours'))
    runs = _rows(index, 'sql_backup_run')
    now = _now(index)
    relevant = [r for r in runs if get(r, 'instanceName', str) == ident and get(r, 'type', str) == 'AUTOMATED']
    fresh = []
    for run in relevant:
        status = get(run, 'status', str)
        if status not in ('SUCCESSFUL', 'FAILED', 'RUNNING', 'PENDING'):
            raise Unavailable('unknown backup run status')
        if status == 'SUCCESSFUL':
            ended = _time(get(run, 'endTime', str))
            if ended <= now and now - ended <= rpo:
                fresh.append(run)
    return result(not fresh, instance=ident, successful_runs_in_rpo=len(fresh))


def _remote(item, index):
    ident, policy, na = _sql(item, index)
    if na:
        return na
    required = get(policy, 'approved_offsite_policy', bool)
    if not required:
        return _na('offsite separation not required by approved policy')
    source_region = get(item, 'region', str)
    targets = _rows(index, 'backup_target')
    related = [r for r in targets if get(r, 'sourceInstance', str) == ident]
    if not related:
        raise Unavailable('backup target join unavailable')
    regions = [get(r, 'failureRegion', str) for r in related]
    if any(not r for r in regions) or not source_region:
        raise Unavailable('backup failure region unavailable')
    return result(any(r == source_region for r in regions), instance=ident, target_regions=regions)


def _operations(index, source):
    rows = _rows(index, 'sql_operation')
    return [r for r in rows if get(r, 'sourceInstance', str) == source and
            get(r, 'operationType', str) in ('RESTORE_VOLUME', 'CLONE')]


def _restore_test(item, index):
    ident, policy, na = _sql(item, index)
    if na:
        return na
    targets = get(policy, 'approved_restore_test_targets', list)
    if any(not isinstance(t, str) for t in targets):
        raise Unavailable('malformed restore test scope')
    now = _now(index)
    valid = []
    for op in _operations(index, ident):
        if get(op, 'targetId', str) not in targets:
            continue
        if get(op, 'status', str) != 'DONE':
            continue
        if get(op, 'validated', bool) is not True:
            raise Unavailable('restore validation result unavailable')
        error = get(op, 'error', dict)
        if error:
            continue
        ended = _time(get(op, 'endTime', str))
        if ended <= now and now - ended <= timedelta(days=365):
            valid.append(op)
    return result(not valid, instance=ident, validated_restore_events=len(valid))


def _public_members(index, resource):
    policies = _rows(index, 'iam_policy')
    matches = [r for r in policies if get(r, 'name', str) == resource]
    if len(matches) != 1:
        raise Unavailable('source or target IAM policy unavailable')
    if get(matches[0], '_representation', str) != 'full':
        raise Unavailable('IAM policy representation not complete')
    members = set()
    for binding in get(matches[0], 'bindings', list):
        for member in get(binding, 'members', list):
            if not isinstance(member, str):
                raise Unavailable('malformed IAM member')
            if member in ('allUsers', 'allAuthenticatedUsers'):
                members.add(member)
    return members


def _restore_destination(item, index):
    ident, policy, na = _sql(item, index)
    if na:
        return na
    approved = get(policy, 'approved_restoration_instances', list)
    if any(not isinstance(t, str) for t in approved):
        raise Unavailable('malformed approved restore destinations')
    instances = {get(r, 'name', str): r for r in _rows(index, 'sql_instance')}
    source_public = get(item, 'settings.ipConfiguration.ipv4Enabled', bool)
    source_members = _public_members(index, ident)
    bad = []
    for op in _operations(index, ident):
        if get(op, 'status', str) != 'DONE' or get(op, 'error', dict):
            continue
        target_id = get(op, 'targetId', str)
        target = instances.get(target_id)
        if target is None:
            raise Unavailable('restore target instance not inventoried')
        target_public = get(target, 'settings.ipConfiguration.ipv4Enabled', bool)
        target_members = _public_members(index, target_id)
        if target_id not in approved or (target_public and not source_public) or target_members - source_members:
            bad.append(target_id)
    return result(bool(bad), instance=ident, unsafe_restore_targets=sorted(set(bad)))


def _iam(item, index):
    ident = _base(item, index, 'iam_policy')
    if get(item, '_representation', str) != 'full':
        raise Unavailable('IAM policy representation not complete')
    context, _ = _ctx(index)
    if get(context, 'inherited_iam_complete', bool) is not True:
        raise Unavailable('inherited IAM policy coverage incomplete')
    return ident, _policy(index), get(item, 'bindings', list)


def _binding_keys(bindings):
    for binding in bindings:
        role = get(binding, 'role', str)
        members = get(binding, 'members', list)
        if any(not isinstance(m, str) for m in members):
            raise Unavailable('malformed IAM binding members')
        yield binding, role, members


def _conditions(item, index):
    ident, policy, bindings = _iam(item, index)
    required = get(policy, 'required_condition_attributes', list)
    for row in required:
        get(row, 'resource', str); get(row, 'role', str); get(row, 'member', str)
        attrs = get(row, 'attributes', list)
        if not attrs or any(a not in ('request.time', 'resource.name', 'resource.type', 'principal.email') for a in attrs):
            raise Unavailable('unrecognized required condition attribute')
    bad = []
    seen = set()
    for binding, role, members in _binding_keys(bindings):
        expression = binding.get('condition', {}).get('expression') if isinstance(binding.get('condition', {}), dict) else None
        if expression is not None and not isinstance(expression, str):
            raise Unavailable('malformed IAM condition expression')
        for member in members:
            for row in required:
                if row['resource'] == ident and row['role'] == role and row['member'] == member:
                    seen.add((ident, role, member))
                    if not expression or any(attr not in expression for attr in row['attributes']):
                        bad.append((role, member))
    expected = {(r['resource'], r['role'], r['member']) for r in required if r['resource'] == ident}
    if expected - seen:
        raise Unavailable('required grant absent from bound IAM inventory')
    return result(bool(bad), policy=ident, bindings_missing_attributes=bad)


def _expiry(item, index):
    ident, policy, bindings = _iam(item, index)
    required = get(policy, 'expiring_privileged_grants', list)
    expected = {(get(r, 'resource', str), get(r, 'role', str), get(r, 'member', str)) for r in required}
    bad, seen = [], set()
    for binding, role, members in _binding_keys(bindings):
        condition = binding.get('condition', {})
        if not isinstance(condition, dict):
            raise Unavailable('malformed IAM binding condition')
        expression = condition.get('expression')
        if expression is not None and not isinstance(expression, str):
            raise Unavailable('malformed expiry expression')
        for member in members:
            key = (ident, role, member)
            if key in expected:
                seen.add(key)
                if not expression or 'request.time' not in expression:
                    bad.append((role, member))
                else:
                    expiry = re.fullmatch(r'\s*request\.time\s*<\s*timestamp\("([^"]+)"\)\s*', expression)
                    if expiry is None:
                        raise Unavailable('IAM expiry expression semantics unavailable')
                    _time(expiry.group(1))
    if {k for k in expected if k[0] == ident} - seen:
        raise Unavailable('required privileged grant absent from policy')
    return result(bool(bad), policy=ident, grants_without_expiry=bad)


def _timeliness(item, index):
    ident, policy, bindings = _iam(item, index)
    events = get(policy, 'personnel_changes', list)
    if get(policy, 'personnel_change_feed_complete', bool) is not True:
        raise Unavailable('personnel change feed incomplete')
    now = _now(index)
    retained = []
    grants = {(role, member) for _, role, members in _binding_keys(bindings) for member in members}
    for event in events:
        if get(event, 'resource', str) != ident:
            continue
        principal = get(event, 'principal', str)
        role = get(event, 'forbiddenRole', str)
        tier = get(event, 'tier', str)
        if tier not in ('privileged', 'other'):
            raise Unavailable('unrecognized personnel change tier')
        effective = _time(get(event, 'effectiveTime', str))
        if effective > now:
            raise Unavailable('future personnel change event')
        deadline = timedelta(hours=48 if tier == 'privileged' else 14 * 24)
        if now - effective > deadline and (role, principal) in grants:
            retained.append((principal, role))
    return result(bool(retained), policy=ident, overdue_grants=retained)


def _transparency(item, index):
    ident = _base(item, index, 'project')
    _, scope = _ctx(index)
    if ident != scope:
        raise Unavailable('project identity differs from scope')
    entries = _rows(index, 'access_transparency_entry')
    now = _now(index)
    suffix = '/logs/cloudaudit.googleapis.com%2Faccess_transparency'
    recent = 0
    for entry in entries:
        if get(entry, 'project', str) != scope:
            raise Unavailable('foreign Access Transparency entry')
        log_name = get(entry, 'logName', str)
        stamp = _time(get(entry, 'timestamp', str))
        if log_name.endswith(suffix) and stamp <= now and now - stamp <= timedelta(days=30):
            recent += 1
    return result(False, project=scope, recent_access_transparency_entries=recent) if recent else unknown('no recent Access Transparency entry; provider access may not have occurred')


def _backup_alert(item, index):
    ident = _base(item, index, 'project')
    _, scope = _ctx(index)
    if ident != scope:
        raise Unavailable('project identity differs from scope')
    metrics = _rows(index, 'logging_metric')
    alerts = _rows(index, 'monitoring_alert_policy')
    names = set()
    for metric in metrics:
        metric_id = get(metric, 'metricId', str)
        get(metric, 'filter', str)
        if get(metric, 'name', str) != scope + '/metrics/' + metric_id:
            raise Unavailable('foreign logging metric identity')
        if not metric_id or '/' in metric_id:
            raise Unavailable('malformed logging metric identity')
        if get(metric, 'filterMatchesFailedCloudSqlBackupRun', bool) and not get(metric, 'disabled', bool):
            names.add('logging.googleapis.com/user/' + metric_id)
    active = []
    for alert in alerts:
        if not get(alert, 'enabled', bool):
            continue
        for condition in get(alert, 'conditions', list):
            expression = get(condition, 'conditionThreshold.filter', str)
            clauses = [part.strip() for part in expression.split(' AND ')]
            matches = []
            for clause in clauses:
                metric_ref = re.fullmatch(r'metric\.type\s*=\s*"([^"]+)"', clause)
                resource_ref = re.fullmatch(r'resource\.type\s*=\s*"([^"]+)"', clause)
                if metric_ref:
                    matches.append(metric_ref.group(1))
                elif not resource_ref:
                    raise Unavailable('alert filter semantics unavailable')
            if len(matches) != 1:
                raise Unavailable('alert metric reference unavailable or ambiguous')
            if matches[0] in names:
                active.append(get(alert, 'name', str))
    return result(not active, project=scope, enabled_alert_policies=sorted(set(active)))


EVALUATORS = {
    'gcp_c5_software_inventory': _software,
    'gcp_compute_approved_packages': _approved_packages,
    'gcp_c5_malware_telemetry': _malware,
    'gcp.compute.os_patch_compliance': lambda i, x: _vulnerabilities(i, x, False, 'approved_patch_grace_hours'),
    'gcp_compute_os_patch_compliance': lambda i, x: _vulnerabilities(i, x, True, 'approved_patch_sla_hours'),
    'gcp_c5_patch_deployment': _patch_deployment,
    'gcp_c5_sql_backup_run': _backup_run,
    'gcp_c5_backup_remote_location': _remote,
    'gcp_c5_restore_test': _restore_test,
    'gcp_c5_restore_destination': _restore_destination,
    'gcp_c5_iam_conditions': _conditions,
    'gcp_c5_iam_expiry': _expiry,
    'gcp_c5_iam_change_timeliness': _timeliness,
    'gcp.logging.access_transparency_entries': _transparency,
    'gcp_cloudsql_backup_failure_alert': _backup_alert,
}
EXTRA = {
    'gcp_c5_software_inventory': ['os_inventory'],
    'gcp_compute_approved_packages': ['os_inventory'],
    'gcp_c5_malware_telemetry': ['os_inventory'],
    'gcp.compute.os_patch_compliance': ['os_inventory', 'os_vulnerability_report'],
    'gcp_compute_os_patch_compliance': ['os_inventory', 'os_vulnerability_report'],
    'gcp_c5_patch_deployment': ['os_inventory', 'os_patch_deployment'],
    'gcp_c5_sql_backup_run': ['sql_backup_run'],
    'gcp_c5_backup_remote_location': ['backup_target'],
    'gcp_c5_restore_test': ['sql_operation'],
    'gcp_c5_restore_destination': ['sql_operation', 'iam_policy'],
    'gcp_c5_iam_conditions': [], 'gcp_c5_iam_expiry': [],
    'gcp_c5_iam_change_timeliness': [],
    'gcp.logging.access_transparency_entries': ['access_transparency_entry'],
    'gcp_cloudsql_backup_failure_alert': ['logging_metric', 'monitoring_alert_policy'],
}
for _id, _meta in META.items():
    _category = _meta['category']
    _native = _category if _category in ('hardening', 'exposure', 'least_privilege', 'iam_graph', 'network') else 'hardening'
    def _evaluate(item, index, check_id=_id):
        return EVALUATORS[check_id](item, index)
    _evaluate.__name__ = _id.replace('.', '_')
    register(_id, 'gcp', _native, _meta['kind'], _meta['title'], _meta['severity'], 'CM-6',
             _meta['hint'], dependencies=[_meta['kind'], *EXTRA[_id]])(_evaluate)
    if _native != _category:
        CHECKS[-1] = replace(CHECKS[-1], category=_category)
