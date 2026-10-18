"""Signed GCP audit and Storage checks over complete, scoped snapshot facts."""
from __future__ import annotations

from datetime import datetime, timezone
import re

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, guard


# Digest of the exact ten-field entries in new-checks-gcp.json.
SPECS = {
    'gcp_logging_detect_t1110': ('audit_log', 'threat_detection', 'high', 'Suspicious authentication brute force', '5ffef6aa6a40ccb10a633064ac062b8411845ab63ac56f9c12710eb29df7aaf4'),
    'gcp_logging_detect_t1119': ('audit_log', 'threat_detection', 'medium', 'Suspicious automated data collection', '66e5fce6561ceca874fe845046ad37d6beffd75ee76852a0e8ae4957357aea5f'),
    'gcp_logging_detect_t1136': ('audit_log', 'threat_detection', 'high', 'Suspicious service account creation', 'd2782530ef565b6eefd57e53b5285ca696ae7d126e27115f16535d98333c6751'),
    'gcp_logging_detect_t1490': ('audit_log', 'threat_detection', 'high', 'Suspicious backup deletion or disablement', '5d5485a169748ae8c43f6b843eba284256c10af530934195441fa6192a2be70b'),
    'gcp_logging_detect_t1518': ('audit_log', 'threat_detection', 'medium', 'Suspicious software discovery', '6eff634e1b98101d1be3537c42555a6af3b46a8452e65144cbb06945f5c2e017'),
    'gcp_logging_detect_t1526': ('audit_log', 'threat_detection', 'medium', 'Suspicious cloud service discovery', '967532b78c4d80ad250b04f7600cc441f2c01a21084c6cb38306e3ad633d40de'),
    'gcp_logging_detect_t1546': ('audit_log', 'threat_detection', 'high', 'Suspicious event trigger creation', 'f3fa73c1b6b9996c10320ec67a0326cdcde64c33d410502e6736a9d5eee31c11'),
    'gcp_logging_detect_t1614': ('audit_log', 'threat_detection', 'medium', 'Suspicious region discovery', '5739c4716bfcc8d7ad27f321db17f2044e909315839c4209b92b52ce221fad4e'),
    'gcp_logging_detect_t1619': ('audit_log', 'threat_detection', 'medium', 'Suspicious storage object discovery', '31d35fd0ef4faddd8f9d0478d82b8e9f6e5a6b180741f6167f83092df5e7f94a'),
    'gcp_logging_detect_t1648': ('audit_log', 'threat_detection', 'high', 'Suspicious serverless execution', 'a2378cd131f703ad09dc392fd935080f6ce02fdd2fc02ef92f030016211c8a6b'),
    'gcp_logging_detect_t1651': ('audit_log', 'threat_detection', 'high', 'Suspicious cloud administration change', '669982d86f34cb0ff0ac6ba065f8db36e96fffa6334be656f084698711ce319d'),
    'gcp_c5_deletion_recoverability': ('bucket', 'data_lifecycle', 'medium', 'Cloud Storage recovery window after deletion', 'da1a5d6067d30edb69ba140dc6597340372a1762b770d5153c64081168185ffc'),
    'gcp_c5_log_retention': ('bucket', 'logging', 'medium', 'SIEM and audit log retention', '1742b3dd522ad1ca649bf125eacee39db8084cd7744b299efcac78b5f796254f'),
    'gcp_gcs_replication_status': ('bucket', 'availability', 'medium', 'Bucket replication topology or health is unavailable', '8ae750fe8a6c2df834bddb54382e72f560262969ed8b5ed2748ea7d448900b38'),
    'gcp_pci_bucket_157fb0c69361': ('bucket', 'exposure', 'high', 'Cloud Storage bucket has no public read grant', 'ac67fb9a740b240793b03f6439ce1f0e96b8bb7ed2edeaba4b79aeb06fcfee11'),
}
PROPOSED_SPEC_SHA256 = {key: spec[4] for key, spec in SPECS.items()}


def _time(value):
    if not isinstance(value, str):
        raise Unavailable('timestamp missing')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise Unavailable('invalid timestamp') from exc
    if parsed.tzinfo is None:
        raise Unavailable('timestamp lacks timezone')
    return parsed.astimezone(timezone.utc)


def _inventory(index, kind, item):
    context = get(index, 'context', dict)
    if get(context, 'provider', str) != 'gcp':
        raise Unavailable('foreign provider')
    scope = get(context, 'scope', str)
    if not re.fullmatch(r'projects/[A-Za-z0-9][A-Za-z0-9._-]*', scope):
        raise Unavailable('project scope missing')
    envs = get(index, 'collections', dict).get(kind)
    if not isinstance(envs, list) or len(envs) != 1:
        raise Unavailable('complete scoped collection missing')
    env = envs[0]
    if (not isinstance(env, dict) or env.get('type') != kind or env.get('scope') != scope or
            env.get('status') not in ('collected', 'empty')):
        raise Unavailable('incomplete or foreign collection')
    rows = complete_items(index, kind)
    wrapped = get(index, kind, list)
    listed = get(env, 'items', list)
    if env['status'] == 'empty' and rows:
        raise Unavailable('empty collection contains resources')
    if (rows != listed or len(wrapped) != len(rows) or any(
            not isinstance(w, dict) or w.get('type') != kind or w.get('scope') != scope or w.get('data') != row
            for w, row in zip(wrapped, rows))):
        raise Unavailable('collection projection mismatch')
    if sum(row == item for row in rows) != 1:
        raise Unavailable('subject missing or ambiguous')
    return context, env, rows


def _policy(context, key, expected):
    return get(get(context, 'metadata', dict), key, expected)


def _strings(values):
    if not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values) or len(values) != len(set(values)):
        raise Unavailable('malformed policy string list')
    return set(values)


def _audit(index, item):
    context, env, rows = _inventory(index, 'audit_log', item)
    coverage = get(env, 'audit_coverage', dict)
    if get(coverage, 'complete', bool) is not True or get(coverage, 'all_pages', bool) is not True:
        raise Unavailable('audit entry coverage incomplete')
    start, end = _time(get(coverage, 'start', str)), _time(get(coverage, 'end', str))
    if start > end:
        raise Unavailable('invalid audit coverage interval')
    normalized = []
    project = context['scope'].split('/', 1)[1]
    seen = set()
    for row in rows:
        identity = get(row, 'insertId', str)
        if not identity or identity in seen:
            raise Unavailable('audit identity missing or duplicated')
        seen.add(identity)
        log_name = get(row, 'logName', str)
        if not log_name.startswith(context['scope'] + '/logs/cloudaudit.googleapis.com%2F'):
            raise Unavailable('audit log provenance or project mismatch')
        if get(row, 'resource.labels.project_id', str) != project:
            raise Unavailable('foreign audit resource')
        timestamp = _time(get(row, 'timestamp', str))
        if not start <= timestamp <= end:
            raise Unavailable('audit event outside covered interval')
        method = get(row, 'protoPayload.methodName', str)
        principal = get(row, 'protoPayload.authenticationInfo.principalEmail', str)
        code = get(row, 'protoPayload.status.code', int)
        if not method or not principal or code < 0:
            raise Unavailable('malformed audit method, principal or status')
        normalized.append((timestamp, method, principal, code, row))
    return context, coverage, normalized


def _bursts(events, threshold, predicate, *, group_ip=False):
    groups = {}
    for timestamp, method, principal, code, row in events:
        if not predicate(method, code, row):
            continue
        ip = get(row, 'protoPayload.requestMetadata.callerIp', str) if group_ip else None
        if group_ip and not ip:
            raise Unavailable('caller IP missing')
        groups.setdefault((principal, ip), []).append(timestamp)
    for (principal, ip), times in groups.items():
        times.sort()
        left = 0
        for right, value in enumerate(times):
            while (value - times[left]).total_seconds() > 300:
                left += 1
            if right - left + 1 > threshold:
                return principal, ip, right - left + 1
    return None


_RATE_METHODS = {
    'gcp_logging_detect_t1119': lambda m: m.endswith('.List') or m.endswith('.Get'),
    'gcp_logging_detect_t1518': lambda m: m == 'osconfig.inventories.get',
    'gcp_logging_detect_t1526': lambda m: m == 'serviceusage.services.list',
    'gcp_logging_detect_t1614': lambda m: m in ('compute.regions.list', 'compute.zones.list'),
    'gcp_logging_detect_t1619': lambda m: m == 'storage.objects.list',
}
_ALLOW_METHODS = {
    'gcp_logging_detect_t1136': ('approved_identity_admins', {'google.iam.admin.v1.CreateServiceAccount'}),
    'gcp_logging_detect_t1546': ('approved_automation_admins', {'google.devtools.cloudbuild.v1.CloudBuild.CreateBuildTrigger', 'google.cloud.scheduler.v1.CloudScheduler.CreateJob'}),
    'gcp_logging_detect_t1648': ('approved_invokers', {'run.routes.invoke', 'cloudfunctions.functions.call'}),
    'gcp_logging_detect_t1651': ('approved_cloud_admins', {'SetIamPolicy', 'UpdateProject'}),
}


def _audit_check(check_id, item, index):
    context, coverage, events = _audit(index, item)
    if check_id == 'gcp_logging_detect_t1110':
        if get(coverage, 'authentication_events', bool) is not True:
            raise Unavailable('authentication audit logging unavailable')
        # The collector marks normalized authentication events explicitly; method
        # name alone cannot reliably identify every authentication operation.
        for _, _, _, _, row in events:
            get(row, 'authenticationEvent', bool)
        hit = _bursts(events, 9, lambda m, c, r: r['authenticationEvent'] and c != 0, group_ip=True)
    elif check_id in _RATE_METHODS:
        policy = 'approved_read_rate' if check_id.endswith('t1119') else 'approved_list_rate'
        limit = _policy(context, policy, int)
        if limit < 0:
            raise Unavailable('negative approved rate')
        hit = _bursts(events, limit, lambda m, c, r: c == 0 and _RATE_METHODS[check_id](m))
    elif check_id == 'gcp_logging_detect_t1490':
        approved = _strings(_policy(context, 'approved_backup_admins', list))
        hits = []
        for _, method, principal, code, row in events:
            if code != 0:
                continue
            relevant = method == 'cloudsql.backupRuns.delete'
            if method == 'cloudsql.instances.update':
                request = get(row, 'protoPayload.request', dict)
                try:
                    enabled = get(request, 'settings.backupConfiguration.enabled', bool)
                except Unavailable:
                    raise Unavailable('backup update request intent unavailable')
                relevant = enabled is False
            if relevant and principal not in approved:
                hits.append(principal)
        hit = (hits[0], None, 1) if hits else None
    else:
        policy, methods = _ALLOW_METHODS[check_id]
        approved = _strings(_policy(context, policy, list))
        if check_id == 'gcp_logging_detect_t1648':
            for _, method, _, code, row in events:
                if code == 0 and method in methods:
                    expected_type = 'cloud_run_revision' if method == 'run.routes.invoke' else 'cloud_function'
                    if get(row, 'resource.type', str) != expected_type:
                        raise Unavailable('serverless audit resource type mismatch')
        hits = [principal for _, method, principal, code, _ in events
                if code == 0 and method in methods and principal not in approved]
        hit = (hits[0], None, 1) if hits else None
    if hit:
        return result(True, principal=hit[0], caller_ip=hit[1], count=hit[2])
    return result(False, inspected_entries=len(events), interval=[coverage['start'], coverage['end']])


def _bucket(index, item):
    context, _, rows = _inventory(index, 'bucket', item)
    project = context['scope'].split('/', 1)[1]
    names = set()
    for row in rows:
        name = get(row, 'name', str)
        if not name or name in names:
            raise Unavailable('bucket identity missing or duplicated')
        names.add(name)
        if get(row, '_provenance.scope', str) != context['scope']:
            raise Unavailable('bucket provenance differs from project scope')
    return context, item['name']


def _deletion(item, index):
    context, name = _bucket(index, item)
    rules = _policy(context, 'approved_bucket_deletions', dict)
    if name not in rules:
        return 'NOT_APPLICABLE', {'bucket': name, 'reason': 'no approved immediate-deletion rule'}
    rule = get(rules, name, dict)
    if get(rule, 'immediate_deletion', bool) is not True:
        return 'NOT_APPLICABLE', {'bucket': name, 'reason': 'approved rule is not immediate deletion'}
    deadline = _time(get(rule, 'deadline', str))
    now = _time(get(context, 'created_at', str))
    if now <= deadline:
        return 'NOT_APPLICABLE', {'bucket': name, 'reason': 'approved deadline has not passed'}
    soft = get(item, 'softDeletePolicy.retentionDurationSeconds', str)
    retention = get(item, 'retentionPolicy.retentionPeriod', str)
    versioning = get(item, 'versioning.enabled', bool)
    if not soft.isdecimal() or not retention.isdecimal():
        raise Unavailable('retention duration malformed')
    blockers = [key for key, bad in [('softDeletePolicy', int(soft) > 0),
                                     ('versioning', versioning), ('retentionPolicy', int(retention) > 0)] if bad]
    return result(bool(blockers), bucket=name, recovery_blockers=blockers)


def _log_retention(item, index):
    context, _, rows = _inventory(index, 'bucket', item)
    name = get(item, 'name', str)
    names = [get(row, 'name', str) for row in rows]
    if len(names) != len(set(names)) or get(item, '_provenance.scope', str) != context['scope']:
        raise Unavailable('Logging bucket identity or scope ambiguous')
    policy = _policy(context, 'approved_log_retention', dict)
    minimum = get(policy, 'minimum_days', int)
    maximum = get(policy, 'maximum_days', int)
    lock_required = get(policy, 'lock_required', bool)
    deadline = _time(get(policy, 'deletion_deadline', str))
    if minimum < 0 or maximum < minimum:
        raise Unavailable('invalid retention bounds')
    # This signed bucket kind needs a Cloud Logging bucket projection, distinct
    # from the current Cloud Storage bucket collection.
    if not re.fullmatch(re.escape(context['scope']) + r'/locations/[a-z0-9-]+/buckets/[^/]+', name):
        raise Unavailable('Cloud Logging bucket identity unavailable')
    if get(item, 'destinationExternal', bool):
        return unknown('external log destination cannot be evaluated')
    days = get(item, 'retentionDays', int)
    locked = get(item, 'locked', bool)
    if days < 0:
        raise Unavailable('negative retention')
    late = _time(get(context, 'created_at', str)) > deadline
    return result(days < minimum or (late and days > maximum) or (lock_required and not locked),
                  bucket=name, retention_days=days, locked=locked)


def _replication(item, index):
    context, name = _bucket(index, item)
    expected = _policy(context, 'expected_replica_locations', dict)
    locations = _strings(get(expected, name, list))
    if not locations:
        raise Unavailable('approved replica locations empty')
    location = get(item, 'location', str)
    if 'customPlacementConfig' in item:
        actual = _strings(get(item, 'customPlacementConfig.dataLocations', list))
    else:
        actual = {location}
    health = get(item, 'replicationHealth.status', str)
    if health != 'HEALTHY':
        return unknown('replication health is unavailable or unrecognized', status=health)
    if actual != locations:
        return result(True, bucket=name, actual_locations=sorted(actual), expected_locations=sorted(locations))
    return result(False, bucket=name, actual_locations=sorted(actual), replication_health=health)


_READ_ROLES = {'roles/owner', 'roles/editor', 'roles/viewer',
               'roles/storage.objectViewer', 'roles/storage.objectAdmin',
               'roles/storage.admin', 'roles/storage.legacyObjectReader',
               'roles/storage.legacyObjectOwner'}
_PUBLIC = {'allUsers', 'allAuthenticatedUsers'}


def _pci(item, index):
    _, name = _bucket(index, item)
    policy = get(item, 'iamPolicy', dict)
    bindings = get(policy, 'bindings', list)
    if any(not isinstance(b, dict) for b in bindings):
        raise Unavailable('malformed IAM binding')
    unknown_role = False
    grants = []
    for binding in bindings:
        role = get(binding, 'role', str)
        members = _strings(get(binding, 'members', list))
        if members & _PUBLIC:
            if 'condition' in binding:
                raise Unavailable('conditional public IAM binding requires condition evaluation')
            if role in _READ_ROLES:
                grants.append(('iam', role))
            else:
                unknown_role = True
    uniform = get(item, 'iamConfiguration.uniformBucketLevelAccess.enabled', bool)
    if not uniform:
        for key in ('bucketAccessControls', 'objectAccessControls'):
            envelope = get(item, key, dict)
            if get(envelope, 'status', str) != 'collected' or get(envelope, 'all_pages', bool) is not True:
                raise Unavailable('ACL inventory incomplete')
            if key == 'objectAccessControls' and get(envelope, 'all_objects', bool) is not True:
                raise Unavailable('object ACL inventory does not cover every object')
            rows = get(envelope, 'items', list)
            for row in rows:
                if get(row, 'bucket', str) != name:
                    raise Unavailable('foreign ACL bucket')
                entity = get(row, 'entity', str)
                role = get(row, 'role', str)
                public_read_roles = ('READER', 'OWNER', 'WRITER') if key == 'bucketAccessControls' else ('READER', 'OWNER')
                if entity in ('allUsers', 'allAuthenticatedUsers') and role in public_read_roles:
                    grants.append((key, entity))
                if role not in ('READER', 'OWNER', 'WRITER'):
                    raise Unavailable('unrecognized ACL role')
    if grants:
        return result(True, bucket=name, grants=grants)
    if unknown_role:
        return unknown('public IAM role read permission unresolved')
    return result(False, bucket=name, inspected_iam_bindings=len(bindings), uniform_bucket_access=uniform)


_EVALUATORS = {**{key: (lambda item, index, cid=key: _audit_check(cid, item, index))
                  for key in SPECS if key.startswith('gcp_logging_detect_')},
               'gcp_c5_deletion_recoverability': _deletion,
               'gcp_c5_log_retention': _log_retention,
               'gcp_gcs_replication_status': _replication,
               'gcp_pci_bucket_157fb0c69361': _pci}

for _id, (_kind, _category, _severity, _title, _sha) in SPECS.items():
    _accepted = _category if _category in {'hardening', 'exposure', 'least_privilege', 'iam_graph', 'network'} else 'hardening'
    @register(_id, 'gcp', _accepted, _kind, _title, _severity, 'CM-6',
              'Review the signed proposed specification and remediate the observed grant or event.',
              dependencies=[_kind])
    def _evaluate(item, index, cid=_id):
        return _EVALUATORS[cid](item, index)
    if _accepted != _category:
        object.__setattr__(CHECKS[-1], 'category', _category)
