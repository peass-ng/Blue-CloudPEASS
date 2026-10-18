"""Exact metadata IAM attachments for Lightsail management; never bucket keys."""
import copy
import hashlib
import json
import re
from datetime import datetime
from urllib.parse import unquote

KIND = 'lightsail_iam_policy_attachment'
SPECS = {KIND: ('iam', 'get_account_authorization_details', None)}
NATIVE_IDS = {KIND: 'id'}
READ_ACTIONS = {('iam', 'get_account_authorization_details'), ('lightsail', 'get_buckets')}
MAX_IDENTITIES = 20000
MAX_ATTACHMENTS = 50000
MAX_DOCUMENT_BYTES = 131072
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
_OK = {'collected', 'empty'}
_NAME = r'[A-Za-z0-9+=,.@_-]{1,128}'
_REGION = r'[a-z]{2}(?:-[a-z]+)+-[0-9]+'


def _result(items=(), status=None, code=None):
    from .aws import ReadResult
    rows = list(items)
    return ReadResult(rows, status or ('collected' if rows else 'empty'), {'code': code} if code else None)


def _scope(session, region, account):
    if not isinstance(account, str) or not re.fullmatch(r'[0-9]{12}', account) or not isinstance(region, str) or not re.fullmatch(_REGION, region):
        raise ValueError('native_scope_invalid')
    partition = session.get_partition_for_region(region)
    if partition not in {'aws', 'aws-cn', 'aws-us-gov'}:
        raise ValueError('native_partition_unsupported')
    return partition


def _bound(requests, account, region):
    policy = getattr(requests, 'lightsail_iam_policy', None)
    fields = {'status', 'scope', 'observed_at', 'max_age_seconds',
              'iam_required_lightsail_bucket_arns', 'approved_lightsail_principals', 'approved_lightsail_actions'}
    if (not isinstance(account, str) or not isinstance(region, str)
            or not isinstance(policy, dict) or set(policy) != fields or policy.get('status') != 'collected'
            or policy.get('scope') != account + '/' + region
            or not all(isinstance(policy.get(k), list) for k in fields - {'status', 'scope', 'observed_at', 'max_age_seconds'})
            or type(policy['max_age_seconds']) is not int or not 1 <= policy['max_age_seconds'] <= 365 * 86400
            or not isinstance(policy['observed_at'], str) or not 1 <= len(policy['observed_at']) <= 64):
        return False
    try:
        approved = datetime.fromisoformat(policy['observed_at'].replace('Z', '+00:00'))
        now = requests.observed_at
        return (isinstance(now, datetime) and approved.utcoffset() is not None and now.utcoffset() is not None
                and 0 <= (now - approved).total_seconds() <= policy['max_age_seconds'])
    except (ValueError, TypeError, OverflowError, AttributeError):
        return False


def _rows(requests, session, region, expression):
    from .aws import ReadFailure
    read = requests.pages(session, 'iam', region, 'get_account_authorization_details', expression)
    if read.status not in _OK:
        raise ReadFailure(read.status, (read.error or {}).get('code', 'iam_inventory_incomplete'))
    if not isinstance(read.items, list) or len(read.items) > MAX_IDENTITIES:
        raise ValueError('iam_inventory_limit')
    return read.items


def _objects(row, key):
    value = row.get(key, [])
    if not isinstance(value, list) or any(not isinstance(v, dict) for v in value):
        raise ValueError('iam_optional_array_malformed')
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('policy_duplicate_json_key')
        result[key] = value
    return result


def _document(value):
    if isinstance(value, str):
        if len(value) > MAX_DOCUMENT_BYTES * 3:
            raise ValueError('policy_document_limit')
        try:
            value = json.loads(value, object_pairs_hook=_unique_object)
        except json.JSONDecodeError:
            value = json.loads(unquote(value), object_pairs_hook=_unique_object)
    if not isinstance(value, dict) or set(value) - {'Version', 'Id', 'Statement'}:
        raise ValueError('policy_document_malformed')
    if len(json.dumps(value, allow_nan=False).encode()) > MAX_DOCUMENT_BYTES:
        raise ValueError('policy_document_limit')
    if 'Version' in value and value['Version'] not in {'2012-10-17', '2008-10-17'}:
        raise ValueError('policy_version_unrecognized')
    statements = value.get('Statement')
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list) or not statements:
        raise ValueError('policy_statements_missing')
    for row in statements:
        if (not isinstance(row, dict) or set(row) - {'Sid', 'Effect', 'Action', 'Resource'}
                or row.get('Effect') not in {'Allow', 'Deny'}):
            raise ValueError('policy_construct_unsupported')
        for field in ('Action', 'Resource'):
            values = row.get(field)
            values = [values] if isinstance(values, str) else values
            if (not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values)
                    or len(values) != len(set(values))):
                raise ValueError('policy_statement_malformed')
            if field == 'Resource' and any('?' in value or '${' in value for value in values):
                raise ValueError('policy_resource_pattern_unsupported')
    return copy.deepcopy(value)


def collect(requests, session, region, account):
    """Complete attached-policy metadata only; this is not effective IAM access."""
    if not _bound(requests, account, region):
        return _result(status='not_collected', code='lightsail_iam_owner_scope_unavailable')
    from .aws import ReadFailure
    try:
        partition = _scope(session, region, account)
        views = {field: _rows(requests, session, region, field) for field in
                 ('UserDetailList', 'GroupDetailList', 'RoleDetailList', 'Policies')}
        if sum(map(len, views.values())) > MAX_IDENTITIES:
            raise ValueError('iam_inventory_limit')
        identities, by_kind, names = set(), {}, {}
        for label, field, name_key in [('user', 'UserDetailList', 'UserName'), ('group', 'GroupDetailList', 'GroupName'), ('role', 'RoleDetailList', 'RoleName')]:
            indexed = {}
            for row in views[field]:
                if not isinstance(row, dict):
                    raise ValueError('iam_identity_malformed')
                arn, name = row.get('Arn'), row.get(name_key)
                if (not isinstance(arn, str) or not re.fullmatch('arn:' + re.escape(partition) + ':iam::' + account + ':' + label + r'/[A-Za-z0-9+=,.@_/-]{1,512}', arn)
                        or not isinstance(name, str) or not re.fullmatch(_NAME, name)
                        or arn.rsplit('/', 1)[-1] != name or arn in identities or name in indexed):
                    raise ValueError('iam_identity_scope_or_duplicate')
                if 'PermissionsBoundary' in row:
                    raise ValueError('iam_permissions_boundary_unsupported')
                identities.add(arn)
                indexed[name] = row
            by_kind[label] = indexed
            names[label] = name_key
        policies = {}
        for row in views['Policies']:
            arn = row.get('Arn') if isinstance(row, dict) else None
            if (not isinstance(arn, str) or not re.fullmatch('arn:' + re.escape(partition) + ':iam::(?:' + account + r'|aws):policy/[A-Za-z0-9+=,.@_/-]{1,512}', arn)
                    or arn in policies):
                raise ValueError('managed_policy_identity_invalid')
            policies[arn] = row
        results, seen, total_bytes = [], set(), 0
        def emit(principal, document, source, group=None):
            nonlocal total_bytes
            requests.check_deadline()
            doc = _document(document)
            identity = [principal, source, group]
            key = json.dumps(identity, sort_keys=True, separators=(',', ':'))
            if key in seen:
                raise ValueError('duplicate_iam_attachment')
            seen.add(key)
            proof = {'read_only': True, 'source_operation': 'iam:GetAccountAuthorizationDetails',
                     'source_scope': account + '/global', 'target_scope': account + '/' + region,
                     'source_identity': copy.deepcopy(source), 'semantics': 'attached_policy_configuration_not_effective_access'}
            if group is not None:
                proof['native_group_arn'] = group
            row = {'id': 'lightsail-iam-attachment:' + hashlib.sha256(key.encode()).hexdigest(),
                   'PrincipalArn': principal, 'PolicyDocument': doc, '_provenance': proof}
            total_bytes += len(json.dumps(row, allow_nan=False).encode())
            if len(results) >= MAX_ATTACHMENTS or total_bytes > MAX_OUTPUT_BYTES:
                raise ValueError('iam_attachment_output_limit')
            results.append(row)
        def attachments(row, principal, kind, group=None):
            inline_field = {'user': 'UserPolicyList', 'group': 'GroupPolicyList', 'role': 'RolePolicyList'}[kind]
            inline_names = set()
            for inline in _objects(row, inline_field):
                name = inline.get('PolicyName')
                if not isinstance(name, str) or not re.fullmatch(_NAME, name) or name in inline_names:
                    raise ValueError('inline_policy_identity_invalid')
                inline_names.add(name)
                emit(principal, inline.get('PolicyDocument'), {'type': 'inline', 'identity_arn': row['Arn'], 'policy_name': name}, group)
            managed_seen = set()
            for attached in _objects(row, 'AttachedManagedPolicies'):
                arn = attached.get('PolicyArn')
                if not isinstance(arn, str) or arn in managed_seen or arn not in policies:
                    raise ValueError('managed_attachment_join_unavailable')
                managed_seen.add(arn)
                native = policies[arn]
                version = native.get('DefaultVersionId')
                if not isinstance(version, str) or not re.fullmatch(r'v[1-9][0-9]*(?:\.[A-Za-z0-9-]+)?', version):
                    raise ValueError('managed_default_version_invalid')
                versions = _objects(native, 'PolicyVersionList')
                defaults = [v for v in versions if v.get('IsDefaultVersion') is True]
                ids = [v.get('VersionId') for v in versions]
                if (not all(isinstance(v, str) for v in ids) or len(ids) != len(set(ids))
                        or any(type(v.get('IsDefaultVersion')) is not bool for v in versions)
                        or len(defaults) != 1 or defaults[0].get('VersionId') != version):
                    raise ValueError('managed_default_version_join_unavailable')
                emit(principal, defaults[0].get('Document'), {'type': 'managed', 'policy_arn': arn, 'version_id': version, 'identity_arn': row['Arn']}, group)
        for kind in ('user', 'role'):
            for row in by_kind[kind].values():
                attachments(row, row['Arn'], kind)
                if kind == 'user':
                    groups = row.get('GroupList', [])
                    if (not isinstance(groups, list) or any(not isinstance(g, str) for g in groups)
                            or len(groups) != len(set(groups)) or any(g not in by_kind['group'] for g in groups)):
                        raise ValueError('iam_group_membership_join_unavailable')
                    for group_name in groups:
                        group = by_kind['group'][group_name]
                        attachments(group, row['Arn'], 'group', group['Arn'])
        return _result(results)
    except ReadFailure as exc:
        return _result(status=exc.status, code=exc.code)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        return _result(status='not_collected', code='lightsail_iam_native_join_unsupported')


def bucket_metadata(requests, session, region, account):
    """Safe IAM-control bucket route: GetBuckets only, never access-key reads."""
    try:
        partition = _scope(session, region, account)
        read = requests.pages(session, 'lightsail', region, 'get_buckets', 'buckets', _tokens=('pageToken', 'nextPageToken'))
        if read.status not in _OK:
            return _result(status=read.status, code=(read.error or {}).get('code', 'lightsail_bucket_inventory_incomplete'))
        rows, ids, names = [], set(), set()
        for native in read.items:
            requests.check_deadline()
            arn, name, location = native.get('arn'), native.get('name'), native.get('location')
            if (not isinstance(arn, str) or not re.fullmatch('arn:' + re.escape(partition) + ':lightsail:' + re.escape(region) + ':' + account + r':Bucket/[A-Za-z0-9-]{1,128}', arn)
                    or arn in ids or not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', name)
                    or name in names or not isinstance(location, dict) or location.get('regionName') != region
                    or native.get('resourceType', 'Bucket') != 'Bucket'):
                raise ValueError('lightsail_bucket_identity_unavailable')
            ids.add(arn)
            names.add(name)
            rows.append({'arn': arn, 'name': name, 'location': {'regionName': region},
                         '_provenance': {'source_operation': 'lightsail:GetBuckets', 'read_only': True,
                                         'account_id': account, 'region': region, 'bucket_keys_read': False}})
        return _result(rows)
    except Exception as exc:
        from .aws import ReadFailure
        if isinstance(exc, ReadFailure):
            return _result(status=exc.status, code=exc.code)
        return _result(status='not_collected', code='lightsail_bucket_native_identity_unavailable')


FETCHERS = {KIND: collect}
