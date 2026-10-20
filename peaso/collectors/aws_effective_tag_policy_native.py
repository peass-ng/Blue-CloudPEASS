"""Own-account native effective TAG_POLICY constraints, projected before cache.

PolicyContent and allowed values never leave project_response. No policy merge,
resource tagging, enforcement, role assumption or state change is performed.
"""
from datetime import datetime, timezone
import hashlib
import json
import re

KIND = 'organization_effective_tag_policy'
PROJECTION = 'effective-tag-policy-digests-v1'
POLICY_TYPE = 'TAG_POLICY'
SPECS = {KIND: ('organizations', 'describe_effective_policy', None)}
GLOBAL_TYPES = {KIND}
NATIVE_IDS = {KIND: 'TargetId'}
READ_ACTIONS = {('organizations', 'describe_effective_policy')}
NOT_FOUND = 'EffectivePolicyNotFoundException'
NOT_IN_USE = 'AWSOrganizationsNotInUseException'
# Both exact SDK error codes prove no TAG_POLICY for this own-account request.
ABSENT_CODES = (NOT_FOUND, NOT_IN_USE)
DOMAIN = 'peaso:aws:organizations:effective-tag-policy:finite-value:v1'


def _invalid():
    from .aws import ReadFailure
    raise ReadFailure('malformed', 'effective_tag_policy_response_invalid')


def _account(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9]{12}', value) is not None


def value_digest(target, key, value):
    if not _account(target) or not isinstance(key, str) or not key or not isinstance(value, str):
        raise ValueError('invalid effective tag digest input')
    encoded = json.dumps([DOMAIN, target, POLICY_TYPE, key, value], ensure_ascii=False,
                         separators=(',', ':'), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _stamp(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            _invalid()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _invalid()
    return value.astimezone(timezone.utc).isoformat()


def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            _invalid()
        out[key] = value
    return out


def project_response(response):
    """Native SDK response -> bounded metadata only, before Requests cache/Future."""
    if not isinstance(response, dict) or not isinstance(response.get('EffectivePolicy'), dict):
        _invalid()
    policy = response['EffectivePolicy']
    target, content = policy.get('TargetId'), policy.get('PolicyContent')
    if (not _account(target) or policy.get('PolicyType') != POLICY_TYPE
            or not isinstance(content, str) or not 1 <= len(content) <= 1_000_000):
        _invalid()
    stamp = _stamp(policy.get('LastUpdatedTimestamp'))
    try:
        document = json.loads(content, object_pairs_hook=_unique,
                              parse_constant=lambda _: _invalid())
    except (ValueError, TypeError, RecursionError):
        _invalid()
    # Organizations returns an empty JSON object for an effective TAG_POLICY
    # with no tag constraints. This is observed native policy data, not missing
    # or malformed collection; preserve it as a complete empty assignment set.
    if document == {}:
        document = {'tags': {}}
    if not isinstance(document, dict) or set(document) != {'tags'} or not isinstance(document['tags'], dict):
        _invalid()
    if len(document['tags']) > 10000:
        _invalid()
    assignments, keys, logicals, complete = [], set(), set(), True
    for logical, definition in document['tags'].items():
        key = definition.get('tag_key') if isinstance(definition, dict) else None
        if (not isinstance(logical, str) or not logical or logical.casefold() in logicals
                or not isinstance(key, str) or not 1 <= len(key) <= 256
                or key.casefold() != logical.casefold() or key in keys):
            complete = False
            continue
        logicals.add(logical.casefold()); keys.add(key)
        assignment = {'TagKey': key, 'ConstraintKind': 'unsupported', 'ValueDigests': []}
        if 'tag_value' not in definition:
            assignment['ConstraintKind'] = 'unrestricted'
        else:
            values = definition['tag_value']
            if (isinstance(values, list) and len(values) <= 10000
                    and all(isinstance(v, str) and len(v) <= 4096 and '*' not in v for v in values)):
                assignment['ConstraintKind'] = 'finite'
                assignment['ValueDigests'] = sorted({value_digest(target, key, value) for value in values})
        assignments.append(assignment)
    return {'_metadata_projection': PROJECTION, 'EffectivePolicy': {
        'TargetId': target, 'PolicyType': POLICY_TYPE, 'LastUpdatedTimestamp': stamp,
        'PolicyPresent': True, 'AssignmentsComplete': complete,
        'TagAssignments': sorted(assignments, key=lambda row: row['TagKey'])}}


def validate_projection(row, target):
    """Validate the retained schema/binding without access to raw cloud values."""
    if (not isinstance(row, dict) or not _account(target) or row.get('TargetId') != target
            or row.get('PolicyType') != POLICY_TYPE or row.get('_metadata_projection') != PROJECTION
            or type(row.get('PolicyPresent')) is not bool or type(row.get('AssignmentsComplete')) is not bool):
        _invalid()
    proof = row.get('_provenance')
    if (not isinstance(proof, dict) or proof.get('read_only') is not True
            or proof.get('source_operation') != 'DescribeEffectivePolicy'
            or proof.get('target_id') != target or proof.get('policy_type') != POLICY_TYPE):
        _invalid()
    assignments = row.get('TagAssignments')
    if not isinstance(assignments, list) or len(assignments) > 10000:
        _invalid()
    if row['PolicyPresent']:
        _stamp(row.get('LastUpdatedTimestamp'))
        if 'native_error_code' in proof:
            _invalid()
    elif (proof.get('native_error_code') not in ABSENT_CODES or assignments
          or row['AssignmentsComplete'] is not True):
        _invalid()
    keys = set()
    for assignment in assignments:
        if not isinstance(assignment, dict) or set(assignment) != {'TagKey', 'ConstraintKind', 'ValueDigests'}:
            _invalid()
        key, kind, digests = assignment['TagKey'], assignment['ConstraintKind'], assignment['ValueDigests']
        if (not isinstance(key, str) or not 1 <= len(key) <= 256 or key in keys
                or kind not in ('finite', 'unrestricted', 'unsupported') or not isinstance(digests, list)
                or any(not isinstance(d, str) or re.fullmatch(r'[0-9a-f]{64}', d) is None for d in digests)
                or digests != sorted(set(digests)) or kind != 'finite' and digests):
            _invalid()
        keys.add(key)
    if 'PolicyContent' in row:
        _invalid()
    return row


def collect(requests, session, region, account):
    from .aws import ReadResult, _failure
    if not _account(account):
        return ReadResult([], 'malformed', {'code': 'effective_tag_policy_account_invalid'})
    proof = {'source_operation': 'DescribeEffectivePolicy', 'read_only': True,
             'target_id': account, 'policy_type': POLICY_TYPE}
    response = requests.detail(session, 'organizations', region, 'describe_effective_policy',
        absent=ABSENT_CODES, PolicyType=POLICY_TYPE, TargetId=account)
    if response.get('collection_status') == 'empty' and response.get('absent') is True and response.get('error', {}).get('code') in ABSENT_CODES:
        row = {'_resource_id': account, 'TargetId': account, 'PolicyType': POLICY_TYPE,
               '_metadata_projection': PROJECTION, 'PolicyPresent': False,
               'AssignmentsComplete': True, 'TagAssignments': [],
               '_provenance': {**proof, 'native_error_code': response['error']['code']}}
        return ReadResult([row])
    if response.get('collection_status') != 'collected':
        state = response.get('collection_status', 'unknown')
        if state not in {'denied', 'timeout', 'not_collected', 'malformed', 'unknown'}:
            state = 'unknown'
        return ReadResult([], state, {'code': response.get('error', {}).get('code', 'effective_tag_policy_unavailable')})
    try:
        if response.get('_metadata_projection') != PROJECTION or not isinstance(response.get('EffectivePolicy'), dict):
            _invalid()  # Never fall back to retaining an unprojected response.
        row = {**response['EffectivePolicy'], '_resource_id': account,
               '_metadata_projection': PROJECTION, '_provenance': proof}
        validate_projection(row, account)
    except Exception as exc:
        failure = _failure(exc)
        return ReadResult([], failure.status, {'code': failure.code})
    return ReadResult([row])


FETCHERS = {KIND: collect}
