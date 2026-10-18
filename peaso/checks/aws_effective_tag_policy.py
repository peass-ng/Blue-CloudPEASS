"""Compare native effective finite tag constraints; no asset/enforcement claim."""
import re

from . import register, result, unknown
from .facts import Unavailable, get
from .aws_a_facts import complete_items

CHECK_ID = 'aws.organizations.effective_tag_policy_values'
KIND = 'organization_effective_tag_policy'


@register(CHECK_ID, 'aws', 'hardening', KIND,
          'Effective tag policy defines the approved finite tag values', 'medium', 'CM-8',
          'Configure effective Organizations tag constraints to match the approved finite values.',
          target='scope', dependencies=[KIND])
def effective_tag_policy_values(item, index):
    from ..collectors.aws_effective_tag_policy_native import value_digest, validate_projection
    context = get(index, 'context', dict)
    scope = get(context, 'scope', str)
    match = re.fullmatch(r'([0-9]{12})/(?:global|[a-z]{2}(?:-[a-z]+)+-[0-9])', scope)
    if get(context, 'provider', str) != 'aws' or match is None or get(item, 'scope', str) != scope:
        raise Unavailable('effective policy account authority unavailable')
    account = match[1]
    metadata = get(context, 'metadata', dict)
    owner = metadata if 'approved_ec2_tag_values' in metadata else get(metadata, 'parameters', dict)
    required = get(owner, 'approved_ec2_tag_values', dict)
    if not required:
        raise Unavailable('approved finite tag constraints absent')
    expected = {}
    for key, values in required.items():
        if (not isinstance(key, str) or not 1 <= len(key) <= 256 or not isinstance(values, list) or not values
                or any(not isinstance(v, str) or not v or '*' in v or len(v) > 4096 for v in values)
                or len(values) != len(set(values))):
            raise Unavailable('approved finite tag constraint malformed or unsupported')
        expected[key] = sorted(value_digest(account, key, value) for value in values)
    envelopes = get(index, 'collections', dict).get(KIND)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable('effective policy collection missing or ambiguous')
    envelope = envelopes[0]
    if (get(envelope, 'type', str) != KIND or get(envelope, 'scope', str) not in {scope, account + '/global'}
            or envelope.get('account_id', account) != account
            or envelope['scope'] != scope and (envelope.get('global') is not True or envelope.get('account_id') != account)):
        raise Unavailable('foreign effective policy collection authority')
    rows = complete_items(index, KIND, scope)
    wrappers = get(index, KIND, list)
    if (len(rows) != 1 or len(wrappers) != 1 or wrappers[0].get('scope') != envelope['scope']
            or wrappers[0].get('type') != KIND or wrappers[0].get('provider', 'aws') != 'aws'
            or wrappers[0].get('data') != rows[0]):
        raise Unavailable('effective policy response missing, ambiguous or mismatched')
    row = rows[0]
    if row.get('AccountId', account) != account:
        raise Unavailable('effective policy resource account conflict')
    try:
        validate_projection(row, account)
    except Exception as exc:
        from ..collectors.aws import ReadFailure
        if not isinstance(exc, (ReadFailure, ValueError, TypeError)):
            raise
        raise Unavailable('effective policy retained metadata invalid') from None
    semantics = 'Native effective finite value constraints; resource tagging and enforcement unassessed'
    if row['AssignmentsComplete'] is not True:
        return unknown('effective tag identities incomplete or ambiguous')
    if not row['PolicyPresent']:
        return result(True, missing_effective_policy=True, semantics=semantics)
    assignments = {a['TagKey']: a for a in row['TagAssignments']}
    failures, unresolved = [], []
    for key, digests in expected.items():
        observed = assignments.get(key)
        if observed is not None and observed['ConstraintKind'] == 'unsupported':
            unresolved.append(key)
        elif observed is None or observed['ConstraintKind'] == 'unrestricted' or observed['ValueDigests'] != digests:
            failures.append(key)
    if failures:
        return result(True, noncompliant_tag_keys=sorted(failures), semantics=semantics)
    if unresolved:
        return unknown('effective value constraints unsupported', unresolved_tag_keys=sorted(unresolved))
    return result(False, noncompliant_tag_keys=[], semantics=semantics)


def _fixture(kind):
    from copy import deepcopy
    from datetime import datetime, timezone
    import json
    from ..collectors.aws_effective_tag_policy_native import project_response, PROJECTION
    account, scope = '123456789012', '123456789012/global'
    values = ['Production'] if kind == 'pass' else ['Development'] if kind == 'fail' else ['Prod*']
    projected = project_response({'EffectivePolicy': {'TargetId': account, 'PolicyType': 'TAG_POLICY',
        'LastUpdatedTimestamp': datetime(2026, 10, 16, tzinfo=timezone.utc),
        'PolicyContent': json.dumps({'tags': {'environment': {'tag_key': 'Environment', 'tag_value': values}}})}})
    row = {**projected['EffectivePolicy'], '_metadata_projection': PROJECTION, '_resource_id': account,
           '_provenance': {'read_only': True, 'source_operation': 'DescribeEffectivePolicy',
                           'target_id': account, 'policy_type': 'TAG_POLICY'}}
    index = {'context': {'provider': 'aws', 'scope': scope,
                        'metadata': {'parameters': {'approved_ec2_tag_values': {'Environment': ['Production']}}}},
             'collections': {KIND: [{'type': KIND, 'scope': scope, 'status': 'collected', 'items': [deepcopy(row)]}]},
             KIND: [{'type': KIND, 'scope': scope, 'data': deepcopy(row)}]}
    return {'scope': scope}, index


from .fixtures import CASES
CASES[CHECK_ID] = {}
for _label in ('pass', 'fail', 'unknown'):
    CASES[CHECK_ID][_label], CASES[CHECK_ID][_label + '_index'] = _fixture(_label)
