"""Resource-level assessment reported by AWS's effective tag policy service."""
from copy import deepcopy
import re

from . import register, result
from .facts import Unavailable, get, memoized
from .aws_a_facts import complete_items
from ..collectors.aws_resource_tag_compliance_native import KIND, SCHEMA, _arn, partition_for_region

CHECK_ID = 'aws.organizations.resource_tag_policy_compliance'


def _assessment_inventory(index, scope):
    envelopes = get(index, 'collections', dict).get(KIND)
    if (not isinstance(envelopes, list) or len(envelopes) != 1
            or not isinstance(envelopes[0], dict)
            or envelopes[0].get('scope') != scope or envelopes[0].get('type') != KIND
            or envelopes[0].get('global') is True):
        raise Unavailable('regional tag assessment collection authority unavailable')
    rows = complete_items(index, KIND, scope)
    by_arn = {}
    for row in rows:
        arn = get(row, 'ResourceARN', str)
        if arn in by_arn:
            raise Unavailable('duplicate tag assessment resource')
        by_arn[arn] = row
    wrappers = get(index, KIND, list)
    seen = set()
    for wrapper in wrappers:
        if (not isinstance(wrapper, dict) or wrapper.get('type') != KIND
                or wrapper.get('scope') != scope or wrapper.get('provider', 'aws') != 'aws'):
            raise Unavailable('tag assessment wrapper outside regional inventory')
        data = get(wrapper, 'data', dict)
        arn = get(data, 'ResourceARN', str)
        if arn in seen or arn not in by_arn or data != by_arn[arn]:
            raise Unavailable('tag assessment wrapper differs from regional inventory')
        seen.add(arn)
    if seen != by_arn.keys():
        raise Unavailable('tag assessment resource wrappers incomplete')
    return by_arn


@register(CHECK_ID, 'aws', 'hardening', KIND,
          'Tagged resources comply with their effective Organizations tag policy', 'medium', 'CM-8',
          'Correct the tag keys or values reported noncompliant by AWS Organizations.', dependencies=[KIND])
def resource_tag_compliance(item, index):
    context = get(index, 'context', dict)
    scope = get(context, 'scope', str)
    match = re.fullmatch(r'([0-9]{12})/([a-z]{2}(?:-[a-z]+)+-[0-9])', scope)
    if get(context, 'provider', str) != 'aws' or match is None:
        raise Unavailable('regional account authority unavailable')
    account, region = match.groups()
    if 'Account' in context and get(context, 'Account', str) != account:
        raise Unavailable('account authority conflict')
    arn = get(item, 'ResourceARN', str)
    native = _arn(arn)
    if native[1] != partition_for_region(region) or native[2] not in ('', region) or native[3] not in (None, account):
        raise Unavailable('resource ARN outside assessed account/region')
    if get(item, 'AccountId', str) != account or get(item, 'Region', str) != region:
        raise Unavailable('foreign tag compliance assessment')
    proof = get(item, '_provenance', dict)
    if (get(proof, 'schema', str) != SCHEMA or get(proof, 'source_operation', str) != 'GetResources'
            or get(proof, 'read_only', bool) is not True
            or get(proof, 'include_compliance_details', bool) is not True
            or get(proof, 'exclude_compliant_resources', bool) is not False):
        raise Unavailable('native tag compliance query unavailable')
    rows = memoized(index, ('native_tag_assessment_inventory', scope),
                    lambda: _assessment_inventory(index, scope))
    if rows.get(arn) != item:
        raise Unavailable('tag compliance assessment identity ambiguous')
    details = get(item, 'ComplianceDetails', dict)
    compliant = get(details, 'ComplianceStatus', bool)
    reported = {}
    for field in ('NoncompliantKeys', 'KeysWithNoncompliantValues'):
        if field in details:
            keys = get(details, field, list)
            if any(not isinstance(key, str) or not key for key in keys) or len(set(keys)) != len(keys):
                raise Unavailable('malformed native noncompliance keys')
            if compliant and keys:
                raise Unavailable('contradictory native compliance assessment')
            reported[field] = keys
    return result(not compliant, resource_arn=arn, reported_keys=reported,
                  semantics='AWS effective tag policy assessment for this returned resource')


def _fixture(state):
    account, region = '123456789012', 'us-east-1'
    scope = account + '/' + region
    row = {'ResourceARN': 'arn:aws:ec2:' + region + ':' + account + ':instance/i-1234',
           'AccountId': account, 'Region': region, 'ComplianceDetails': {},
           '_provenance': {'schema': SCHEMA, 'source_operation': 'GetResources', 'read_only': True,
                           'include_compliance_details': True, 'exclude_compliant_resources': False}}
    if state is not None: row['ComplianceDetails']['ComplianceStatus'] = state
    index = {'context': {'provider': 'aws', 'scope': scope, 'Account': account},
             'collections': {KIND: [{'type': KIND, 'scope': scope, 'status': 'collected', 'items': [deepcopy(row)]}]},
             KIND: [{'type': KIND, 'scope': scope, 'data': deepcopy(row)}]}
    return row, index


from .fixtures import CASES
CASES[CHECK_ID] = {}
for _label, _state in [('pass', True), ('fail', False), ('unknown', None)]:
    CASES[CHECK_ID][_label], CASES[CHECK_ID][_label + '_index'] = _fixture(_state)
