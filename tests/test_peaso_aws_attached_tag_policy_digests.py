"""Private literals compared without retaining DescribePolicy.Content."""
import json
from copy import deepcopy
import pytest

from tests.test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from tests.aws_tag_policy_fixture import collect_policy
from tests.test_peaso_aws_tag_policy_locked_assignment import MASTER, ORG, POLICY
from peaso.collectors import aws, aws_attached_tag_policy_native as native

ARN = f'arn:aws:organizations::{MASTER}:policy/{ORG}/tag_policy/{POLICY}'
PRIVATE = 'NEVER-CACHE-PRIVATE-TAG-VALUE'


def document(key='Environment', values=None):
    return {'tags': {key.casefold(): {'tag_key': {'@@assign': key},
        'tag_value': {'@@assign': values if values is not None else [PRIVATE]}}}}


def raw(doc):
    return {'Policy': {'PolicySummary': {'Id': POLICY, 'Arn': ARN, 'Name': 'policy',
        'Type': 'TAG_POLICY', 'AwsManaged': False}, 'Content': json.dumps(doc)}}


@pytest.mark.parametrize('key', ['Environment', 'Password', 'InternalProject'])
@pytest.mark.parametrize('match', [True, False])
def test_custom_key_or_value_normal_path_can_decide_without_raw_rows(monkeypatch, sdk, key, match):
    required = {key: [PRIVATE if match else 'OWNER-APPROVED-DIFFERENT']}
    snapshot, finding = collect_policy(monkeypatch, sdk, document(key), approved=required)
    assert finding['status'] == ('PASS' if match else 'FAIL')
    rows = next(c['items'] for c in snapshot['collections'] if c['type'] == 'organization_tag_policy')
    assert PRIVATE not in json.dumps(rows) and 'Content' not in json.dumps(rows)
    assert rows[0]['TagValueDigests'] == [{'TagKey': key, 'ConstraintKind': 'finite',
        'ValueDigests': [native.value_digest(ARN, POLICY, key, PRIVATE)]}]


def test_projection_binding_and_input_purity():
    original = raw(document()); saved = deepcopy(original)
    projected = native.project_response(original)
    assert original == saved and PRIVATE not in json.dumps(projected) and 'Content' not in json.dumps(projected)
    digests = {native.value_digest(arn, pid, key, value) for arn, pid, key, value in [
        (ARN, POLICY, 'Environment', PRIVATE), (ARN.replace(MASTER, ACCOUNT), POLICY, 'Environment', PRIVATE),
        (ARN, 'p-otherpol', 'Environment', PRIVATE), (ARN, POLICY, 'Password', PRIVATE),
        (ARN, POLICY, 'Environment', PRIVATE.lower())]}
    assert len(digests) == 5


def test_projection_preserves_supported_partition_namespace():
    value = raw(document())
    value['Policy']['PolicySummary']['Arn'] = ARN.replace('arn:aws:', 'arn:aws-iso:')
    projected = native.project_response(value)
    assert projected['Policy']['PolicySummary']['Arn'].startswith('arn:aws-iso:')


def test_requests_future_stores_projection_and_reuses_only_one_sdk_read(sdk):
    session, add = sdk; org = add('organizations')
    org.add_response('describe_policy', raw(document('Password')), {'PolicyId': POLICY})
    reader = aws.Requests({'service_concurrency': 1, 'retry_attempts': 1})
    for _ in range(2):
        value = reader.detail(session, 'organizations', REGION, 'describe_policy', PolicyId=POLICY)
        assert value['_metadata_projection'] == native.PROJECTION
    assert reader.calls == 1 and reader.cache_hits >= 1
    retained = next(iter(reader._cache.values())).result()
    assert PRIVATE not in json.dumps(retained) and 'Content' not in json.dumps(retained)
    org.assert_no_pending_responses()


@pytest.mark.parametrize('mode', ['append', 'wildcard', 'lock_unknown', 'null', 'duplicate_json'])
def test_unsupported_or_malformed_content_is_not_an_empty_policy(sdk, mode):
    session, add = sdk; org = add('organizations'); value = raw(document())
    doc = json.loads(value['Policy']['Content']); definition = next(iter(doc['tags'].values()))
    if mode == 'append': definition['tag_value'] = {'@@append': [PRIVATE]}
    elif mode == 'wildcard': definition['tag_value'] = {'@@assign': ['*']}
    elif mode == 'lock_unknown': definition['tag_key']['@@operators_allowed_for_child_policies'] = ['@@unknown']
    elif mode == 'null': definition['tag_value'] = None
    value['Policy']['Content'] = '{"tags":{},"tags":{}}' if mode == 'duplicate_json' else json.dumps(doc)
    org.add_response('describe_policy', value, {'PolicyId': POLICY})
    reader = aws.Requests({'service_concurrency': 1, 'retry_attempts': 1})
    result = reader.detail(session, 'organizations', REGION, 'describe_policy', PolicyId=POLICY)
    assert result['collection_status'] == 'malformed'
    exc = next(iter(reader._cache.values())).exception()
    assert exc.__traceback__ is None and exc.__context__ is None
    assert PRIVATE not in repr(vars(exc))
    org.assert_no_pending_responses()


def test_scp_content_and_cache_are_unchanged(sdk):
    session, add = sdk; org = add('organizations')
    value = raw({'Version': '2012-10-17', 'Statement': []})
    value['Policy']['PolicySummary']['Type'] = 'SERVICE_CONTROL_POLICY'
    value['Policy']['PolicySummary']['Arn'] = ARN.replace('/tag_policy/', '/service_control_policy/')
    org.add_response('describe_policy', value, {'PolicyId': POLICY})
    reader = aws.Requests({'service_concurrency': 1, 'retry_attempts': 1})
    result = reader.detail(session, 'organizations', REGION, 'describe_policy', PolicyId=POLICY)
    assert result['Policy']['Content'] == value['Policy']['Content']
    assert '_metadata_projection' not in result
    org.assert_no_pending_responses()


@pytest.mark.parametrize('mode,expected', [('one_complete', 'PASS'), ('split_policies', 'FAIL'),
    ('legacy_snapshot', 'PASS'), ('foreign_account', 'UNKNOWN'), ('wrong_marker', 'UNKNOWN')])
def test_one_policy_must_satisfy_all_required_keys_and_legacy_stays_usable(mode, expected):
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot
    scope = ACCOUNT + '/global'
    def row(pid, values):
        arn = ARN.replace(POLICY, pid)
        return {'Id': pid, 'PolicyType': 'TAG_POLICY', 'AccountId': ACCOUNT, 'Complete': True,
            'AttachedToAccountPath': True, '_metadata_projection': native.PROJECTION,
            'NativePolicyArn': arn, 'TagValueDigests': [{'TagKey': key, 'ConstraintKind': 'finite',
                'ValueDigests': [native.value_digest(arn, pid, key, value)]} for key, value in values.items()],
            '_provenance': {'read_only': True, 'source_operation': 'ListPoliciesForTarget+DescribePolicy+ListParents'}}
    rows = [row(POLICY, {'Environment': PRIVATE, 'Password': PRIVATE})]
    if mode == 'split_policies':
        rows = [row(POLICY, {'Environment': PRIVATE}), row('p-otherpol', {'Password': PRIVATE})]
    elif mode == 'legacy_snapshot':
        rows[0].pop('_metadata_projection'); rows[0].pop('TagValueDigests'); rows[0].pop('NativePolicyArn')
        rows[0]['Ec2Tags'] = {'Environment': [PRIVATE], 'Password': [PRIVATE]}
    elif mode == 'foreign_account': rows[0]['AccountId'] = MASTER
    elif mode == 'wrong_marker': rows[0]['_metadata_projection'] = 'unknown-version'
    snapshot = make_snapshot('aws', [scope], [{'type': 'organization_tag_policy', 'scope': scope,
        'status': 'collected', 'service': 'organizations', 'items': rows}], metadata={'parameters': {
            'approved_ec2_tag_values': {'Environment': [PRIVATE], 'Password': [PRIVATE]}}})
    findings = evaluate_snapshot(snapshot, checks=['aws_cis_ec2_tag_policy'])['findings']
    assert findings and all(f['status'] == expected for f in findings)
