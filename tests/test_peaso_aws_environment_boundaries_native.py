"""Owner classifications and imported observations never invent a whole universe."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from test_peaso_aws_bulk_inventory import sdk, ACCOUNT
from peaso.collectors import aws, aws_environment_boundaries_native as native
from peaso.collectors.bulk_evidence import collect as collect_bulk
from peaso.engine import evaluate_snapshot

REGION = 'eu-west-1'
SCOPE = ACCOUNT + '/' + REGION
OTHER = '111111111111'
INSTANCE = 'i-0123456789abcdef0'
ARN = f'arn:aws:ec2:{REGION}:{ACCOUNT}:instance/{INSTANCE}'
CHECK = 'aws_organizations_environment_account_separation'


def options(age=30):
    now = datetime.now(timezone.utc)
    return {'compliance_parameters': {native.NAMESPACE: {
        'status': 'collected', 'scope': SCOPE, 'observed_at': (now - timedelta(seconds=age)).isoformat(),
        'max_age_seconds': 300, 'environment_boundaries': {'production': [ACCOUNT], 'development': [OTHER]},
        'workload_classifications': [{'resource_arn': ARN, 'environment': 'production'}]}}}


def evidence(policy, complete=True):
    return {'status': 'collected', 'scope': SCOPE, 'observed_at': policy['observed_at'],
            'source_id': 'existing-authorized-capture', 'complete': complete,
            'observations': [{'source_boundary_id': a, 'destination_boundary_id': b, 'reachable': False}
                             for a, b in [(ACCOUNT, OTHER), (OTHER, ACCOUNT)]]}


@pytest.mark.parametrize('mode', ['extra', 'bool_age', 'foreign_scope', 'foreign_resource',
                                  'duplicate_resource', 'observed_reachability_in_criteria',
                                  'competing_flat', 'duplicate_link', 'bool_like_reachability',
                                  'foreign_link', 'declared_complete_missing_pair'])
def test_strict_owner_and_imported_observation_validation(mode):
    raw = options(); policy = raw['compliance_parameters'][native.NAMESPACE]
    if mode == 'extra': policy['invented_complete'] = True
    elif mode == 'bool_age': policy['max_age_seconds'] = True
    elif mode == 'foreign_scope': policy['scope'] = OTHER + '/' + REGION
    elif mode == 'foreign_resource': policy['workload_classifications'][0]['resource_arn'] = ARN.replace(ACCOUNT, OTHER)
    elif mode == 'duplicate_resource': policy['workload_classifications'] *= 2
    elif mode == 'observed_reachability_in_criteria': policy['workload_classifications'][0]['reachable'] = False
    elif mode == 'competing_flat': raw['compliance_parameters']['environment_boundaries'] = policy['environment_boundaries']
    else:
        policy['boundary_evidence'] = evidence(policy)
        rows = policy['boundary_evidence']['observations']
        if mode == 'duplicate_link': rows.append(deepcopy(rows[0]))
        elif mode == 'bool_like_reachability': rows[0]['reachable'] = 0
        elif mode == 'foreign_link': rows[0]['source_boundary_id'] = '999999999999'
        elif mode == 'declared_complete_missing_pair': rows.pop()
    with pytest.raises(ValueError): native.normalize(raw, [SCOPE])


@pytest.mark.parametrize('age,fresh', [(30, True), (601, False), (-601, False)])
def test_owner_clock_is_not_refreshed(age, fresh):
    raw = options(age); before = deepcopy(raw); policy = native.normalize(raw, [SCOPE])
    assert raw == before
    assert bool(native.owner_metadata(policy, datetime.now(timezone.utc))) is fresh
    assert policy['observed_at'] == before['compliance_parameters'][native.NAMESPACE]['observed_at']


def test_native_ec2_join_uses_explicit_classification_and_stays_partial(sdk):
    session, add = sdk; stub = add('ec2')
    stub.add_response('describe_instances', {'Reservations': [{'Instances': [{'InstanceId': INSTANCE}]}]}, {})
    requests = aws.Requests({'retries': 0}); requests.observed_at = datetime.now(timezone.utc)
    requests.environment_boundaries_policy = native.normalize(options(), [SCOPE])
    result = native.workloads(requests, session, REGION, ACCOUNT)
    assert result.status == 'partial' and result.error['code'] == 'environment_cross_service_workload_universe_unresolved'
    row, = result.items
    assert (row['id'], row['Environment'], row['BoundaryId']) == (ARN, 'production', ACCOUNT)
    assert row['_provenance']['source_operation'] == 'ec2:DescribeInstances'
    assert row['_provenance']['classification_source'] == 'explicit_owner_criteria'
    assert requests.calls == 1
    stub.assert_no_pending_responses()


def test_unclassified_or_missing_native_workloads_never_become_empty_complete():
    class Reads:
        observed_at = datetime.now(timezone.utc)
        environment_boundaries_policy = native.normalize(options(), [SCOPE])
        def pages(self, *args): return aws.ReadResult([{'InstanceId': 'i-11111111111111111'}], 'collected')
    result = native.workloads(Reads(), None, REGION, ACCOUNT)
    assert result.status == 'partial' and result.items == []
    assert result.error['code'] == 'environment_classification_absent_from_native_inventory'


def test_missing_owner_does_not_call_sdk_and_does_not_invent_link_absence():
    class Reads:
        def pages(self, *args): raise AssertionError('No SDK read authorized by missing criteria')
    for fetcher in (native.workloads, native.boundary_links):
        result = fetcher(Reads(), None, REGION, ACCOUNT)
        assert result.status == 'not_collected' and result.items == []


@pytest.mark.parametrize('mode', ['fresh', 'stale', 'missing', 'partial'])
def test_external_link_import_preserves_source_and_never_certifies_universe(mode):
    raw = options(); policy = raw['compliance_parameters'][native.NAMESPACE]
    if mode != 'missing':
        policy['boundary_evidence'] = evidence(policy, mode != 'partial')
        if mode == 'stale': policy['boundary_evidence']['observed_at'] = (datetime.now(timezone.utc)-timedelta(days=1)).isoformat()
        if mode == 'partial': policy['boundary_evidence']['observations'].pop()
    requests = aws.Requests({}); requests.observed_at = datetime.now(timezone.utc)
    requests.environment_boundaries_policy = native.normalize(raw, [SCOPE])
    result = native.boundary_links(requests, None, REGION, ACCOUNT)
    assert requests.calls == 0
    if mode in {'stale', 'missing'}:
        assert result.status == 'not_collected' and result.items == []
    else:
        assert result.status == 'partial' and result.items
        assert all(row['Reachable'] is False and row['_provenance']['evidence_source'] == 'external_observation_import'
                   and row['_provenance']['native_aws_reachability_claimed'] is False for row in result.items)


def test_public_collector_and_bulk_owner_merge_leave_real_signed_control_unknown(sdk, monkeypatch):
    session, add = sdk
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'unit-pinned'))
    sts = add('sts'); sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/auditor', 'UserId': 'reviewer'}, {})
    org = add('organizations')
    org.add_response('describe_organization', {'Organization': {'Id': 'o-abcdefghij', 'MasterAccountId': OTHER}}, {})
    org.add_response('list_accounts', {'Accounts': [
        {'Id': ident, 'Arn': f'arn:aws:organizations::{OTHER}:account/o-abcdefghij/{ident}', 'State': 'ACTIVE'}
        for ident in [OTHER, ACCOUNT]]}, {})
    ec2 = add('ec2'); ec2.add_response('describe_instances', {'Reservations': [{'Instances': [{'InstanceId': INSTANCE}]}]}, {})
    raw = options(); raw['service_concurrency'] = 1
    policy = raw['compliance_parameters'][native.NAMESPACE]; policy['boundary_evidence'] = evidence(policy)
    snapshot = collect_bulk(aws, {'provider': 'aws', 'scopes': [SCOPE], 'options': raw},
                            ['aws_organization_account', 'environment_workload_resource', 'environment_boundary_link'])
    assert snapshot['metadata']['parameters']['environment_boundaries'] == policy['environment_boundaries']
    workloads = next(c for c in snapshot['collections'] if c['type'] == 'environment_workload_resource')
    links = next(c for c in snapshot['collections'] if c['type'] == 'environment_boundary_link')
    assert workloads['status'] == links['status'] == 'partial'
    assert workloads['items'][0]['Environment'] == 'production'
    assert links['items'][0]['_provenance']['native_aws_reachability_claimed'] is False
    assert {row['status'] for row in evaluate_snapshot(snapshot, checks=[CHECK])['findings']} == {'UNKNOWN'}
    org.assert_no_pending_responses(); ec2.assert_no_pending_responses(); sts.assert_no_pending_responses()


@pytest.mark.parametrize('unsafe', ['password=do-not-persist', {'Variables': {'SECRET': 'do-not-persist'}}])
def test_public_environment_enum_exception_keeps_other_values_redacted(sdk, monkeypatch, unsafe):
    session, add = sdk
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'unit-pinned'))
    sts = add('sts'); sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/auditor', 'UserId': 'reviewer'}, {})
    monkeypatch.setitem(aws.FETCHERS, 'environment_workload_resource', lambda *args: aws.ReadResult(
        [{'id': ARN, 'Environment': unsafe}], 'partial'))
    snapshot = aws.collect({'provider': 'aws', 'scopes': [SCOPE], 'options': {'service_concurrency': 1}},
                           ['environment_workload_resource'])
    collection = next(row for row in snapshot['collections'] if row['type'] == 'environment_workload_resource')
    assert 'Environment' not in collection['items'][0]
    assert aws._safe({'Environment': 'production'}) == {}
    assert 'do-not-persist' not in str(snapshot)
    sts.assert_no_pending_responses()
