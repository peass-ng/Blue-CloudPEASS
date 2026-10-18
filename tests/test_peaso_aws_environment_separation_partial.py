"""A native counterexample can fail separation; partial coverage cannot pass it."""
from copy import deepcopy
from datetime import datetime, timezone
import pytest
from peaso.snapshot import make_snapshot
from tests.archived_check_contract import evaluate_snapshot

ACCOUNT = '123456789012'
OTHER = '111111111111'
REGION = 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
STAMP = '2026-10-16T02:00:00+00:00'
CHECK = 'aws_organizations_environment_account_separation'
NS = 'aws_environment_separation'


def observed(number=0, environment='production'):
    ident = 'i-' + str(number).zfill(17)
    return {'id': f'arn:aws:ec2:{REGION}:{ACCOUNT}:instance/{ident}', 'ResourceKind': 'instance',
            'ResourceId': ident, 'Environment': environment, 'BoundaryId': ACCOUNT,
            '_provenance': {'source_operation': 'ec2:DescribeInstances', 'read_only': True,
                            'classification_source': 'explicit_owner_criteria', 'native_scope': SCOPE}}


def snapshot(rows=None, mode='unapproved', workload_status='partial', links_status='not_collected'):
    rows = [observed()] if rows is None else rows
    bounds = {'production': [OTHER if mode == 'unapproved' else ACCOUNT],
              'development': [ACCOUNT if mode == 'shared' else OTHER]}
    owner = {'status': 'collected', 'scope': SCOPE, 'observed_at': STAMP, 'max_age_seconds': 300,
             'environment_boundaries': bounds, 'workload_classifications': [
                 {'resource_arn': row['id'], 'environment': row['Environment']} for row in rows]}
    return make_snapshot('aws', [SCOPE], [
        {'type': 'aws_organization_account', 'scope': SCOPE, 'service': 'organizations', 'status': 'collected', 'items': [{'AccountId': ACCOUNT}]},
        {'type': 'environment_workload_resource', 'scope': SCOPE, 'service': 'ec2', 'status': workload_status,
         'items': rows, 'error': {'code': 'cross_service_unresolved'}},
        {'type': 'environment_boundary_link', 'scope': SCOPE, 'service': 'ec2', 'status': links_status, 'items': []}],
        metadata={'parameters': {NS: owner, 'environment_boundaries': deepcopy(bounds)}}, created_at=STAMP)


def verdict(value):
    findings = evaluate_snapshot(value, checks=[CHECK])['findings']
    assert len(findings) == 1
    return findings[0]['status']


@pytest.mark.parametrize('mode', ['unapproved', 'shared'])
def test_native_partial_counterexample_precedes_missing_connectivity(mode):
    rows = [observed(), observed(1, 'test')] if mode == 'shared' else [observed()]
    assert verdict(snapshot(rows, mode)) == 'FAIL'


@pytest.mark.parametrize('status', ['partial', 'denied', 'timeout', 'unknown', 'malformed', 'not_collected'])
def test_collection_failure_does_not_hide_a_valid_native_counterexample(status):
    value = snapshot()
    value['collections'][1]['error']['code'] = status
    from peaso.snapshot import seal
    assert verdict(seal(value)) == 'FAIL'


@pytest.mark.parametrize('mode', ['missing_namespace', 'stale', 'future', 'classification_mismatch',
                                  'wrong_operation', 'not_readonly', 'imported', 'foreign_scope',
                                  'foreign_partition', 'foreign_arn_account', 'foreign_arn_region',
                                  'wrong_instance', 'foreign_boundary', 'duplicate_arn',
                                  'competing_flat', 'foreign_envelope', 'wrong_account_field', 'wrong_region_field'])
def test_untrusted_partial_observation_never_becomes_native_failure_or_pass(mode):
    value = snapshot(); params = value['metadata']['parameters']; owner = params[NS]
    collection = value['collections'][1]; row = collection['items'][0]
    if mode == 'missing_namespace': params.pop(NS)
    elif mode == 'stale': owner['observed_at'] = '2026-10-15T02:00:00+00:00'
    elif mode == 'future': owner['observed_at'] = '2026-10-17T02:00:00+00:00'
    elif mode == 'classification_mismatch': owner['workload_classifications'][0]['environment'] = 'development'
    elif mode == 'wrong_operation': row['_provenance']['source_operation'] = 'external:Imported'
    elif mode == 'not_readonly': row['_provenance']['read_only'] = 1
    elif mode == 'imported': row['_provenance']['evidence_source'] = 'external_observation_import'
    elif mode == 'foreign_scope': row['_provenance']['native_scope'] = OTHER + '/' + REGION
    elif mode == 'foreign_partition': row['id'] = row['id'].replace('arn:aws:', 'arn:aws-cn:')
    elif mode == 'foreign_arn_account': row['id'] = row['id'].replace(ACCOUNT, OTHER)
    elif mode == 'foreign_arn_region': row['id'] = row['id'].replace(REGION, 'eu-west-1')
    elif mode == 'wrong_instance': row['ResourceId'] = 'i-11111111111111111'
    elif mode == 'foreign_boundary': row['BoundaryId'] = OTHER
    elif mode == 'duplicate_arn': collection['items'].append(deepcopy(row))
    elif mode == 'competing_flat': params['environment_boundaries']['development'] = ['999999999999']
    elif mode == 'foreign_envelope': collection['scope'] = OTHER + '/' + REGION
    elif mode == 'wrong_account_field': row['AccountId'] = OTHER
    elif mode == 'wrong_region_field': row['Region'] = 'eu-west-1'
    from peaso.snapshot import seal
    assert verdict(seal(value)) == 'UNKNOWN'


@pytest.mark.parametrize('links_status', ['partial', 'denied', 'not_collected', 'collected'])
def test_partial_safe_subset_cannot_pass_or_adopt_imported_reachability(links_status):
    value = snapshot(mode='approved', links_status=links_status)
    links = value['collections'][2]
    links['items'] = [] if links_status in ('denied', 'not_collected') else [{'id': ACCOUNT + '->' + OTHER, 'SourceBoundaryId': ACCOUNT,
                      'DestinationBoundaryId': OTHER, 'Reachable': True,
                      '_provenance': {'evidence_source': 'external_observation_import',
                                      'native_aws_reachability_claimed': False}}]
    from peaso.snapshot import seal
    assert verdict(seal(value)) == 'UNKNOWN'


@pytest.mark.parametrize('complete_links,expected', [(True, 'PASS'), (False, 'UNKNOWN')])
def test_original_complete_inventory_pass_contract_remains(complete_links, expected):
    value = snapshot(mode='approved', workload_status='collected',
                     links_status='empty' if complete_links else 'not_collected')
    value['collections'][1]['items'] = [
        {'Environment': 'production', 'BoundaryId': ACCOUNT},
        {'Environment': 'development', 'BoundaryId': OTHER}]
    from peaso.snapshot import seal
    assert verdict(seal(value)) == expected


def test_full_known_violation_does_not_require_connectivity_for_failure():
    value = snapshot(workload_status='collected')
    assert verdict(value) == 'FAIL'


from test_peaso_aws_bulk_inventory import sdk

@pytest.mark.parametrize('mode,expected', [('unapproved', 'FAIL'), ('shared', 'FAIL'), ('approved', 'UNKNOWN')])
def test_actual_native_org_ec2_public_collector_dispatch(sdk, monkeypatch, mode, expected):
    from peaso.collectors import aws
    from peaso.collectors.bulk_evidence import collect as collect_bulk
    session, add = sdk
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'unit-inert'))
    sts = add('sts'); sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/auditor', 'UserId': 'fixture'}, {})
    org = add('organizations')
    org.add_response('describe_organization', {'Organization': {'Id': 'o-abcdefghij', 'MasterAccountId': OTHER}}, {})
    org.add_response('list_accounts', {'Accounts': [
        {'Id': ident, 'Arn': f'arn:aws:organizations::{OTHER}:account/o-abcdefghij/{ident}', 'State': 'ACTIVE'}
        for ident in [OTHER, ACCOUNT]]}, {})
    rows = [observed(), observed(1, 'test')] if mode == 'shared' else [observed()]
    ec2 = add('ec2'); ec2.add_response('describe_instances', {'Reservations': [
        {'Instances': [{'InstanceId': row['ResourceId']} for row in rows]}]}, {})
    raw = deepcopy(snapshot(rows, mode)['metadata']['parameters'][NS])
    raw['observed_at'] = datetime.now(timezone.utc).isoformat()
    actual = collect_bulk(aws, {'provider': 'aws', 'scopes': [SCOPE], 'options': {
        'service_concurrency': 1, 'compliance_parameters': {NS: raw}}},
        ['aws_organization_account', 'environment_workload_resource', 'environment_boundary_link'])
    workload = next(c for c in actual['collections'] if c['type'] == 'environment_workload_resource')
    assert workload['status'] == 'partial' and workload['items']
    assert {f['status'] for f in evaluate_snapshot(actual, checks=[CHECK])['findings']} == {expected}
    org.assert_no_pending_responses(); ec2.assert_no_pending_responses(); sts.assert_no_pending_responses()
