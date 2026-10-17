"""Passive Organizations identity projection; no invented environment evidence."""
from copy import deepcopy
import pytest

from test_peaso_aws_bulk_inventory import sdk, ACCOUNT
from peaso.collectors import aws, aws_organizations_native as native
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

REGION = 'eu-west-1'
MANAGEMENT = '111111111111'
ORG = {'Id': 'o-abcdefghij', 'MasterAccountId': MANAGEMENT, 'FeatureSet': 'ALL'}
CHECK = 'aws_organizations_environment_account_separation'


def member(identifier, state='ACTIVE'):
    return {'Id': identifier, 'Arn': f'arn:aws:organizations::{MANAGEMENT}:account/{ORG["Id"]}/{identifier}',
            'State': state, 'Name': 'not-persisted', 'Email': 'not-persisted@example.invalid'}


def describe(stub):
    stub.add_response('describe_organization', {'Organization': ORG}, {})


def test_real_sdk_pagination_keeps_empty_page_and_native_identity(sdk):
    session, add = sdk
    stub = add('organizations'); describe(stub)
    stub.add_response('list_accounts', {'Accounts': [], 'NextToken': 'second'}, {})
    stub.add_response('list_accounts', {'Accounts': [member(MANAGEMENT)], 'NextToken': 'third'}, {'NextToken': 'second'})
    stub.add_response('list_accounts', {'Accounts': [member(ACCOUNT, 'SUSPENDED')]}, {'NextToken': 'third'})
    requests = aws.Requests({'retries': 0})
    result = native.account_identities(requests, session, REGION, ACCOUNT)
    assert result.status == 'collected' and requests.calls == 4
    assert [row['Id'] for row in result.items] == [MANAGEMENT, ACCOUNT]
    assert result.items[1]['State'] == 'SUSPENDED'
    for row in result.items:
        assert row['AccountId'] == ACCOUNT and row['Region'] == REGION
        assert row['OrganizationId'] == ORG['Id'] and row['ManagementAccountId'] == MANAGEMENT
        assert row['_provenance']['native_arn'] == member(row['Id'])['Arn']
        assert row['_provenance']['read_only'] is True
        assert not {'Arn', 'Name', 'Email', 'Environment', 'BoundaryId', 'Reachable', 'Complete'} & row.keys()
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('failure', ['describe_denied', 'accounts_denied', 'second_page_denied', 'page_budget'])
def test_denied_or_incomplete_inventory_cannot_be_complete(sdk, failure):
    session, add = sdk
    stub = add('organizations')
    if failure == 'describe_denied':
        stub.add_client_error('describe_organization', 'AccessDeniedException', expected_params={})
    else:
        describe(stub)
        if failure == 'accounts_denied':
            stub.add_client_error('list_accounts', 'AccessDeniedException', expected_params={})
        else:
            stub.add_response('list_accounts', {'Accounts': [member(MANAGEMENT)], 'NextToken': 'second'}, {})
            if failure == 'second_page_denied':
                stub.add_client_error('list_accounts', 'AccessDeniedException', expected_params={'NextToken': 'second'})
    options = {'retries': 0, **({'max_pages': 1} if failure == 'page_budget' else {})}
    result = native.account_identities(aws.Requests(options), session, REGION, ACCOUNT)
    assert result.status not in ('collected', 'empty') and result.items == []
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('mode', ['duplicate', 'foreign_organization', 'foreign_management', 'arn_id_mismatch',
                                  'unknown_state', 'missing_state', 'missing_audited', 'missing_management', 'empty'])
def test_identity_or_membership_contradiction_remains_unavailable(sdk, mode):
    session, add = sdk
    stub = add('organizations'); describe(stub)
    rows = [member(MANAGEMENT), member(ACCOUNT)]
    if mode == 'duplicate': rows.append(deepcopy(rows[-1]))
    elif mode == 'foreign_organization': rows[-1]['Arn'] = rows[-1]['Arn'].replace(ORG['Id'], 'o-foreignorg')
    elif mode == 'foreign_management': rows[-1]['Arn'] = rows[-1]['Arn'].replace(MANAGEMENT, '999999999999')
    elif mode == 'arn_id_mismatch': rows[-1]['Arn'] = rows[-1]['Arn'].replace(ACCOUNT, '999999999999')
    elif mode == 'unknown_state': rows[-1]['State'] = 'UNKNOWN'
    elif mode == 'missing_state': rows[-1].pop('State')
    elif mode == 'missing_audited': rows.pop()
    elif mode == 'missing_management': rows.pop(0)
    elif mode == 'empty': rows = []
    # The SDK permits unknown strings: the producer must validate their semantics.
    stub.add_response('list_accounts', {'Accounts': rows}, {})
    result = native.account_identities(aws.Requests({'retries': 0}), session, REGION, ACCOUNT)
    assert result.status in ('partial', 'malformed')
    assert result.error['code'].startswith('organization_account_')
    stub.assert_no_pending_responses()


def test_status_legacy_normalization_and_non_dict_rejection():
    class Reads:
        def detail(self, *args): return {'collection_status': 'collected', 'Organization': ORG}
        def pages(self, *args): return aws.ReadResult(self.members, 'collected')
    reads = Reads(); reads.members = [member(MANAGEMENT), member(ACCOUNT)]
    for row in reads.members: row['Status'] = row.pop('State')
    result = native.account_identities(reads, None, REGION, ACCOUNT)
    assert result.status == 'collected' and all(row['State'] == 'ACTIVE' for row in result.items)
    reads.members = [None]
    assert native.account_identities(reads, None, REGION, ACCOUNT).status == 'malformed'


def test_actual_collector_dispatch_preserves_unknown_without_workloads_and_links(sdk, monkeypatch):
    session, add = sdk
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'unit-pinned'))
    sts = add('sts')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/auditor', 'UserId': 'reviewer'}, {})
    stub = add('organizations'); describe(stub)
    stub.add_response('list_accounts', {'Accounts': [member(MANAGEMENT), member(ACCOUNT)]}, {})
    snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT + '/' + REGION],
                            'options': {'service_concurrency': 1, 'retries': 0}}, ['aws_organization_account'])
    collection, = [row for row in snapshot['collections'] if row['type'] == 'aws_organization_account']
    assert collection['type'] == 'aws_organization_account' and collection['status'] == 'collected'
    assert collection['scope'] == ACCOUNT + '/' + REGION
    assert 'aws_organization_account' in aws.AWS_TYPES and 'aws_organization_account' not in aws.GLOBAL_TYPES
    assert {'organization_effective_scp', 'organization_tag_policy', 'organization_resource_policy'} <= aws.GLOBAL_TYPES
    # Native account facts are accepted, but approved boundaries alone cannot
    # invent complete workload environments or cross-account link observations.
    snapshot = make_snapshot('aws', snapshot['scopes'], snapshot['collections'], metadata={
        'parameters': {'environment_boundaries': {'production': [ACCOUNT], 'development': [MANAGEMENT]}}})
    findings = evaluate_snapshot(snapshot, checks=[CHECK])['findings']
    assert findings and {row['status'] for row in findings} == {'UNKNOWN'}
    assert all('environment_workload_resource' in row['evidence'].get('reason', '') for row in findings)
    stub.assert_no_pending_responses(); sts.assert_no_pending_responses()
