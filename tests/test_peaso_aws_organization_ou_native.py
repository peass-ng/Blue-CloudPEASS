"""Actual Organizations SDK reads, complete roster and scoped parent joins."""
from copy import deepcopy
import pytest

from tests.test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from peaso.collectors import aws, aws_organization_ou_native as native
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

MEMBER = '999999999999'
ORG = 'o-1234567890'
PROD, SENSITIVE, ROOT = 'ou-abcd-12345678', 'ou-abcd-87654321', 'r-abcd'
CONTROL = 'aws_cis_organization_units_environment_sensitivity'


def account(aid, state='ACTIVE'):
    return {'Id': aid, 'State': state, 'Arn': f'arn:aws:organizations::{ACCOUNT}:account/{ORG}/{aid}'}


def roster():
    return [account(ACCOUNT), account(MEMBER)]


def parent(stub, child, pid, kind):
    stub.add_response('list_parents', {'Parents': [{'Id': pid, 'Type': kind}]}, {'ChildId': child})


def unit(stub, uid, name, org=ORG):
    stub.add_response('describe_organizational_unit', {'OrganizationalUnit': {
        'Id': uid, 'Arn': f'arn:aws:organizations::{ACCOUNT}:ou/{org}/{uid}', 'Name': name}}, {'OrganizationalUnitId': uid})


def paths(stub, name='prod'):
    parent(stub, ACCOUNT, ROOT, 'ROOT')
    parent(stub, MEMBER, PROD, 'ORGANIZATIONAL_UNIT'); unit(stub, PROD, name)
    parent(stub, PROD, SENSITIVE, 'ORGANIZATIONAL_UNIT'); unit(stub, SENSITIVE, 'sensitive')
    parent(stub, SENSITIVE, ROOT, 'ROOT')


def requests(**kw):
    return aws.Requests({'service_concurrency': 1, 'retry_attempts': 1, **kw})


def verdict(read, accounts):
    scope = ACCOUNT + '/global'
    snapshot = make_snapshot('aws', [scope], [
        {'type': 'organization_account', 'scope': scope, 'service': 'organizations', 'status': 'collected', 'items': accounts},
        {'type': 'organization_parent', 'scope': scope, 'service': 'organizations', 'status': read.status, 'items': read.items,
         **({'error': read.error} if read.error else {})}], metadata={'parameters': {
            'organization_management_account_id': ACCOUNT, 'approved_environment_ou_patterns': ['prod'],
            'approved_sensitivity_ou_patterns': ['sensitive']}})
    return next(f['status'] for f in evaluate_snapshot(snapshot, checks=[CONTROL])['findings'] if f['check_id'] == CONTROL)


@pytest.mark.parametrize('name,expected', [('prod', 'PASS'), ('dev', 'FAIL')])
def test_sdk_collector_covers_every_active_member_and_native_names(sdk, name, expected):
    session, add = sdk; stub = add('organizations')
    stub.add_response('list_accounts', {'Accounts': roster()}, {})
    paths(stub, name)
    reader = requests(); read = native.collect(reader, session, REGION, ACCOUNT)
    assert read.status == 'collected' and len(read.items) == 4 and reader.calls == 7
    assert all(r['InheritanceComplete'] and r['ParentCollection']['complete'] for r in read.items)
    assert verdict(read, roster()) == expected
    stub.assert_no_pending_responses()


def test_reuses_complete_supplied_roster_without_another_list_accounts(sdk):
    session, add = sdk; stub = add('organizations'); paths(stub)
    reader = requests()
    read = native.collect(reader, session, REGION, ACCOUNT, aws.ReadResult(roster()))
    assert read.status == 'collected' and reader.calls == 6
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('status', ['partial', 'denied', 'timeout', 'not_collected'])
def test_incomplete_supplied_roster_never_starts_scope_traversal(sdk, status):
    session, add = sdk; stub = add('organizations'); reader = requests()
    read = native.collect(reader, session, REGION, ACCOUNT, aws.ReadResult(roster(), status, {'code': 'fixture_incomplete'}))
    assert read.status not in ('collected', 'empty') and read.items == [] and reader.calls == 0
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('mode', ['foreign_org', 'duplicate_account', 'unknown_state', 'contradictory_legacy', 'missing_current', 'malformed_arn'])
def test_bad_complete_roster_never_authorizes_native_scope_hops(sdk, mode):
    session, add = sdk; stub = add('organizations'); rows = roster()
    if mode == 'foreign_org': rows[1]['Arn'] = rows[1]['Arn'].replace(ORG, 'o-0987654321')
    elif mode == 'duplicate_account': rows.append(deepcopy(rows[0]))
    elif mode == 'unknown_state': rows[1]['State'] = 'UNKNOWN'
    elif mode == 'contradictory_legacy': rows[1]['Status'] = 'SUSPENDED'
    elif mode == 'missing_current': rows.pop(0)
    elif mode == 'malformed_arn': rows[1]['Arn'] = rows[1]['Arn'].replace(MEMBER, '000000000000')
    reader = requests(); read = native.collect(reader, session, REGION, ACCOUNT, aws.ReadResult(rows))
    assert read.status == 'malformed' and read.items == [] and reader.calls == 0
    stub.assert_no_pending_responses()


def test_native_pagination_consumes_empty_intermediate_accounts_page(sdk):
    session, add = sdk; stub = add('organizations')
    stub.add_response('list_accounts', {'Accounts': [], 'NextToken': 'next'}, {})
    stub.add_response('list_accounts', {'Accounts': roster()}, {'NextToken': 'next'})
    paths(stub)
    reader = requests(); read = native.collect(reader, session, REGION, ACCOUNT)
    assert read.status == 'collected' and reader.calls == 8
    stub.assert_no_pending_responses()


def test_pagination_budget_stops_before_any_parent_request(sdk):
    session, add = sdk; stub = add('organizations')
    stub.add_response('list_accounts', {'Accounts': roster(), 'NextToken': 'next'}, {})
    reader = requests(max_pages=1); read = native.collect(reader, session, REGION, ACCOUNT)
    assert read.status not in ('collected', 'empty') and reader.calls == 1 and read.items == []
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('mode', ['parent_denied', 'unit_denied', 'foreign_unit', 'cycle', 'invalid_parent_type'])
def test_incomplete_member_paths_preserve_partial_not_clean_pass(sdk, mode):
    session, add = sdk; stub = add('organizations')
    parent(stub, ACCOUNT, ROOT, 'ROOT')
    if mode == 'parent_denied':
        stub.add_client_error('list_parents', 'AccessDeniedException', expected_params={'ChildId': MEMBER})
    else:
        parent(stub, MEMBER, PROD, 'ROOT' if mode == 'invalid_parent_type' else 'ORGANIZATIONAL_UNIT')
        if mode == 'unit_denied':
            stub.add_client_error('describe_organizational_unit', 'AccessDeniedException', expected_params={'OrganizationalUnitId': PROD})
        elif mode != 'invalid_parent_type':
            unit(stub, PROD, 'prod', 'o-0987654321' if mode == 'foreign_unit' else ORG)
            if mode == 'cycle': parent(stub, PROD, PROD, 'ORGANIZATIONAL_UNIT')
    reader = requests(); read = native.collect(reader, session, REGION, ACCOUNT, aws.ReadResult(roster()))
    assert read.status == 'partial' and read.items and read.error
    assert verdict(read, roster()) == 'UNKNOWN'
    if mode == 'cycle': assert any(r['InheritanceComplete'] is False for r in read.items)
    stub.assert_no_pending_responses()


def test_inactive_member_has_no_parent_hops_and_native_state_overrides_legacy(sdk):
    session, add = sdk; stub = add('organizations')
    rows = roster(); rows[1].update(State='PENDING_ACTIVATION', Status='ACTIVE')
    parent(stub, ACCOUNT, ROOT, 'ROOT')
    reader = requests(); read = native.collect(reader, session, REGION, ACCOUNT, aws.ReadResult(rows))
    assert read.status == 'collected' and reader.calls == 1
    assert verdict(read, rows) == 'PASS'
    stub.assert_no_pending_responses()


def test_shared_ou_reads_reuse_single_flight_cache_and_unique_edges(sdk):
    session, add = sdk; stub = add('organizations'); other = '888888888888'
    rows = roster() + [account(other)]
    parent(stub, ACCOUNT, ROOT, 'ROOT')
    parent(stub, other, PROD, 'ORGANIZATIONAL_UNIT'); unit(stub, PROD, 'prod')
    parent(stub, PROD, SENSITIVE, 'ORGANIZATIONAL_UNIT'); unit(stub, SENSITIVE, 'sensitive')
    parent(stub, SENSITIVE, ROOT, 'ROOT')
    parent(stub, MEMBER, PROD, 'ORGANIZATIONAL_UNIT')
    reader = requests(); read = native.collect(reader, session, REGION, ACCOUNT, aws.ReadResult(rows))
    assert read.status == 'collected' and len(read.items) == 5
    assert reader.calls == 7 and reader.cache_hits >= 4
    assert len({row['ChildId'] for row in read.items}) == len(read.items)
    assert verdict(read, rows) == 'PASS'
    stub.assert_no_pending_responses()


def test_member_paths_run_in_parallel_with_fixed_worker_bound():
    from threading import Barrier, Lock
    barrier, lock = Barrier(2, timeout=2), Lock()
    accounts = [account(aid) for aid in [ACCOUNT, MEMBER, '888888888888', '777777777777']]
    class Reader:
        workers = 2
        active = maximum = calls = 0
        def pages(self, session, service, region, operation, expression, **kwargs):
            assert service == 'organizations' and operation == 'list_parents' and expression == 'Parents'
            assert kwargs['ChildId'] in {r['Id'] for r in accounts}
            with lock:
                self.active += 1; self.calls += 1; self.maximum = max(self.maximum, self.active)
            try:
                barrier.wait()
                return aws.ReadResult([{'Id': ROOT, 'Type': 'ROOT'}])
            finally:
                with lock: self.active -= 1
    reader = Reader()
    result = native.collect(reader, None, REGION, ACCOUNT, aws.ReadResult(accounts))
    assert result.status == 'collected' and len(result.items) == 4
    assert reader.maximum == 2 and reader.active == 0 and reader.calls == 4
