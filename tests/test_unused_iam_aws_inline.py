from copy import deepcopy
import pytest
from peaso import unused_iam_aws_inline as subject

ACCOUNT = '123456789012'
SCOPE = ACCOUNT+'/global'
NOW = '2026-10-21T12:00:00Z'
PROOF = {'operation': 'iam:GetAccountAuthorizationDetails', 'native_response_complete': True}


def fixture(bound=False):
    group = {'GroupName': 'synthetic', 'GroupId': 'AGPA0123456789ABCDE', 'Arn': f'arn:aws:iam::{ACCOUNT}:group/team/synthetic',
        'GroupPolicyList': [{'PolicyName': 'StorageReader', 'PolicyDocument': {'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Action': ['s3:GetObject'], 'Resource': 'arn:aws:s3:::synthetic-data/*'}]}}], '_provenance': deepcopy(PROOF)}
    user = {'UserName': 'synthetic-user', 'UserId': 'AIDA0123456789ABCDE', 'Arn': f'arn:aws:iam::{ACCOUNT}:user/synthetic-user',
            'GroupList': ['synthetic'] if bound else [], '_provenance': deepcopy(PROOF)}
    index = {'context': {'provider': 'aws', 'scope': SCOPE, 'created_at': NOW}, 'collections': {}}
    for kind, items in [('iam_group', [group]), ('iam_user', [user])]:
        index[kind] = [{'type': kind, 'scope': SCOPE, 'data': row} for row in items]
        index['collections'][kind] = [{'type': kind, 'scope': SCOPE, 'service': 'iam', 'status': 'collected', 'items': items}]
    return group, index


@pytest.mark.parametrize('bound', [True, False])
def test_inline_policies_have_exact_members_or_fail_with_full_documents(bound):
    group, index = fixture(bound);before = deepcopy(index)
    status, evidence = subject.evaluate(group, index)
    assert status == ('PASS' if bound else 'FAIL'), evidence
    assert evidence['inline_policies'] == group['GroupPolicyList']
    assert evidence['inline_policies'][0]['PolicyDocument']['Statement'][0]['Action'] == ['s3:GetObject']
    assert index == before


@pytest.mark.parametrize('mode', ['foreign_account', 'foreign_context', 'foreign_user', 'bad_id', 'missing_arn', 'missing_proof', 'incomplete_proof',
    'projection', 'collection_scope', 'service', 'partial_users', 'denied', 'partial_denied', 'field_denied', 'bad_groups', 'duplicate_group', 'duplicate_user',
    'bad_policy', 'duplicate_policy', 'missing_document', 'missing_effect', 'bad_document', 'group_field_denied'])
def test_no_absence_without_current_complete_native_memberships(mode):
    group, index = fixture();expected = 'UNKNOWN'
    users = index['collections']['iam_user'][0];user = users['items'][0]
    if mode == 'foreign_account': group['Arn'] = group['Arn'].replace(ACCOUNT, '999999999999')
    elif mode == 'foreign_context': index['context']['provider'] = 'gcp'
    elif mode == 'foreign_user': user['Arn'] = user['Arn'].replace(ACCOUNT, '999999999999')
    elif mode == 'bad_id': group['GroupId'] = 'unknown'
    elif mode == 'missing_arn': group.pop('Arn')
    elif mode == 'missing_proof': group.pop('_provenance')
    elif mode == 'incomplete_proof': user['_provenance']['native_response_complete'] = False
    elif mode == 'projection': index['iam_user'] = []
    elif mode == 'collection_scope': users['scope'] = '999999999999/global'
    elif mode == 'service': users['service'] = 'identitystore'
    elif mode == 'partial_users': users['status'] = 'partial'
    elif mode == 'denied': users.update(status='denied', items=[]);index['iam_user'] = [];expected = 'DENIED'
    elif mode == 'partial_denied': users.update(status='partial', error={'cause_status': 'denied'});expected = 'DENIED'
    elif mode == 'field_denied': user['_coverage'] = {'GroupList': {'status': 'denied'}};expected = 'DENIED'
    elif mode == 'bad_groups': user['GroupList'] = [None]
    elif mode == 'duplicate_group': index['collections']['iam_group'][0]['items'].append(deepcopy(group));index['iam_group'].append(deepcopy(index['iam_group'][0]))
    elif mode == 'duplicate_user': users['items'].append(deepcopy(user));index['iam_user'].append(deepcopy(index['iam_user'][0]))
    elif mode == 'bad_policy': group['GroupPolicyList'] = [None]
    elif mode == 'duplicate_policy': group['GroupPolicyList'].append(deepcopy(group['GroupPolicyList'][0]))
    elif mode == 'missing_document': group['GroupPolicyList'][0].pop('PolicyDocument')
    elif mode == 'missing_effect': group['GroupPolicyList'][0]['PolicyDocument']['Statement'][0].pop('Effect')
    elif mode == 'bad_document': group['GroupPolicyList'][0]['PolicyDocument'] = 'unparsed'
    elif mode == 'group_field_denied': group['_coverage'] = {'GroupPolicyList': {'status': 'denied'}};expected = 'DENIED'
    assert subject.evaluate(group, index)[0] == expected


def test_native_empty_inventory_and_documented_omissions():
    group, index = fixture()
    index['collections']['iam_user'][0].update(status='empty', items=[]);index['iam_user'] = []
    assert subject.evaluate(group, index)[0] == 'FAIL'
    group['GroupPolicyList'] = []
    assert subject.evaluate(group, index)[0] == 'NOT_APPLICABLE'
    group.pop('GroupPolicyList')
    assert subject.evaluate(group, index)[0] == 'NOT_APPLICABLE'
    group, index = fixture()
    index['iam_user'][0]['data'].pop('GroupList')
    assert subject.evaluate(group, index)[0] == 'FAIL'


def test_positive_member_survives_unrelated_partial_inventory_and_group_name_case():
    group, index = fixture(True)
    index['iam_user'][0]['data']['GroupList'] = ['SYNTHETIC']
    index['collections']['iam_user'][0].update(status='partial', error={'cause_status': 'denied'})
    assert subject.evaluate(group, index)[0] == 'PASS'


def test_conflicting_duplicate_user_cannot_certify_a_current_member():
    group, index = fixture(True)
    duplicate = deepcopy(index['iam_user'][0]);duplicate['data']['GroupList'] = []
    index['iam_user'].append(duplicate)
    index['collections']['iam_user'][0]['items'].append(duplicate['data'])
    assert subject.evaluate(group, index)[0] == 'UNKNOWN'


def test_membership_join_is_memoized_per_existing_engine_index(monkeypatch):
    from peaso.checks.facts import MemoIndex
    group, index = fixture(True)
    calls = [];old = subject.records
    def tracked(index, kind, scope):
        if kind == 'iam_user': calls.append(kind)
        return old(index, kind, scope)
    monkeypatch.setattr(subject, 'records', tracked)
    index = MemoIndex(index)
    assert subject.evaluate(group, index)[0] == 'PASS'
    assert subject.evaluate(group, index)[0] == 'PASS'
    assert calls == ['iam_user']


@pytest.mark.parametrize('mode', ['missing_action', 'both_actions', 'missing_resource', 'empty_resource', 'bad_condition'])
def test_policy_details_require_complete_action_resource_and_condition_shapes(mode):
    group, index = fixture()
    statement = group['GroupPolicyList'][0]['PolicyDocument']['Statement'][0]
    if mode == 'missing_action': statement.pop('Action')
    elif mode == 'both_actions': statement['NotAction'] = 'iam:*'
    elif mode == 'missing_resource': statement.pop('Resource')
    elif mode == 'empty_resource': statement['Resource'] = []
    elif mode == 'bad_condition': statement['Condition'] = None
    assert subject.evaluate(group, index)[0] == 'UNKNOWN'


def test_wildcards_and_not_action_are_retained_without_claiming_effective_access():
    group, index = fixture()
    statement = group['GroupPolicyList'][0]['PolicyDocument']['Statement'][0]
    statement.update(Action='*', Resource='*')
    assert subject.evaluate(group, index)[1]['inline_policies'][0]['PolicyDocument']['Statement'][0]['Action'] == '*'
    statement['NotAction'] = statement.pop('Action')
    assert subject.evaluate(group, index)[0] == 'FAIL'


@pytest.mark.parametrize('bound,partial,expected', [(False, False, 'FAIL'), (True, False, 'PASS'), (False, True, 'DENIED'), (True, True, 'PASS')])
def test_native_hardening_json_includes_inline_policy_names_and_documents(bound, partial, expected):
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    from peaso.engine import evaluate_snapshot, hydrate_frameworks
    from peaso.snapshot import make_snapshot
    check = next(c for c in CHECKS if c.id == subject.CHECK)
    assert check.category == 'hardening'
    case = CASES[subject.CHECK]
    for case_status in ('PASS', 'FAIL'):
        key = case_status.lower()
        assert check.evaluate(case[key], case[key+'_index'])[0] == case_status
    group, index = fixture(bound)
    if partial: index['collections']['iam_user'][0].update(status='partial', error={'code': 'AccessDenied', 'cause_status': 'denied'})
    collections = [deepcopy(c) for cs in index['collections'].values() for c in cs]
    report = hydrate_frameworks(evaluate_snapshot(make_snapshot('aws', [SCOPE], collections, created_at=NOW), categories=['hardening'], checks=[subject.CHECK]))
    finding = report['findings'][0]
    assert finding['status'] == expected, finding
    if expected in ('PASS', 'FAIL'):
        assert finding['evidence']['inline_policies'] == group['GroupPolicyList']
    assert 'HackTricks Cloud Best Practices' in finding['frameworks']
    assert len(finding['evidence']['summary'].splitlines()) == 3
