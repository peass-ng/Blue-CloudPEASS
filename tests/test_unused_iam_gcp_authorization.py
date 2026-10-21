from copy import deepcopy
import json
import pytest

from peaso import unused_iam_gcp_authorization as subject

SCOPE = 'projects/usage-project'
NOW = '2026-10-21T12:00:00Z'
MEMBER = 'serviceAccount:worker@usage-project.iam.gserviceaccount.com'


def proof(refs, **extra):
    return {'scope': SCOPE, 'collected_at': NOW, 'source_requests': refs, **extra}


def read(ref, url, method='GET', status='collected'):
    return {'id': ref, 'url': url, 'method': method, 'status': status, 'scope': SCOPE, 'http_status': 200 if status == 'collected' else 403}


def group_fixture(members=False):
    name = 'groups/synthetic'
    names = [name+'/memberships/member'] if members else []
    item = {'name': name, 'parent': 'customers/Csynthetic', 'groupKey': {'id': 'team@example.test'},
        'labels': {'cloudidentity.googleapis.com/groups.discussion_forum': ''},
        '_provenance': proof(['group-read'], representation='full'),
        '_coverage': {'directMemberships': {'status': 'collected', 'scope': SCOPE, 'group': name,
            'collected_at': NOW, 'source_requests': ['members-read']}},
        '_direct_membership_names': names, '_direct_membership_requests': ['members-read']}
    index = capture({'group': [item], 'group_membership': []}, [
        read('group-read', 'https://cloudidentity.googleapis.com/v1/groups'),
        read('members-read', 'https://cloudidentity.googleapis.com/v1/'+name+'/memberships')])
    return item, index


def grant_fixture(used=False):
    item = {'name': SCOPE+'/locations/global/insightTypes/google.iam.policy.Insight/insights/synthetic',
        'content': {'role': 'roles/viewer', 'member': MEMBER,
                    'condition': {'expression': ''}, 'exercisedPermissions': [{'permission': 'compute.instances.get'}] if used else [],
                    'inferredPermissions': []}, 'stateInfo': {'state': 'ACTIVE'}, 'category': 'SECURITY',
        'insightSubtype': 'PERMISSIONS_USAGE', 'observationPeriod': '7776000s',
        'lastRefreshTime': '2026-10-20T07:00:00Z',
        'targetResources': ['//cloudresourcemanager.googleapis.com/'+SCOPE], '_provenance': proof(['insight-read'])}
    policy = {'name': SCOPE, 'bindings': [{'role': 'roles/viewer', 'members': [MEMBER]}],
              '_provenance': proof(['policy-read'], representation='full')}
    index = capture({'insight': [item], 'iam_policy': [policy]}, [
        read('insight-read', 'https://recommender.googleapis.com/v1/'+SCOPE+'/locations/global/insightTypes/google.iam.policy.Insight/insights'),
        read('policy-read', 'https://cloudresourcemanager.googleapis.com/v3/'+SCOPE+':getIamPolicy', 'POST')])
    return item, index


def capture(kinds, ledger):
    index = {'context': {'provider': 'gcp', 'scope': SCOPE, 'created_at': NOW,
                         'metadata': {'source_requests': ledger}}, 'collections': {}}
    for kind, rows in kinds.items():
        service = {'group': 'cloudidentity', 'group_membership': 'cloudidentity',
                   'insight': 'recommender', 'iam_policy': 'iam/cloudasset'}[kind]
        index[kind] = [{'data': row, 'type': kind, 'scope': SCOPE} for row in rows]
        index['collections'][kind] = [{'type': kind, 'service': service, 'scope': SCOPE,
                                     'status': 'collected' if rows else 'empty', 'items': rows}]
    return index


def test_complete_static_empty_group_fails_and_nonempty_passes():
    for members, expected in [(False, 'FAIL'), (True, 'PASS')]:
        item, index = group_fixture(members)
        before = deepcopy(index)
        status, evidence = subject.evaluate_group(item, index)
        assert status == expected, evidence
        assert evidence['membership_count'] == int(members)
        assert index == before


@pytest.mark.parametrize('mutation', ['denied', 'partial', 'missing', 'foreign', 'projection', 'duplicate', 'time', 'read', 'dynamic', 'partial_group', 'external_group'])
def test_group_absence_needs_complete_bound_specific_membership_read(mutation):
    item, index = group_fixture()
    marker = item['_coverage']['directMemberships']
    expected = 'UNKNOWN'
    if mutation == 'denied': marker['status'] = 'denied'; expected = 'DENIED'
    elif mutation == 'partial': marker['status'] = 'partial'
    elif mutation == 'missing': item.pop('_direct_membership_names')
    elif mutation == 'foreign': marker['group'] = 'groups/other'
    elif mutation == 'projection': index['group'] = []
    elif mutation == 'duplicate': item['_direct_membership_names'] = ['groups/synthetic/memberships/m']*2
    elif mutation == 'time': marker['collected_at'] = '2026-01-01T00:00:00Z'
    elif mutation == 'read': index['context']['metadata']['source_requests'][1]['url'] += ':wrong'
    elif mutation == 'dynamic': item['dynamicGroupMetadata'] = {'status': {'status': 'UPDATING_MEMBERSHIPS'}}
    elif mutation == 'partial_group': item['_provenance']['representation'] = 'partial'
    elif mutation == 'external_group': item['parent'] = 'identitysources/external'
    assert subject.evaluate_group(item, index)[0] == expected


def test_one_group_read_is_not_blocked_by_unrelated_partial_directory_inventory():
    item, index = group_fixture()
    index['collections']['group'][0]['status'] = 'partial'
    index['collections']['group_membership'][0]['status'] = 'partial'
    assert subject.evaluate_group(item, index)[0] == 'FAIL'
    item, index = group_fixture(True)
    item['_coverage']['directMemberships']['status'] = 'denied'
    assert subject.evaluate_group(item, index)[0] == 'PASS'


def test_unused_grant_fails_with_exact_current_role_member_condition_and_source_period():
    item, index = grant_fixture()
    before = deepcopy(index)
    status, evidence = subject.evaluate_grant(item, index)
    assert status == 'FAIL', evidence
    assert evidence['role'] == 'roles/viewer' and evidence['principal'] == MEMBER
    assert evidence['observation_days'] == 90
    assert evidence['exercised_permissions'] == []
    assert index == before


@pytest.mark.parametrize('mutation', ['old', 'future', 'short', 'foreign', 'type', 'target', 'changed_role', 'changed_member', 'changed_condition', 'missing_policy', 'malformed_permissions', 'missing_inferred', 'inferred', 'wrong_read', 'wrong_policy_read'])
def test_unused_role_grant_needs_current_matching_evidence(mutation):
    item, index = grant_fixture()
    binding = index['iam_policy'][0]['data']['bindings'][0]
    if mutation == 'old': item['lastRefreshTime'] = '2026-01-01T00:00:00Z'
    elif mutation == 'future': item['lastRefreshTime'] = '2027-01-01T00:00:00Z'
    elif mutation == 'short': item['observationPeriod'] = '86400s'
    elif mutation == 'foreign': item['name'] = item['name'].replace('usage-project', 'other-project')
    elif mutation == 'type': item['name'] = item['name'].replace('google.iam.policy.Insight', 'google.other.Insight')
    elif mutation == 'target': item['targetResources'] = ['//storage.googleapis.com/other-bucket']
    elif mutation == 'changed_role': binding['role'] = 'roles/editor'
    elif mutation == 'changed_member': binding['members'] = ['user:other@example.test']
    elif mutation == 'changed_condition': binding['condition'] = {'expression': 'false'}
    elif mutation == 'missing_policy': index['collections']['iam_policy'] = []
    elif mutation == 'malformed_permissions': item['content']['exercisedPermissions'] = [{}]
    elif mutation == 'missing_inferred': item['content'].pop('inferredPermissions')
    elif mutation == 'inferred': item['content']['inferredPermissions'] = [{'permission': 'compute.instances.get'}]
    elif mutation == 'wrong_read': index['context']['metadata']['source_requests'][0]['method'] = 'POST'
    elif mutation == 'wrong_policy_read': index['context']['metadata']['source_requests'][1]['method'] = 'GET'
    assert subject.evaluate_grant(item, index)[0] == 'UNKNOWN'


def test_permission_use_pass_is_not_a_claim_all_permissions_are_needed():
    item, index = grant_fixture(True)
    status, evidence = subject.evaluate_grant(item, index)
    assert status == 'PASS' and evidence['exercised_permissions'] == ['compute.instances.get']


@pytest.mark.parametrize('state', ['ACCEPTED', 'DISMISSED'])
def test_inactive_insights_do_not_produce_unused_grant_failures(state):
    item, index = grant_fixture()
    item['stateInfo']['state'] = state
    assert subject.evaluate_grant(item, index)[0] == 'NOT_APPLICABLE'


@pytest.mark.parametrize('cid,builder', [(subject.GROUP, group_fixture), (subject.GRANT, grant_fixture)])
def test_native_cases_hardening_json_and_formal_mapping(cid, builder):
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    from peaso.engine import evaluate_snapshot, hydrate_frameworks
    from peaso.snapshot import make_snapshot
    check = next(row for row in CHECKS if row.id == cid)
    assert check.category == 'hardening'
    for expected in ('PASS', 'FAIL'):
        case = CASES[cid]
        key = expected.lower()
        assert check.evaluate(case[key], case[key+'_index'])[0] == expected
    item, index = builder()
    collections = [deepcopy(collection) for rows in index['collections'].values() for collection in rows]
    snapshot = make_snapshot('gcp', [SCOPE], collections, created_at=NOW, metadata=index['context']['metadata'])
    report = hydrate_frameworks(evaluate_snapshot(snapshot, categories=['hardening'], checks=[cid]))
    finding = json.loads(json.dumps(report))['findings'][0]
    assert finding['status'] == 'FAIL', finding
    assert finding['category'] == 'hardening'
    assert 'HackTricks Cloud Best Practices' in finding['frameworks']
    assert any(name != 'HackTricks Cloud Best Practices' for name in finding['frameworks'])


def test_native_capture_start_and_completed_snapshot_time_are_distinct():
    item, index = group_fixture()
    index['context']['metadata']['asset_read_time'] = NOW
    index['context']['created_at'] = '2026-10-21T12:01:00Z'
    assert subject.evaluate_group(item, index)[0] == 'FAIL'
    item, index = grant_fixture()
    index['context']['metadata']['asset_read_time'] = NOW
    index['context']['created_at'] = '2026-10-21T12:01:00Z'
    assert subject.evaluate_grant(item, index)[0] == 'FAIL'


@pytest.mark.parametrize('scope', ['folders/123456789012', 'organizations/123456789012'])
def test_unused_permission_grants_use_exact_folder_or_organization_authority(scope):
    item, index = grant_fixture()
    item, index = json.loads(json.dumps([item, index]).replace(SCOPE, scope))
    assert subject.evaluate_grant(item, index)[0] == 'FAIL'
