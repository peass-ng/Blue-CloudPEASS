from copy import deepcopy
import json
import pytest
from peaso import unused_iam_gcp_directory as subject

NOW = '2026-10-21T12:00:00Z'
PROJECT = 'projects/usage-project'
ORG = 'organizations/123456789012'
CUSTOMER = 'Csynthetic'
UID = '123456789012345678901'
EMAIL = 'user@example.test'


def proof(scope, refs):
    return {'scope': scope, 'source_requests': refs, 'collected_at': NOW}


def read(ref, url, scope=PROJECT, query=None):
    return {'id': ref, 'url': url, 'scope': scope, 'method': 'GET', 'status': 'collected', 'http_status': 200, 'query': query or {}}


def capture(scope, kinds, ledger):
    index = {'context': {'provider': 'gcp', 'scope': scope, 'created_at': NOW,
        'metadata': {'source_requests': ledger, 'asset_read_time': NOW}}, 'collections': {}}
    for kind, rows in kinds.items():
        index[kind] = [{'data': row, 'scope': scope, 'type': kind} for row in rows]
        index['collections'][kind] = [{'type': kind, 'scope': scope, 'service': 'iam' if 'pool' in kind or 'provider' in kind else 'workspace-directory',
                                      'status': 'collected' if rows else 'empty', 'items': rows,
                                      'source_requests': list(dict.fromkeys(ref for row in rows for ref in row.get('_provenance', {}).get('source_requests', [])))}]
    return index


def user_fixture(recent=False):
    binding = {'status': 'collected', 'scope': PROJECT, 'customer': CUSTOMER, 'organization': ORG, 'chain': [
        {'requested': PROJECT, 'name': 'projects/987654321012', 'projectId': 'usage-project', 'parent': ORG, 'source_request': 'project-read'},
        {'requested': ORG, 'name': ORG, 'directoryCustomerId': CUSTOMER, 'source_request': 'org-read'}]}
    item = {'name': f'customers/{CUSTOMER}/workspace_user/{UID}', 'id': UID, 'customerId': CUSTOMER,
        'directoryCustomer': CUSTOMER, 'primaryEmail': EMAIL, 'suspended': False, 'archived': False,
        '_directoryBinding': binding, '_provenance': proof(PROJECT, ['users-read'])}
    observation = {'name': f'customers/{CUSTOMER}/users/{UID}/loginActivity', 'user_id': UID, 'directory_customer': CUSTOMER,
        'user_name': item['name'], 'status': 'collected', '_provenance': proof(PROJECT, ['user-get']),
        'detail': {'id': UID, 'customerId': CUSTOMER, 'primaryEmail': EMAIL, 'suspended': False, 'archived': False,
            'creationTime': '2024-01-01T00:00:00Z', 'lastLoginTime': '2026-10-20T12:00:00Z' if recent else '2025-01-01T00:00:00Z'}}
    ledger = [read('project-read', 'https://cloudresourcemanager.googleapis.com/v3/'+PROJECT),
        read('org-read', 'https://cloudresourcemanager.googleapis.com/v3/'+ORG), read('users-read', subject.USERS),
        read('user-get', subject.USERS+'/'+UID, query={'projection': 'full', 'viewType': 'admin_view', 'fields': subject.FIELDS})]
    return item, capture(PROJECT, {'workspace_user': [item], subject.KIND: [observation]}, ledger)


def pool_fixture(workforce=False, enabled=False):
    scope = ORG if workforce else PROJECT
    kind, child = ('workforce_pool', 'workforce_provider') if workforce else ('workload_identity_pool', 'workload_identity_provider')
    name = 'locations/global/workforcePools/synthetic' if workforce else PROJECT+'/locations/global/workloadIdentityPools/synthetic'
    endpoint = 'https://iam.googleapis.com/v1/locations/global/workforcePools' if workforce else 'https://iam.googleapis.com/v1/'+PROJECT+'/locations/global/workloadIdentityPools'
    item = {'name': name, 'state': 'ACTIVE', 'disabled': False, '_provenance': proof(scope, ['pools-read'])}
    if workforce: item['parent'] = ORG
    provider = {'name': name+'/providers/disabled', 'state': 'ACTIVE', 'disabled': not enabled, '_provenance': proof(scope, ['providers-read'])}
    index = capture(scope, {kind: [item], child: [provider]}, [read('pools-read', endpoint, scope, {'parent': ORG} if workforce else {}),
        read('providers-read', 'https://iam.googleapis.com/v1/'+name+'/providers', scope)])
    return item, index


def observation(index):
    return index[subject.KIND][0]['data']


def test_old_individual_login_fails_and_recent_login_passes():
    for recent, expected in [(False, 'FAIL'), (True, 'PASS')]:
        item, index = user_fixture(recent)
        before = deepcopy(index)
        status, evidence = subject.evaluate_user(item, index)
        assert status == expected, evidence
        assert evidence['principal'] == EMAIL and evidence['last_recorded_login']
        assert index == before


@pytest.mark.parametrize('mutation', ['no_detail', 'denied', 'sentinel', 'future', 'creation_future', 'missing_date', 'uid', 'customer', 'email', 'projection', 'wrong_get', 'binding', 'hierarchy', 'chain_read', 'foreign', 'ambiguous'])
def test_old_login_requires_native_detail_and_directory_binding(mutation):
    item, index = user_fixture()
    obs = observation(index)
    expected = 'UNKNOWN'
    if mutation == 'no_detail': obs.pop('detail')
    elif mutation == 'denied': obs['status'] = 'denied'; expected = 'DENIED'
    elif mutation == 'sentinel': obs['detail']['lastLoginTime'] = '1970-01-01T00:00:00Z'
    elif mutation == 'future': obs['detail']['lastLoginTime'] = '2027-01-01T00:00:00Z'
    elif mutation == 'creation_future': obs['detail']['creationTime'] = '2027-01-01T00:00:00Z'
    elif mutation == 'missing_date': obs['detail'].pop('lastLoginTime')
    elif mutation == 'uid': obs['detail']['id'] = 'different'
    elif mutation == 'customer': obs['detail']['customerId'] = 'Cforeign'
    elif mutation == 'email': obs['detail']['primaryEmail'] = 'other@example.test'
    elif mutation == 'projection': index['context']['metadata']['source_requests'][-1]['query']['fields'] = 'id'
    elif mutation == 'wrong_get': index['context']['metadata']['source_requests'][-1]['url'] += '/wrong'
    elif mutation == 'binding': item['_directoryBinding']['customer'] = 'Cforeign'
    elif mutation == 'hierarchy': item['_directoryBinding']['chain'][-1]['directoryCustomerId'] = 'Cforeign'
    elif mutation == 'chain_read': index['context']['metadata']['source_requests'][1]['url'] += '/wrong'
    elif mutation == 'foreign': obs['_provenance']['scope'] = 'projects/foreign'
    elif mutation == 'ambiguous': index[subject.KIND].append(deepcopy(index[subject.KIND][0])); index['collections'][subject.KIND][0]['items'].append(deepcopy(obs))
    assert subject.evaluate_user(item, index)[0] == expected


def test_new_user_and_disabled_user_have_explicit_non_stale_outcomes():
    item, index = user_fixture()
    observation(index)['detail'].update(creationTime='2026-10-20T12:00:00Z', lastLoginTime='2026-10-20T12:00:00Z')
    assert subject.evaluate_user(item, index)[0] == 'PASS'
    item['suspended'] = True
    index['collections'][subject.KIND] = []
    assert subject.evaluate_user(item, index)[0] == 'NOT_APPLICABLE'


def test_bound_old_user_positive_survives_unrelated_partial_inventory():
    item, index = user_fixture()
    index['collections']['workspace_user'][0]['status'] = 'partial'
    index['collections'][subject.KIND][0]['status'] = 'partial'
    assert subject.evaluate_user(item, index)[0] == 'FAIL'


@pytest.mark.parametrize('workforce', [False, True])
def test_provider_availability_and_unusable_pool_are_structural(workforce):
    evaluate = subject.evaluate_workforce if workforce else subject.evaluate_workload
    for enabled, expected in [(False, 'FAIL'), (True, 'PASS')]:
        item, index = pool_fixture(workforce, enabled)
        before = deepcopy(index)
        status, evidence = evaluate(item, index)
        assert status == expected, evidence
        assert index == before


@pytest.mark.parametrize('workforce', [False, True])
@pytest.mark.parametrize('mutation', ['partial', 'denied', 'parent', 'foreign', 'state', 'provider_state', 'projection', 'filtered', 'missing_request', 'duplicate', 'unreadable_disabled'])
def test_no_provider_requires_complete_authoritative_evidence(workforce, mutation):
    item, index = pool_fixture(workforce)
    evaluate = subject.evaluate_workforce if workforce else subject.evaluate_workload
    child = 'workforce_provider' if workforce else 'workload_identity_provider'
    expected = 'UNKNOWN'
    if mutation == 'partial': index['collections'][child][0]['status'] = 'partial'
    elif mutation == 'denied': index['collections'][child][0]['status'] = 'denied'; expected = 'DENIED'
    elif mutation == 'parent': item['name'] += '/wrong'
    elif mutation == 'foreign': index['context']['scope'] = 'projects/foreign'
    elif mutation == 'state': item['state'] = 'STATE_UNSPECIFIED'
    elif mutation == 'provider_state': index[child][0]['data']['state'] = 'STATE_UNSPECIFIED'
    elif mutation == 'projection': index[child] = []
    elif mutation == 'filtered': index['context']['metadata']['source_requests'][-1]['query']['filter'] = 'disabled=true'
    elif mutation == 'missing_request': index['collections'][child][0]['source_requests'] = []
    elif mutation == 'duplicate': index[child].append(deepcopy(index[child][0])); index['collections'][child][0]['items'].append(deepcopy(index[child][0]['data']))
    elif mutation == 'unreadable_disabled': item['_coverage'] = {'disabled': {'status': 'denied'}}; expected = 'DENIED'
    assert evaluate(item, index)[0] == expected


def test_workload_trust_domains_do_not_need_external_federation_providers():
    item, index = pool_fixture()
    item['mode'] = 'TRUST_DOMAIN'
    index['collections']['workload_identity_provider'] = []
    assert subject.evaluate_workload(item, index)[0] == 'NOT_APPLICABLE'


def test_complete_empty_provider_list_is_distinct_from_a_missing_list():
    item, index = pool_fixture()
    index['workload_identity_provider'] = []
    index['collections']['workload_identity_provider'][0].update(status='empty', items=[])
    assert subject.evaluate_workload(item, index)[0] == 'FAIL'


@pytest.mark.parametrize('cid,builder', [(subject.USER, user_fixture), (subject.WORKLOAD, pool_fixture),
    (subject.WORKFORCE, lambda: pool_fixture(True))])
def test_native_cases_and_hardening_report_with_formal_mapping(cid, builder):
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    from peaso.engine import evaluate_snapshot, hydrate_frameworks
    from peaso.snapshot import make_snapshot
    check = next(row for row in CHECKS if row.id == cid)
    assert check.category == 'hardening'
    case = CASES[cid]
    for expected in ('PASS', 'FAIL'):
        key = expected.lower()
        assert check.evaluate(case[key], case[key+'_index'])[0] == expected
    item, index = builder()
    scope = index['context']['scope']
    collections = [deepcopy(row) for rows in index['collections'].values() for row in rows]
    snapshot = make_snapshot('gcp', [scope], collections, created_at=NOW, metadata=index['context']['metadata'])
    report = hydrate_frameworks(evaluate_snapshot(snapshot, categories=['hardening'], checks=[cid]))
    finding = json.loads(json.dumps(report))['findings'][0]
    assert finding['status'] == 'FAIL', finding['evidence']
    assert finding['category'] == 'hardening'
    assert 'HackTricks Cloud Best Practices' in finding['frameworks']
    assert 'NIS2 - Network and Information Security Directive (Directive (EU) 2022/2555)' in finding['frameworks']


@pytest.mark.parametrize('workforce', [False, True])
def test_nested_provider_path_is_not_an_enabled_consumer(workforce):
    item, index = pool_fixture(workforce, True)
    child = 'workforce_provider' if workforce else 'workload_identity_provider'
    index[child][0]['data']['name'] += '/providers/foreign'
    evaluate = subject.evaluate_workforce if workforce else subject.evaluate_workload
    assert evaluate(item, index)[0] == 'UNKNOWN'
