from copy import deepcopy
import json
import pytest
from peaso import unused_iam_gcp_roles as subject

NOW = '2026-10-21T12:00:00Z'
PROJECT = 'projects/usage-project'
ORG = 'organizations/123456789012'


def proof(scope, refs, **extra):
    return {'scope': scope, 'collected_at': NOW, 'source_requests': refs, **extra}


def read(ref, url, scope, method='GET', query=None, request=None):
    return {'id': ref, 'url': url, 'scope': scope, 'method': method, 'status': 'collected',
            'http_status': 200, 'query': query or {}, **({'request': request} if request else {})}


def fixture(bound=False, org=False, resource=False):
    scope = ORG if org else PROJECT
    name = scope+'/roles/synthetic'
    role = {'name': name, 'includedPermissions': ['compute.instances.get', 'compute.instances.delete'],
            'stage': 'GA', '_provenance': proof(scope, ['roles-read'])}
    root = {'name': scope, 'bindings': [] if not bound or resource else [{'role': name, 'members': ['user:owner@example.test']}],
            '_provenance': proof(scope, ['root-read'], representation='full')}
    policies = [root]
    if resource:
        policies.append({'name': '//storage.googleapis.com/example-bucket', 'project': 'projects/123456789012',
            'bindings': [{'role': name, 'members': ['group:team@example.test'], 'condition': {'expression': 'false'}}] if bound else [],
            '_provenance': proof(scope, ['search-read'], representation='partial')})
    ledger = [read('roles-read', 'https://iam.googleapis.com/v1/'+scope+'/roles', scope, query={'view': 'FULL', 'showDeleted': 'true'}),
        read('root-read', 'https://cloudresourcemanager.googleapis.com/v3/'+scope+':getIamPolicy', scope, 'POST', request={'options': {'requestedPolicyVersion': 3}}),
        read('search-read', 'https://cloudasset.googleapis.com/v1/'+scope+':searchAllIamPolicies', scope)]
    index = {'context': {'provider': 'gcp', 'scope': scope, 'created_at': NOW,
        'metadata': {'asset_read_time': NOW, 'source_requests': ledger}}, 'collections': {}}
    for kind, rows, service, refs in [('iam_role', [role], 'iam', ['roles-read']),
                                     ('iam_policy', policies, 'iam/cloudasset', ['root-read', 'search-read'])]:
        index[kind] = [{'type': kind, 'scope': scope, 'data': row} for row in rows]
        index['collections'][kind] = [{'type': kind, 'scope': scope, 'service': service, 'status': 'collected', 'items': rows,
                                      'source_requests': refs}]
    return role, index


@pytest.mark.parametrize('org', [False, True])
@pytest.mark.parametrize('resource', [False, True])
def test_unbound_role_fails_and_root_or_resource_grant_passes(org, resource):
    for bound, expected in [(False, 'FAIL'), (True, 'PASS')]:
        role, index = fixture(bound, org, resource)
        before = deepcopy(index)
        status, evidence = subject.evaluate_role(role, index)
        assert status == expected, evidence
        assert evidence['included_permissions'] == role['includedPermissions']
        assert index == before


@pytest.mark.parametrize('mutation', ['denied', 'partial_denied', 'partial', 'missing_search', 'search_filter', 'asset_filter', 'read_mask', 'root_version',
    'missing_root', 'foreign_scope', 'projection', 'role_partial', 'role_read', 'bad_members', 'foreign_read', 'duplicate_receipt', 'permission_type'])
def test_absence_needs_complete_unfiltered_current_source_inventory(mutation):
    role, index = fixture()
    ledger = index['context']['metadata']['source_requests']
    policies = index['collections']['iam_policy'][0]
    expected = 'UNKNOWN'
    if mutation == 'denied': policies['status'] = 'denied'; expected = 'DENIED'
    elif mutation == 'partial_denied': policies.update(status='partial', error={'kind': 'denied'}); ledger[-1]['status'] = 'denied'; expected = 'DENIED'
    elif mutation == 'partial': policies['status'] = 'partial'
    elif mutation == 'missing_search': policies['source_requests'] = ['root-read']
    elif mutation == 'search_filter': ledger[-1]['query'] = {'query': 'policy:user:other@example.test'}
    elif mutation == 'asset_filter': ledger[-1]['query'] = {'assetTypes': ['storage.googleapis.com/Bucket']}
    elif mutation == 'read_mask': ledger[-1]['query'] = {'readMask': 'resource'}
    elif mutation == 'root_version': ledger[1]['request'] = {'options': {'requestedPolicyVersion': 1}}
    elif mutation == 'missing_root': index['iam_policy'] = []; policies['items'] = []
    elif mutation == 'foreign_scope': index['context']['scope'] = 'projects/foreign'
    elif mutation == 'projection': index['iam_role'] = []
    elif mutation == 'role_partial': ledger[0]['query']['view'] = 'BASIC'
    elif mutation == 'role_read': ledger[0]['method'] = 'POST'
    elif mutation == 'bad_members': policies['items'][0]['bindings'] = [{'role': role['name'], 'members': None}]
    elif mutation == 'foreign_read': ledger[-1]['scope'] = 'projects/foreign'
    elif mutation == 'duplicate_receipt': ledger.append(deepcopy(ledger[-1]))
    elif mutation == 'permission_type': role['includedPermissions'] = ['compute.instances.get', None]
    assert subject.evaluate_role(role, index)[0] == expected


def test_known_grant_survives_unrelated_partial_inventory_and_is_not_usage_history():
    role, index = fixture(True, resource=True)
    index['collections']['iam_policy'][0]['status'] = 'partial'
    status, evidence = subject.evaluate_role(role, index)
    assert status == 'PASS'
    assert evidence['declared_grants'][0]['condition']['expression'] == 'false'
    assert 'not authentication history' in evidence['semantics']


def test_only_soft_deleted_predefined_or_foreign_owned_roles_are_not_applicable():
    role, index = fixture()
    role['deleted'] = True
    assert subject.evaluate_role(role, index)[0] == 'NOT_APPLICABLE'
    role, index = fixture()
    role['name'] = 'roles/viewer'
    assert subject.evaluate_role(role, index)[0] == 'NOT_APPLICABLE'
    role, index = fixture()
    role['name'] = ORG+'/roles/foreign'
    assert subject.evaluate_role(role, index)[0] == 'NOT_APPLICABLE'


def test_role_permission_list_does_not_mean_it_has_any_grants():
    role, index = fixture()
    role['includedPermissions'] = []
    assert subject.evaluate_role(role, index)[0] == 'FAIL'


def test_unproven_project_number_is_unknown_not_a_foreign_role():
    role, index = fixture()
    role['name'] = 'projects/987654321012/roles/synthetic'
    assert subject.evaluate_role(role, index)[0] == 'UNKNOWN'


def test_verified_project_alias_matches_grants_written_with_project_id():
    role, index = fixture(True)
    role['name'] = 'projects/987654321012/roles/synthetic'
    meta = index['context']['metadata']
    meta['source_requests'].append(read('project-read', 'https://cloudresourcemanager.googleapis.com/v3/'+PROJECT, PROJECT))
    meta['data_service_project_bindings'] = {PROJECT: {'status': 'collected', 'scope': PROJECT,
        'project_id': 'usage-project', 'project_number': '987654321012', 'source_requests': ['project-read']}}
    assert subject.evaluate_role(role, index)[0] == 'PASS'


def test_scoped_binding_join_uses_existing_scan_memo_index_once(monkeypatch):
    from peaso.checks.facts import MemoIndex
    role, index = fixture(True)
    second = deepcopy(role);second['name'] = PROJECT+'/roles/second'
    index['iam_role'].append({'type': 'iam_role', 'scope': PROJECT, 'data': second})
    index['collections']['iam_role'][0]['items'].append(second)
    calls = []
    original = subject.records
    def tracked(index, kind, scope):
        if kind == 'iam_policy': calls.append(kind)
        return original(index, kind, scope)
    monkeypatch.setattr(subject, 'records', tracked)
    native = MemoIndex(index)
    assert subject.evaluate_role(role, native)[0] == 'PASS'
    assert subject.evaluate_role(second, native)[0] == 'FAIL'
    assert calls == ['iam_policy']


def test_native_registration_cases_and_hardening_json():
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    from peaso.engine import evaluate_snapshot, hydrate_frameworks
    from peaso.snapshot import make_snapshot
    check = next(row for row in CHECKS if row.id == subject.CHECK)
    assert check.category == 'hardening'
    for expected in ('PASS', 'FAIL'):
        key = expected.lower();case = CASES[subject.CHECK]
        assert check.evaluate(case[key], case[key+'_index'])[0] == expected
    role, index = fixture()
    collections = [deepcopy(row) for rows in index['collections'].values() for row in rows]
    snapshot = make_snapshot('gcp', [PROJECT], collections, created_at=NOW, metadata=index['context']['metadata'])
    finding = hydrate_frameworks(evaluate_snapshot(snapshot, categories=['hardening'], checks=[subject.CHECK]))['findings'][0]
    assert finding['status'] == 'FAIL', finding['evidence']
    assert finding['evidence']['included_permissions'] == role['includedPermissions']
    assert 'HackTricks Cloud Best Practices' in finding['frameworks']
