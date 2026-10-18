"""Counterexamples for native project-alias evidence authority."""
import copy
import pytest
from peaso.gcp_project_alias import AliasUnavailable, prove_project_alias
from tests.test_peaso_gcp_project_alias import fixture, SCOPE

@pytest.mark.parametrize('position', [0, 1])
def test_missing_collector_native_identity_cannot_authorize_alias(position):
    projects, policies, ledger = fixture()
    policies['items'][position].pop('native_id')
    with pytest.raises(AliasUnavailable, match='native_id'):
        prove_project_alias(SCOPE, projects, policies, ledger)

@pytest.mark.parametrize('record', [0, 3, 4])
@pytest.mark.parametrize('field', ['id', 'status', 'method', 'query'])
def test_denied_ledger_field_cannot_authorize_alias(record, field):
    projects, policies, ledger = fixture()
    ledger[record]['_coverage'] = {field: {'status': 'denied'}}
    with pytest.raises(AliasUnavailable):
        prove_project_alias(SCOPE, projects, policies, ledger)

@pytest.mark.parametrize('bindings', [
    [1],
    [{'role': 'roles/viewer', 'members': [7]}],
    [{'role': 'roles/viewer', 'members': []}],
    [{'role': 'roles/viewer', 'members': ['user:alice@example.com'], 'condition': {'expression': True}}],
    [{'role': 'roles/viewer', 'members': ['user:alice@example.com'], 'condition': {'expression': ''}}],
    [{'role': 'roles/viewer', 'members': ['user:alice@example.com'], 'unparsed': 'policy content'}],
])
def test_equal_malformed_bindings_are_not_identity_evidence(bindings):
    projects, policies, ledger = fixture()
    for policy in policies['items']:
        policy['bindings'] = copy.deepcopy(bindings)
    with pytest.raises(AliasUnavailable):
        prove_project_alias(SCOPE, projects, policies, ledger)

def test_valid_conditional_bindings_and_unrelated_denied_hydration_remain_supported():
    projects, policies, ledger = fixture()
    bindings = [{'role': 'projects/alias-demo/roles/custom_role',
                 'members': ['user:alice@example.com'],
                 'condition': {'expression': 'request.time < timestamp("2030-01-01T00:00:00Z")',
                               'title': 'reviewed temporal condition'}}]
    for policy in policies['items']:
        policy['bindings'] = copy.deepcopy(bindings)
        policy['version'] = 3
    ledger[2]['status'] = 'denied'
    ledger[2]['http_status'] = 403
    ledger[2]['_coverage'] = {'status': {'status': 'denied'}}
    assert prove_project_alias(SCOPE, projects, policies, ledger).project_number == '123456789'

@pytest.mark.parametrize('version', [True, 2, '3'])
def test_invalid_unprojected_direct_version_is_unknown(version):
    projects, policies, ledger = fixture()
    policies['items'][0]['version'] = version
    with pytest.raises(AliasUnavailable):
        prove_project_alias(SCOPE, projects, policies, ledger)

@pytest.mark.parametrize('denied_field', [None, 'name', 'assetType'])
def test_native_known_resource_peer_is_not_a_project_alias(denied_field):
    from peaso.checks.gcp_data_access import _native
    from tests.test_peaso_gcp_project_alias import CHECK
    projects, policies, ledger = fixture()
    peer = {'name': '//storage.googleapis.com/projects/_/buckets/example',
            'assetType': 'storage.googleapis.com/Bucket',
            '_provenance': {'scope': SCOPE, 'source_requests': ['peer'], 'representation': 'partial'}}
    if denied_field:
        peer['_coverage'] = {denied_field: {'status': 'denied'}}
    policies['items'].append(peer)
    policies['source_requests'].append('peer')
    index = {'context': {'scope': SCOPE, 'metadata': {'source_requests': ledger}},
             'collections': {'project': [projects], 'iam_policy': [policies]}}
    assert _native(peer, index, CHECK)[0] == ('UNKNOWN' if denied_field else 'NOT_APPLICABLE')
