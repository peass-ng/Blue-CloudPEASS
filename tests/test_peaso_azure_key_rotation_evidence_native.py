"""Native rotation policy facts never fabricate enforcement or effective rights."""
from copy import deepcopy
import json

import pytest

from peaso.collectors import azure, azure_key_rotation_evidence_native as native
from peaso.checks import evaluate_check

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
VAULT = SCOPE + '/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault'
ORIGIN = 'https://vault.vault.azure.net'
KEY = VAULT + '/keys/key'
NATIVE_KEY = ORIGIN + '/keys/key'
CONTROL = 'azure_pci_3_7_4_5'


def sources():
    def envelope(kind, scope, rows):
        return {'type': kind, 'scope': scope, 'status': 'collected' if rows else 'empty', 'items': rows}
    def proof(endpoint):
        return {'read_only': True, 'endpoint': endpoint, 'audience': 'https://vault.azure.net'}
    return [
        envelope('vault', SCOPE, [{'id': VAULT, 'type': 'Microsoft.KeyVault/vaults',
            'properties': {'vaultUri': ORIGIN}}]),
        envelope('key_metadata', VAULT, [{'id': KEY, 'name': 'key', 'parent_id': VAULT,
            'data_plane_id': NATIVE_KEY, '_provenance': proof('keys/list')}]),
        envelope('key_rotation_policy', KEY, [{'id': KEY + '/rotationpolicy', 'parent_id': KEY,
            'type': 'Microsoft.KeyVault/vaults/keys/rotationpolicy',
            'properties': {'lifetimeActions': [{'action': {'type': 'Rotate'}, 'trigger': {'timeAfterCreate': 'P90D'}}]},
            '_provenance': proof('keys/rotationpolicy/get')}]),
    ]


def project(collections=None, **limits):
    reader = azure._Reader({'concurrency': 1, 'retries': 0, **limits})
    reader.collections = sources() if collections is None else collections
    reader.total = sum(len(c['items']) for c in reader.collections)
    original = deepcopy(reader.collections)
    native.collect(reader, [SCOPE], {'key_rotation_evidence'})
    assert reader.collections[:-1] == original
    assert reader.budget.calls == 0
    return reader.collections[-1]


def test_exact_native_join_and_no_invented_enforcement():
    collection = project()
    assert collection['status'] == 'collected'
    row = collection['items'][0]
    assert row['keyId'] == NATIVE_KEY and row['armKeyId'] == KEY and row['vaultId'] == VAULT
    assert row['rotationPolicy']['lifetimeActions'][0]['trigger'] == {'timeAfterCreate': 'P90D'}
    assert row['_coverage'] == {f: {'status': 'not_collected'} for f in ('enforcementAssignments', 'rotationIdentities')}
    assert row['enforcementAssignments'] == row['rotationIdentities'] == []
    # Mutating a projection cannot mutate its native source or nested proof.
    assert row['_provenance'] is not row['rotationPolicy']['_provenance']


@pytest.mark.parametrize('actions,expected', [
    pytest.param([], 'FAIL', id='native_missing_rotate'),
    pytest.param([{'action': {'type': 'Rotate'}, 'trigger': {'timeAfterCreate': 'P90D'}}], 'UNKNOWN', id='configured_without_rights'),
])
def test_collect_to_actual_signed_evaluator_never_passes_without_effective_enforcement(actions, expected):
    incoming = sources()
    incoming[2]['items'][0]['properties']['lifetimeActions'] = actions
    collection = project(incoming)
    index = {'context': {'provider': 'azure', 'scope': SCOPE,
        'metadata': {'compliance_policy': {'sw16': {CONTROL: {'status': 'collected', 'scope': SCOPE,
            'requiredKeyIds': [NATIVE_KEY], 'maxRotationInterval': 'P90D',
            'rotationPolicyDefinitionId': '/providers/Microsoft.Authorization/policyDefinitions/rotation'}}}}},
        'collections': {'key_rotation_evidence': [collection]},
        'key_rotation_evidence': [{'type': 'key_rotation_evidence', 'scope': SCOPE, 'data': row} for row in collection['items']]}
    assert evaluate_check(CONTROL, {}, index)[0] == expected


@pytest.mark.parametrize('mode', [
    'foreign_scope', 'foreign_vault', 'traversal', 'foreign_origin', 'duplicate_vault',
    'duplicate_key', 'duplicate_policy', 'foreign_key', 'foreign_native_key', 'foreign_parent',
    'wrong_policy_id', 'wrong_policy_parent', 'wrong_policy_type', 'missing_actions',
    'malformed_actions', 'oversized_actions', 'unknown_action', 'unreadable_key',
    'unreadable_policy', 'wrong_key_operation', 'wrong_policy_operation', 'wrong_audience',
    'missing_source', 'duplicate_source', 'partial_source', 'denied_source',
    'empty_conflicts', 'collected_without_items', 'secret_action_field', 'secret_trigger_field',
])
def test_invalid_or_incomplete_native_join_cannot_publish_complete_facts(mode):
    incoming = sources()
    vault, key, policy = [c['items'][0] for c in incoming]
    if mode == 'foreign_scope': incoming[0]['scope'] = SCOPE.replace('1111', '2222')
    elif mode == 'foreign_vault': vault['id'] = VAULT + '-foreign'
    elif mode == 'traversal': vault['id'] = VAULT.replace('/rg/', '/../')
    elif mode == 'foreign_origin': vault['properties']['vaultUri'] = 'https://foreign.vault.azure.net'
    elif mode == 'duplicate_vault': incoming[0]['items'].append(deepcopy(vault))
    elif mode == 'duplicate_key': incoming[1]['items'].append(deepcopy(key))
    elif mode == 'duplicate_policy': incoming[2]['items'].append(deepcopy(policy))
    elif mode == 'foreign_key': key['id'] = KEY + '-foreign'
    elif mode == 'foreign_native_key': key['data_plane_id'] = ORIGIN + '/keys/foreign'
    elif mode == 'foreign_parent': key['parent_id'] = VAULT + '-foreign'
    elif mode == 'wrong_policy_id': policy['id'] = KEY + '-foreign/rotationpolicy'
    elif mode == 'wrong_policy_parent': policy['parent_id'] = KEY + '-foreign'
    elif mode == 'wrong_policy_type': policy['type'] = 'Microsoft.KeyVault/vaults/secrets'
    elif mode == 'missing_actions': policy['properties'].pop('lifetimeActions')
    elif mode == 'malformed_actions': policy['properties']['lifetimeActions'] = None
    elif mode == 'oversized_actions': policy['properties']['lifetimeActions'] *= 65
    elif mode == 'unknown_action': policy['properties']['lifetimeActions'][0]['action']['type'] = 'Unknown'
    elif mode == 'unreadable_key': key['_provenance']['read_only'] = 1
    elif mode == 'unreadable_policy': policy['_provenance']['read_only'] = False
    elif mode == 'wrong_key_operation': key['_provenance']['endpoint'] = 'keys/import'
    elif mode == 'wrong_policy_operation': policy['_provenance']['endpoint'] = 'keys/rotationpolicy/set'
    elif mode == 'wrong_audience': policy['_provenance']['audience'] = 'https://management.azure.com'
    elif mode == 'missing_source': incoming.pop(2)
    elif mode == 'duplicate_source': incoming.append(deepcopy(incoming[2]))
    elif mode == 'partial_source': incoming[1]['status'] = 'partial'
    elif mode == 'denied_source': incoming[2]['status'] = 'denied'
    elif mode == 'empty_conflicts': incoming[1]['status'] = 'empty'
    elif mode == 'collected_without_items': incoming[2]['items'] = []
    elif mode == 'secret_action_field': policy['properties']['lifetimeActions'][0]['secret'] = 'NEVER_COPY_KEY'
    elif mode == 'secret_trigger_field': policy['properties']['lifetimeActions'][0]['trigger']['secret'] = 'NEVER_COPY_KEY'
    result = project(incoming)
    assert result['status'] not in ('collected', 'empty') and result['items'] == []
    assert 'NEVER_COPY_KEY' not in json.dumps(result)


def test_complete_empty_and_missing_selection():
    assert project([{'type': 'vault', 'scope': SCOPE, 'status': 'empty', 'items': []}])['status'] == 'empty'
    reader = azure._Reader({})
    native.collect(reader, [SCOPE], {'vault'})
    assert reader.collections == []
    assert native.required_types({'vault'}) == set()
    assert native.required_types({'key_rotation_evidence'}) == {'vault', 'key_metadata', 'key_rotation_policy'}


def test_native_secret_properties_are_never_copied():
    incoming = sources()
    for collection in incoming:
        collection['items'][0]['privateKey'] = 'NEVER_COPY_KEY'
    incoming[2]['items'][0]['properties']['privateKey'] = 'NEVER_COPY_KEY'
    assert 'NEVER_COPY_KEY' not in json.dumps(project(incoming))


def test_derived_resource_budget_is_enforced():
    result = project(max_resources=1)
    assert result['status'] not in ('collected', 'empty')
