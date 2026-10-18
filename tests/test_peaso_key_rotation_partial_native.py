# Historical fixture contracts; current native admission is tested separately.
"""Independent native key policies survive inaccessible vault/key siblings."""
from copy import deepcopy
from datetime import datetime, timezone
import json

import pytest

from peaso.collectors import azure, azure_key_rotation_evidence_native as native
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
from tests.test_peaso_azure_key_rotation_evidence_native import SCOPE, VAULT, ORIGIN, KEY, NATIVE_KEY, CONTROL, sources
from tests.test_peaso_key_rotation_conclusive_native import owner


def capture(layout='vaults', reverse=False, failure='denied', bad=True, stage='policy', global_bad=None):
    incoming = sources()
    second = deepcopy(sources())
    if layout == 'vaults':
        second = json.loads(json.dumps(second).replace(VAULT, VAULT + 'two').replace(ORIGIN, 'https://vaulttwo.vault.azure.net'))
        incoming[0]['items'].extend(second[0]['items'])
        incoming.extend(second[1:])
        other_key = 'https://vaulttwo.vault.azure.net/keys/key'
        if reverse: incoming[0]['items'].reverse()
    else:
        second = json.loads(json.dumps(second).replace(KEY, VAULT + '/keys/other').replace(NATIVE_KEY, ORIGIN + '/keys/other'))
        second[1]['items'][0]['name'] = 'other'
        incoming[1]['items'].extend(second[1]['items'])
        incoming.append(second[2])
        other_key = ORIGIN + '/keys/other'
        if reverse: incoming[1]['items'].reverse()
    target = next(c for c in incoming if c['type'] == 'key_rotation_policy' and c['scope'] == KEY)
    if bad: target['items'][0]['properties']['lifetimeActions'] = []
    if stage == 'policy':
        denied = next(c for c in incoming if c['type'] == 'key_rotation_policy' and c is not target)
    else:
        denied = next(c for c in incoming if c['type'] == 'key_metadata' and c['scope'] != VAULT)
    denied.update(status=failure, items=[])
    if global_bad == 'partial': incoming[0]['status'] = 'partial'
    elif global_bad == 'foreign': incoming[0]['items'][-1]['id'] = VAULT.replace(SCOPE, SCOPE.replace('1111', '2222'))
    reader = azure._Reader({'concurrency': 1, 'retries': 0})
    reader.collections = incoming
    reader.total = sum(len(c['items']) for c in incoming)
    native.collect(reader, [SCOPE], {'key_rotation_evidence'})
    assert reader.budget.calls == 0
    policy = owner()
    policy['requiredKeyIds'] = [NATIVE_KEY, other_key]
    if reverse: policy['requiredKeyIds'].reverse()
    collections = deepcopy(reader.collections)
    for c in collections: c.setdefault('service', 'Microsoft.KeyVault')
    snapshot = make_snapshot('azure', [SCOPE], collections, created_at=datetime.now(timezone.utc).isoformat(),
        metadata={'compliance_policy': {'sw16': {CONTROL: policy}}})
    return snapshot


def evidence(snapshot):
    return next(c for c in snapshot['collections'] if c['type'] == 'key_rotation_evidence')


def verdict(snapshot):
    findings = [f for f in evaluate_snapshot(snapshot, checks=[CONTROL])['findings'] if f['check_id'] == CONTROL]
    assert len(findings) == 1
    return findings[0]['status']


@pytest.mark.parametrize('layout', ['vaults', 'keys'])
@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('failure', ['denied', 'timeout'])
def test_known_native_bad_policy_survives_other_policy_failure(layout, reverse, failure):
    snapshot = capture(layout, reverse, failure)
    assert evidence(snapshot)['status'] == 'partial'
    assert len(evidence(snapshot)['items']) == 1
    assert evidence(snapshot)['items'][0]['keyId'] == NATIVE_KEY
    assert verdict(snapshot) == 'FAIL'


@pytest.mark.parametrize('reverse', [False, True])
def test_bad_native_policy_survives_other_vault_key_inventory_denial(reverse):
    snapshot = capture(reverse=reverse, stage='keys')
    assert evidence(snapshot)['status'] == 'partial'
    assert verdict(snapshot) == 'FAIL'


@pytest.mark.parametrize('layout', ['vaults', 'keys'])
@pytest.mark.parametrize('reverse', [False, True])
def test_safe_native_policy_with_inaccessible_sibling_never_passes(layout, reverse):
    snapshot = capture(layout=layout, reverse=reverse, bad=False)
    assert evidence(snapshot)['status'] == 'partial'
    assert verdict(snapshot) in ('UNKNOWN', 'DENIED')


@pytest.mark.parametrize('mode', [
    'foreign_vault', 'foreign_native_key', 'foreign_scope', 'missing_proof', 'wrong_projection',
    'wrong_request', 'not_readonly', 'incomplete_policy', 'missing_vault_inventory', 'incomplete_vault_inventory',
])
def test_partial_counterexample_requires_strict_native_identity_and_parent_authority(mode):
    snapshot = capture()
    row = evidence(snapshot)['items'][0]
    if mode == 'foreign_vault': row['vaultId'] = VAULT + '-foreign'
    elif mode == 'foreign_native_key': row['keyId'] = ORIGIN + '/keys/foreign'
    elif mode == 'foreign_scope': row['scope_id'] = SCOPE.replace('1111', '2222')
    elif mode == 'missing_proof': row.pop('_provenance')
    elif mode == 'wrong_projection': row['_provenance']['projection'] = 'external-owner-observation'
    elif mode == 'wrong_request': row['_provenance']['request_uri'] += '/foreign'
    elif mode == 'not_readonly': row['_provenance']['read_only'] = 1
    elif mode == 'incomplete_policy': row['rotationPolicy']['_provenance']['representation'] = 'list'
    elif mode == 'missing_vault_inventory': snapshot['collections'] = [c for c in snapshot['collections'] if c['type'] != 'vault']
    elif mode == 'incomplete_vault_inventory': next(c for c in snapshot['collections'] if c['type'] == 'vault')['status'] = 'partial'
    sealed = make_snapshot('azure', [SCOPE], snapshot['collections'], metadata=snapshot['metadata'], created_at=snapshot['created_at'])
    assert verdict(sealed) == 'UNKNOWN'


@pytest.mark.parametrize('global_bad', ['partial', 'foreign'])
@pytest.mark.parametrize('reverse', [False, True])
def test_unknown_or_invalid_global_parent_roster_emits_no_native_counterexample(global_bad, reverse):
    snapshot = capture(reverse=reverse, global_bad=global_bad)
    assert evidence(snapshot)['items'] == []
    assert verdict(snapshot) == 'UNKNOWN'
