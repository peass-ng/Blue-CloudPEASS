"""Only current captured tenant group evidence is visible to tenant checks."""
import copy
import pytest
from peaso.checks import Check
from peaso.checks.facts import complete_items
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

TENANT = '22222222-2222-2222-2222-222222222222'
OTHER = '33333333-3333-3333-3333-333333333333'
GROUP = '11111111-aaaa-bbbb-cccc-111111111111'
KIND = 'conditional_access_group_membership'
SCOPE = '/tenants/' + TENANT
SUB = '/subscriptions/11111111-1111-1111-1111-111111111111'


def run(monkeypatch, mutation=None):
    metadata = {'tenant_verified': True, 'tenant_id': TENANT,
        'credential_context_id': 'scan-credential', 'customer_context_id': 'scan-customer',
        'subscription_tenants': {SUB: TENANT}}
    proof = {k: metadata[k] for k in ('tenant_verified', 'tenant_id',
                                    'credential_context_id', 'customer_context_id')}
    member = {'id': GROUP, 'group_id': GROUP, 'user_ids': [],
              '_provenance': {**proof, 'read_only': True}}
    envelope = {'type': KIND, 'scope': SCOPE + '/groups/' + GROUP,
        'service': 'Microsoft.Graph', 'status': 'collected', 'items': [member],
        '_provenance': copy.deepcopy(proof)}
    if mutation == 'foreign-tenant': envelope['scope'] = envelope['scope'].replace(TENANT, OTHER)
    if mutation == 'foreign-credential': envelope['_provenance']['credential_context_id'] = 'other'
    if mutation == 'foreign-customer': envelope['_provenance']['customer_context_id'] = 'other'
    if mutation == 'unverified-global': metadata['tenant_verified'] = False
    if mutation == 'unverified-source': envelope['_provenance']['tenant_verified'] = False
    if mutation == 'foreign-row': member['_provenance']['tenant_id'] = OTHER
    if mutation == 'old-row-capture': member['_provenance']['credential_context_id'] = 'old'
    if mutation == 'wrong-service': envelope['service'] = 'Microsoft.Web'
    if mutation == 'wrong-type': envelope['type'] = 'directory_membership'
    if mutation == 'extra-child': envelope['scope'] += '/members'
    if mutation == 'malformed-group-id': envelope['scope'] = SCOPE + '/groups/not-a-guid'
    if mutation == 'partial': envelope.update(status='partial', items=[])
    def predicate(item, index):
        rows = complete_items(index, KIND)
        return ('PASS' if len(rows) == 1 else 'FAIL'), {'count': len(rows)}
    check = Check('azure.test.mfa_group_tenant_join', 'azure', 'hardening',
        'conditional_access_policy', 'Group join', 'medium', 'AC-2', 'Review',
        predicate, 'resource', (KIND,))
    monkeypatch.setattr('peaso.engine._registry', lambda: [check])
    capture = make_snapshot('azure', [SUB], [
        {'type': 'conditional_access_policy', 'scope': SCOPE,
         'service': 'Microsoft.Graph', 'status': 'collected', 'items': [{'id': 'policy-1'}]},
        envelope], metadata=metadata)
    return evaluate_snapshot(capture, categories=['hardening'], checks=[check.id])['findings'][0]['status']


def test_verified_same_tenant_child_group_can_join(monkeypatch):
    assert run(monkeypatch) == 'PASS'


@pytest.mark.parametrize('mutation', ['foreign-tenant', 'foreign-credential', 'foreign-customer',
    'unverified-global', 'unverified-source', 'foreign-row', 'old-row-capture', 'wrong-service',
    'wrong-type', 'extra-child', 'malformed-group-id', 'partial'])
def test_other_group_sources_never_supply_proof(monkeypatch, mutation):
    assert run(monkeypatch, mutation) == 'UNKNOWN'
