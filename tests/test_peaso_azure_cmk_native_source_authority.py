# Historical fixture contracts; current native admission is tested separately.
"""CMK native GET authority must belong to the evaluated capture."""
from copy import deepcopy

import pytest

from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
from test_peaso_azure_cmk_native_full_get import CHECK, SUB, capture


@pytest.mark.parametrize('mutation', [
    'row_credential', 'row_customer', 'envelope_credential',
    'envelope_customer', 'unverified_tenant', 'foreign_subscription_tenant',
    'row_read_only', 'missing_native_operation',
])
def test_native_get_requires_current_verified_capture(monkeypatch, mutation):
    original, snapshot, _, _ = capture(monkeypatch, 'system_missing')
    assert original['status'] == 'FAIL'
    collections = deepcopy(snapshot['collections'])
    metadata = deepcopy(snapshot['metadata'])
    envelope = next(c for c in collections if c['type'] == 'recovery_vault')
    row = envelope['items'][0]
    if mutation == 'row_credential':
        row['_provenance']['credential_context_id'] = 'prior-credential'
    elif mutation == 'row_customer':
        row['_provenance']['customer_context_id'] = 'other-customer'
    elif mutation == 'envelope_credential':
        envelope['_provenance']['credential_context_id'] = 'prior-credential'
    elif mutation == 'envelope_customer':
        envelope['_provenance']['customer_context_id'] = 'other-customer'
    elif mutation == 'unverified_tenant':
        metadata['tenant_verified'] = False
    elif mutation == 'foreign_subscription_tenant':
        metadata['subscription_tenants'][SUB] = 'foreign-tenant'
    elif mutation == 'row_read_only':
        row['_provenance']['read_only'] = False
    elif mutation == 'missing_native_operation':
        row['_provenance'].pop('source_operation')
        row['_provenance'].pop('api_version')
    changed = make_snapshot('azure', [SUB], collections, metadata=metadata,
                            created_at=snapshot['created_at'])
    finding = next(f for f in evaluate_snapshot(changed, checks=[CHECK])['findings']
                   if f['check_id'] == CHECK)
    assert finding['status'] == 'UNKNOWN', finding
