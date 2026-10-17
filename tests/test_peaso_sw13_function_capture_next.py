"""Original Function runtime configuration rejects explicitly foreign captures."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
CID = 'azure_app_service_app_function_latest_runtime_version_f50215a'
DATA = json.loads((Path(__file__).parent / 'fixtures/bulk_pending_behavior.json').read_text())

def verdict(field=None, foreign=False, coverage=None):
    index = deepcopy(DATA[CID]['pass_index'])
    row = index['collections']['function_app_configuration'][0]['items'][0]
    metadata = index['context']['metadata']
    if field:
        metadata[field] = 'approved-context'
        row['_provenance'][field] = 'foreign-context' if foreign else 'approved-context'
    if coverage is not None:
        mapping = metadata['compliance_policy']['sw13']['checks'][CID]['expectedFunctionSettings']
        app_id = row['appId']
        mapping['_coverage'] = {app_id: None if coverage == 'explicit-null' else coverage}
    context = index['context']
    envelopes = [dict(batch, service='external:inert-fixture') for batches in index['collections'].values() for batch in batches]
    snapshot = make_snapshot('azure', [context['scope']], envelopes,
                             metadata=metadata, created_at=context['created_at'])
    findings = evaluate_snapshot(snapshot, checks=[CID])['findings']
    assert len(findings) == 1
    return findings[0]['status']

@pytest.mark.parametrize('field', ['credential_context_id', 'customer_context_id', 'tenant_id'])
def test_foreign_explicit_configuration_capture_is_unknown(field):
    assert verdict(field, foreign=True) == 'UNKNOWN'

@pytest.mark.parametrize('field', [None, 'credential_context_id', 'customer_context_id', 'tenant_id'])
def test_legacy_or_matching_capture_keeps_valid_original_pass(field):
    assert verdict(field) == 'PASS'

@pytest.mark.parametrize('marker', ['explicit-null', {'status': 'unavailable'}, {'status': 'denied'}, {'status': 'empty'}])
def test_explicit_unusable_mapping_coverage_remains_unknown(marker):
    assert verdict(coverage=marker) == 'UNKNOWN'
