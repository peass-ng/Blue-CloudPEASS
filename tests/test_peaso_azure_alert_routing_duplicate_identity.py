"""Contradictory native duplicate identities cannot be silently reduced to PASS."""
from copy import deepcopy
import pytest

from peaso.collectors.azure import _Reader
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from peaso.checks.compliance_new_sw25_facts import ROUTING_ID
from tests.test_peaso_azure_alert_routing_native import native, CONTRACTS, SCOPE


@pytest.mark.parametrize('kind', CONTRACTS)
@pytest.mark.parametrize('pages', ['same_page', 'separate_pages'])
@pytest.mark.parametrize('first_has_route', [True, False])
def test_conflicting_duplicate_native_alerts_are_partial_unknown(kind, pages, first_has_route):
    first = native(kind, first_has_route)
    second = native(kind, not first_has_route)
    second['id'] = second['id'].upper()  # ARM identities are case insensitive.
    responses = [[first, second]] if pages == 'same_page' else [[first], [second]]
    reader = _Reader({'concurrency': 1, 'retries': 0})
    collection = reader._read((kind, SCOPE, 'Microsoft.Insights', lambda: iter(deepcopy(responses))))
    assert collection['status'] == 'partial'
    assert len(collection['items']) == 1
    assert collection['error']
    snapshot = make_snapshot('azure', [SCOPE], [collection] + [
        {'type': other, 'scope': SCOPE, 'service': 'Microsoft.Insights', 'status': 'empty', 'items': []}
        for other in CONTRACTS if other != kind])
    result = next(f for f in evaluate_snapshot(snapshot, checks=[ROUTING_ID])['findings'] if f['check_id'] == ROUTING_ID)
    assert result['status'] == 'UNKNOWN'


@pytest.mark.parametrize('kind', CONTRACTS)
def test_identical_duplicate_does_not_claim_complete_native_roster(kind):
    row = native(kind)
    reader = _Reader({'concurrency': 1, 'retries': 0})
    collection = reader._read((kind, SCOPE, 'Microsoft.Insights', lambda: iter([[row], [deepcopy(row)]])))
    assert collection['status'] == 'partial'
    assert len(collection['items']) == 1
