"""A regional violation survives unavailable peer fields, not peer identity errors."""
from copy import deepcopy

import pytest

from peaso.snapshot import make_snapshot
from tests.test_peaso_azure_region_counterexample import RID, snapshot, status


def two_rows(violating, peer, *, reverse=False):
    capture = snapshot(location=violating.get('location', 'eastus'),
                       zones=violating.get('zones', ['1']))
    first = deepcopy(capture['collections'][0]['items'][0])
    first.update(violating)
    second = {'id': RID + 'peer', 'type': 'Microsoft.Compute/virtualMachines',
              'location': 'westeurope', 'zones': ['1']}
    second.update(peer)
    capture['collections'][0]['items'] = [second, first] if reverse else [first, second]
    return make_snapshot('azure', capture['scopes'], capture['collections'], metadata=capture['metadata'])


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('peer_case', ['missing_zones', 'missing_location', 'bad_zones'])
def test_definite_out_of_region_survives_unavailable_peer_fields(peer_case, reverse):
    peer = {'zones': ['bad']} if peer_case == 'bad_zones' else {}
    capture = two_rows({}, peer, reverse=reverse)
    if peer_case.startswith('missing_'):
        del capture['collections'][0]['items'][0 if reverse else 1][peer_case.removeprefix('missing_')]
    capture = make_snapshot('azure', capture['scopes'], capture['collections'], metadata=capture['metadata'])
    assert status(capture) == 'FAIL'


@pytest.mark.parametrize('reverse', [False, True])
def test_definite_out_of_zone_survives_missing_peer_location(reverse):
    capture = two_rows({'location': 'westeurope', 'zones': ['2']}, {}, reverse=reverse)
    del capture['collections'][0]['items'][0 if reverse else 1]['location']
    capture = make_snapshot('azure', capture['scopes'], capture['collections'], metadata=capture['metadata'])
    assert status(capture) == 'FAIL'


def test_missing_peer_location_without_violation_is_unknown():
    capture = two_rows({'location': 'westeurope'}, {})
    del capture['collections'][0]['items'][1]['location']
    capture = make_snapshot('azure', capture['scopes'], capture['collections'], metadata=capture['metadata'])
    assert status(capture) == 'UNKNOWN'


def test_foreign_peer_identity_cannot_be_overridden_by_known_region_violation():
    capture = two_rows({}, {'id': '/subscriptions/foreign/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/peer'})
    assert status(capture) == 'UNKNOWN'


def test_contradictory_peer_type_cannot_be_overridden_by_known_region_violation():
    capture = two_rows({}, {'type': 'Microsoft.Storage/storageAccounts'})
    assert status(capture) == 'UNKNOWN'
