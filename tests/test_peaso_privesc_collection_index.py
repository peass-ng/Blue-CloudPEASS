"""Model-local lookup preserves order, native identity and scope/status evidence."""
import copy
import json
import pytest
from peaso.snapshot import freeze
from peaso.privesc.effective_permissions import Model, collections, items, inventory_status


@pytest.mark.parametrize('provider', ['aws', 'gcp', 'azure', 'k8s'])
def test_index_matches_scan_without_mutating_or_collapsing_facts(provider):
    source = freeze({'provider': provider, 'collections': [
        {'type': 'identity', 'scope': 'scope-b', 'status': 'collected', 'items': [{'id': 'b'}]},
        {'type': 'other', 'scope': 'scope-a', 'status': 'empty', 'items': []},
        {'type': 'identity', 'scope': 'scope-a', 'status': 'denied', 'items': []},
        {'type': 'identity', 'scope': 'scope-c', 'status': 'collected', 'items': [{'id': 'c'}]},
    ]})
    before = json.dumps(source, sort_keys=True)
    model = Model(source)
    expected = collections(source, 'identity')
    assert collections(model.snapshot, 'identity') == expected
    assert all(a is b for a, b in zip(collections(model.snapshot, 'identity'), expected))
    assert list(items(model.snapshot, 'identity')) == list(items(source, 'identity'))
    assert inventory_status(model.snapshot, 'identity') == inventory_status(source, 'identity')
    assert collections(model.snapshot, 'missing') == []
    returned = collections(model.snapshot, 'identity')
    returned.clear()
    assert collections(model.snapshot, 'identity') == expected
    with pytest.raises(TypeError):
        model.snapshot['provider'] = 'changed'
    with pytest.raises(TypeError):
        collections(model.snapshot, 'identity')[0]['items'][0]['id'] = 'changed'
    assert json.dumps(source, sort_keys=True) == before


def test_model_indexes_are_independent_and_plain_snapshot_fallback_remains_live():
    first = {'collections': [{'type': 'identity', 'scope': 'first', 'status': 'empty', 'items': []}]}
    second = {'collections': [{'type': 'identity', 'scope': 'second', 'status': 'empty', 'items': []}]}
    a, b = Model(first), Model(second)
    assert collections(a.snapshot, 'identity')[0]['scope'] == 'first'
    assert collections(b.snapshot, 'identity')[0]['scope'] == 'second'
    first['collections'].append({'type': 'identity', 'scope': 'later', 'status': 'empty', 'items': []})
    assert len(collections(first, 'identity')) == 2
    assert len(collections(a.snapshot, 'identity')) == 1
