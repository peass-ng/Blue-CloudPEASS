"""Inert routing boundaries for the sampled Azure subnet route projection."""

from peaso.collectors import azure
from peaso.collectors import azure_wave_network_controls as routes
from tests.test_peaso_azure_wave_network_controls_native import SCOPE, VNET, reader as native_reader


def _run(source):
    before = source.budget.calls
    routes.collect(source, [SCOPE], {'subnet_effective_route'})
    assert source.budget.calls == before
    return [row for row in source.collections if row['type'] == 'subnet_effective_route']


def test_missing_subnet_parent_is_explicitly_unavailable():
    source = azure._Reader({'concurrency': 1, 'retries': 0})
    facts = _run(source)
    assert len(facts) == 1
    assert facts[0]['scope'] == SCOPE
    assert facts[0]['status'] not in ('collected', 'empty')
    assert facts[0]['items'] == []


def test_denied_subnet_parent_cannot_publish_empty_route_inventory():
    source = azure._Reader({'concurrency': 1, 'retries': 0})
    source.collections = [{'type': 'subnet', 'scope': VNET, 'service': 'Microsoft.Network',
                           'status': 'denied', 'items': []}]
    facts = _run(source)
    assert len(facts) == 1
    assert facts[0]['scope'] == VNET
    assert facts[0]['status'] not in ('collected', 'empty')
    assert facts[0]['items'] == []


def test_authoritative_empty_subnet_parent_needs_no_route_dependencies():
    source = azure._Reader({'concurrency': 1, 'retries': 0})
    source.collections = [{'type': 'subnet', 'scope': VNET, 'service': 'Microsoft.Network',
                           'status': 'empty', 'items': []}]
    facts = _run(source)
    assert len(facts) == 1
    assert facts[0]['scope'] == VNET
    assert facts[0]['status'] == 'empty'
    assert facts[0]['items'] == []


def test_authoritative_empty_with_available_dependencies_is_empty():
    source = native_reader()
    source.collections[0] = {'type': 'subnet', 'scope': VNET, 'service': 'Microsoft.Network',
                             'status': 'empty', 'items': []}
    facts = _run(source)
    assert len(facts) == 1
    assert facts[0]['scope'] == VNET
    assert facts[0]['status'] == 'empty'
    assert facts[0]['items'] == []


def test_authoritative_empty_vnet_parent_routes_to_empty_child():
    source = azure._Reader({'concurrency': 1, 'retries': 0})
    source.collections = [{'type': 'vnet', 'scope': SCOPE, 'service': 'Microsoft.Network',
                           'status': 'empty', 'items': []}]
    facts = _run(source)
    assert len(facts) == 1
    assert facts[0]['scope'] == SCOPE
    assert facts[0]['status'] == 'empty'
    assert facts[0]['items'] == []


def test_contradictory_empty_subnet_envelope_is_unavailable():
    source = native_reader()
    source.collections[0]['status'] = 'empty'
    facts = _run(source)
    assert len(facts) == 1
    assert facts[0]['status'] not in ('collected', 'empty')
    assert facts[0]['items'] == []


def test_subscription_root_empty_subnet_parent_is_authoritative():
    source = azure._Reader({'concurrency': 1, 'retries': 0})
    source.collections = [{'type': 'subnet', 'scope': SCOPE, 'service': 'Microsoft.Network',
                           'status': 'empty', 'items': []}]
    facts = _run(source)
    assert len(facts) == 1
    assert facts[0]['scope'] == SCOPE
    assert facts[0]['status'] == 'empty'
    assert facts[0]['items'] == []


def test_duplicate_subnet_parent_cannot_publish_empty_route_inventory():
    source = azure._Reader({'concurrency': 1, 'retries': 0})
    source.collections = [
        {'type': 'subnet', 'scope': VNET, 'status': 'empty', 'items': []},
        {'type': 'subnet', 'scope': VNET, 'status': 'empty', 'items': []},
    ]
    facts = _run(source)
    assert len(facts) == 1
    assert facts[0]['status'] not in ('collected', 'empty')
    assert facts[0]['items'] == []


def test_malformed_scoped_parent_cannot_publish_empty_route_inventory():
    source = azure._Reader({'concurrency': 1, 'retries': 0})
    source.collections = [{'type': 'subnet', 'scope': VNET + '/subnets/other',
                           'status': 'empty', 'items': []}]
    facts = _run(source)
    assert len(facts) == 1
    assert facts[0]['status'] not in ('collected', 'empty')
    assert facts[0]['items'] == []
