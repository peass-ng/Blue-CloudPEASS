"""Independent, inert adversarial probes for Azure subnet route routing."""
from copy import deepcopy

from peaso.collectors import azure
from peaso.collectors import azure_wave_network_controls as routes
from tests.test_peaso_azure_wave_network_controls_native import SCOPE, VNET, reader

OTHER = '/subscriptions/22222222-2222-2222-2222-222222222222'


def _project(collections, scopes=(SCOPE,)):
    source = azure._Reader({'concurrency': 1, 'retries': 0})
    source.collections = collections
    calls = source.budget.calls
    routes.collect(source, scopes, {'subnet_effective_route'})
    assert source.budget.calls == calls
    return [row for row in source.collections if row['type'] == 'subnet_effective_route']


def test_subscription_root_conflicts_with_vnet_child_fail_closed():
    facts = _project([
        {'type': 'subnet', 'scope': SCOPE, 'status': 'empty', 'items': []},
        {'type': 'subnet', 'scope': VNET, 'status': 'empty', 'items': []},
    ])
    assert len(facts) == 2
    assert {row['scope'] for row in facts} == {SCOPE, VNET}
    assert all(row['status'] not in ('empty', 'collected') and row['items'] == [] for row in facts)


def test_casefold_duplicate_vnet_parent_fails_closed():
    facts = _project([
        {'type': 'subnet', 'scope': VNET, 'status': 'empty', 'items': []},
        {'type': 'subnet', 'scope': VNET.upper(), 'status': 'empty', 'items': []},
    ])
    assert len(facts) == 1
    assert facts[0]['scope'] == VNET
    assert all(row['status'] not in ('empty', 'collected') and row['items'] == [] for row in facts)


def test_foreign_parent_cannot_authorize_requested_scope():
    facts = _project([
        {'type': 'subnet', 'scope': OTHER + VNET[len(SCOPE):], 'status': 'empty', 'items': []},
    ])
    assert len(facts) == 1
    assert facts[0]['scope'] == SCOPE
    assert facts[0]['status'] not in ('empty', 'collected')


def test_two_subscriptions_settle_independently_without_extra_requests():
    source = reader()
    foreign = {'type': 'subnet', 'scope': OTHER + VNET[len(SCOPE):],
               'status': 'denied', 'items': []}
    facts = _project(deepcopy(source.collections) + [foreign], (SCOPE, OTHER))
    assert len(facts) == 2
    by_scope = {row['scope']: row for row in facts}
    assert by_scope[VNET]['status'] == 'collected'
    assert by_scope[VNET]['items'][0]['nicEvidence'][0]['directInternetWitness']['destinationIp'] == '1.1.1.1'
    assert by_scope[foreign['scope']]['status'] not in ('empty', 'collected')
    assert by_scope[foreign['scope']]['items'] == []
