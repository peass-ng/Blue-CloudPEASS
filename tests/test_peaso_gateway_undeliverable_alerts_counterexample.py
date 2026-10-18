"""Complete native disabled/empty action routes prove inability to deliver."""
import pytest

from tests.test_peaso_gateway_disabled_alerts_counterexample import disabled_snapshot, status, FAMILIES, SCOPE

GROUP = SCOPE + '/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/disabled'


def routed_snapshot(mode='disabled'):
    snapshot = disabled_snapshot()
    for collection in snapshot['collections']:
        if collection['type'] not in FAMILIES:
            continue
        props = collection['items'][0]['properties']
        props['enabled'] = True
        groups = [] if mode == 'empty' else [GROUP]
        kind = collection['type']
        props['actions'] = ([{'actionGroupId': g} for g in groups] if kind == 'metric_alert' else
            {'actionGroups': [{'actionGroupId': g} for g in groups] if kind == 'activity_log_alert' else groups})
    snapshot['collections'].append({'type': 'action_group', 'scope': SCOPE, 'status': 'collected',
        'items': [{'id': GROUP, 'type': 'Microsoft.Insights/actionGroups', 'properties': {'enabled': False}}]})
    return snapshot


def test_complete_disabled_groups_prove_failure_without_semantics_or_history():
    assert status(routed_snapshot()) == 'FAIL'


def test_complete_empty_action_routes_prove_failure_without_semantics_or_history():
    assert status(routed_snapshot('empty')) == 'FAIL'


@pytest.mark.parametrize('family', FAMILIES)
def test_any_enabled_group_candidate_retains_semantic_and_history_requirements(family):
    snapshot = routed_snapshot('empty')
    group = snapshot['collections'][-1]['items'][0]
    group['properties']['enabled'] = True
    props = next(c for c in snapshot['collections'] if c['type'] == family)['items'][0]['properties']
    props['actions'] = ([{'actionGroupId': GROUP}] if family == 'metric_alert' else
        {'actionGroups': [{'actionGroupId': GROUP}] if family == 'activity_log_alert' else [GROUP]})
    assert status(snapshot) == 'UNKNOWN'


@pytest.mark.parametrize('mode', ['missing_group', 'unknown_group', 'partial_groups', 'malformed_enabled',
    'wrong_group_type', 'foreign_group', 'duplicate_route', 'wrong_alert_type'])
def test_unresolved_or_malformed_route_does_not_prove_delivery_impossible(mode):
    snapshot = routed_snapshot()
    group_collection = snapshot['collections'][-1]
    alert = next(c for c in snapshot['collections'] if c['type'] == 'metric_alert')['items'][0]
    if mode == 'missing_group': snapshot['collections'].pop()
    elif mode == 'unknown_group': group_collection.update(status='empty', items=[])
    elif mode == 'partial_groups': group_collection['status'] = 'partial'
    elif mode == 'malformed_enabled': group_collection['items'][0]['properties']['enabled'] = 'false'
    elif mode == 'wrong_group_type': group_collection['items'][0]['type'] = 'Microsoft.Compute/virtualMachines'
    elif mode == 'foreign_group': group_collection['items'][0]['id'] = GROUP.replace('1111', '2222')
    elif mode == 'duplicate_route': alert['properties']['actions'] *= 2
    elif mode == 'wrong_alert_type': alert['type'] = 'Microsoft.Compute/virtualMachines'
    assert status(snapshot) == 'UNKNOWN'


@pytest.mark.parametrize('family', FAMILIES)
def test_missing_native_actions_is_not_an_empty_action_list(family):
    snapshot = routed_snapshot('empty')
    del next(c for c in snapshot['collections'] if c['type'] == family)['items'][0]['properties']['actions']
    assert status(snapshot) == 'UNKNOWN'
